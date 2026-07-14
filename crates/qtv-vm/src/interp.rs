//! Deterministic interpreter. Decodes and executes, meters gas per instruction, faults on

use std::collections::BTreeMap;

use crate::isa::{decode, DecodeError, Instr, OpCode, NUM_REGS};
use crate::state::Machine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    OutOfGas,
    Overflow,
    DivByZero,
    StackOverflow,
    StackUnderflow,
    BadMemory,
    BadJump,
    BadConst,
    Decode(DecodeError),
    Pending(OpCode),
}

/// The result of a clean halt. State changes are surfaced only on success, so a fault rolls back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub regs: [u64; NUM_REGS],
    pub gas_used: u64,
    pub storage: BTreeMap<u64, u64>,
}

/// Internal control flow after a step.
enum Step {
    Next,
    Halt,
}

pub struct Interpreter<'a> {
    code: &'a [u8],
    consts: &'a [u64],
    machine: Machine,
    gas_limit: u64,
    gas_used: u64,
    storage: BTreeMap<u64, u64>,
}

impl<'a> Interpreter<'a> {
    pub fn new(code: &'a [u8], consts: &'a [u64], gas_limit: u64) -> Self {
        Interpreter {
            code,
            consts,
            machine: Machine::new(),
            gas_limit,
            gas_used: 0,
            storage: BTreeMap::new(),
        }
    }

    /// Seed the declared state read set. The interpreter works on this copy and returns it only on
    pub fn with_storage(mut self, storage: BTreeMap<u64, u64>) -> Self {
        self.storage = storage;
        self
    }

    pub fn run(mut self) -> Result<Outcome, Fault> {
        loop {
            let pc = self.machine.pc as usize;
            let (instr, len) = decode(self.code, pc).map_err(Fault::Decode)?;

            let cost = crate::gas::cost(instr.opcode());
            let spent = self.gas_used.checked_add(cost).ok_or(Fault::OutOfGas)?;
            if spent > self.gas_limit {
                return Err(Fault::OutOfGas);
            }
            self.gas_used = spent;

            let next = pc.checked_add(len).ok_or(Fault::BadJump)?;
            self.machine.pc = u32::try_from(next).map_err(|_| Fault::BadJump)?;

            match self.step(instr)? {
                Step::Next => {}
                Step::Halt => {
                    return Ok(Outcome {
                        regs: self.machine.regs,
                        gas_used: self.gas_used,
                        storage: self.storage,
                    })
                }
            }
        }
    }

    fn step(&mut self, instr: Instr) -> Result<Step, Fault> {
        let m = &mut self.machine;
        match instr {
            Instr::Halt => return Ok(Step::Halt),
            Instr::Nop => {}

            Instr::Mov { d, a } => {
                let v = m.reg(a);
                m.set_reg(d, v);
            }
            Instr::Ldi { d, imm } => m.set_reg(d, imm),
            Instr::Ldc { d, idx } => {
                let v = *self.consts.get(idx as usize).ok_or(Fault::BadConst)?;
                m.set_reg(d, v);
            }

            Instr::Add { d, a, b } => {
                let v = m.reg(a).checked_add(m.reg(b)).ok_or(Fault::Overflow)?;
                m.set_reg(d, v);
            }
            Instr::Sub { d, a, b } => {
                let v = m.reg(a).checked_sub(m.reg(b)).ok_or(Fault::Overflow)?;
                m.set_reg(d, v);
            }
            Instr::Mul { d, a, b } => {
                let v = m.reg(a).checked_mul(m.reg(b)).ok_or(Fault::Overflow)?;
                m.set_reg(d, v);
            }
            Instr::Div { d, a, b } => {
                let v = m.reg(a).checked_div(m.reg(b)).ok_or(Fault::DivByZero)?;
                m.set_reg(d, v);
            }
            Instr::Rem { d, a, b } => {
                let v = m.reg(a).checked_rem(m.reg(b)).ok_or(Fault::DivByZero)?;
                m.set_reg(d, v);
            }
            Instr::AddW { d, a, b } => {
                let v = m.reg(a).wrapping_add(m.reg(b));
                m.set_reg(d, v);
            }
            Instr::SubW { d, a, b } => {
                let v = m.reg(a).wrapping_sub(m.reg(b));
                m.set_reg(d, v);
            }
            Instr::MulW { d, a, b } => {
                let v = m.reg(a).wrapping_mul(m.reg(b));
                m.set_reg(d, v);
            }

            other => return Err(Fault::Pending(other.opcode())),
        }
        Ok(Step::Next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(instrs: &[Instr]) -> Vec<u8> {
        let mut code = Vec::new();
        for i in instrs {
            i.encode(&mut code);
        }
        code
    }

    #[test]
    fn halts_cleanly() {
        let code = program(&[Instr::Nop, Instr::Halt]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.gas_used, 1);
    }

    #[test]
    fn missing_halt_faults() {
        let code = program(&[Instr::Nop]);
        let err = Interpreter::new(&code, &[], 100).run().unwrap_err();
        assert_eq!(err, Fault::Decode(DecodeError::Truncated));
    }

    #[test]
    fn computes_value_and_reports_gas() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 5 },
            Instr::Ldi { d: 1, imm: 7 },
            Instr::Add { d: 2, a: 0, b: 1 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 12);
        assert_eq!(out.gas_used, 1 + 1 + 2);
    }

    #[test]
    fn loads_from_constant_pool() {
        let code = program(&[Instr::Ldc { d: 0, idx: 1 }, Instr::Halt]);
        let out = Interpreter::new(&code, &[10, 20], 100).run().expect("halt");
        assert_eq!(out.regs[0], 20);
    }

    #[test]
    fn overflow_faults() {
        let code = program(&[
            Instr::Ldi {
                d: 0,
                imm: u64::MAX,
            },
            Instr::Ldi { d: 1, imm: 1 },
            Instr::Add { d: 2, a: 0, b: 1 },
            Instr::Halt,
        ]);
        assert_eq!(
            Interpreter::new(&code, &[], 100).run(),
            Err(Fault::Overflow)
        );
    }

    #[test]
    fn divide_by_zero_faults() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 10 },
            Instr::Ldi { d: 1, imm: 0 },
            Instr::Div { d: 2, a: 0, b: 1 },
            Instr::Halt,
        ]);
        assert_eq!(
            Interpreter::new(&code, &[], 100).run(),
            Err(Fault::DivByZero)
        );
    }

    #[test]
    fn wrapping_add_wraps() {
        let code = program(&[
            Instr::Ldi {
                d: 0,
                imm: u64::MAX,
            },
            Instr::Ldi { d: 1, imm: 1 },
            Instr::AddW { d: 2, a: 0, b: 1 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 0);
    }
}
