//! Deterministic interpreter. Decodes and executes, meters gas per instruction, faults on
//! overflow or out of gas and rolls back, and halts cleanly.

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
    #[allow(dead_code)]
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
    /// a clean halt, so a fault leaves the caller's state untouched.
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
        match instr {
            Instr::Halt => Ok(Step::Halt),
            Instr::Nop => Ok(Step::Next),
            other => Err(Fault::Pending(other.opcode())),
        }
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
}
