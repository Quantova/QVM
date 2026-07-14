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
    JumpTo(u32),
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
                Step::JumpTo(target) => self.machine.pc = target,
            }
        }
    }

    fn step(&mut self, instr: Instr) -> Result<Step, Fault> {
        let code_len = self.code.len();
        let consts = self.consts;
        let check = |target: u32| -> Result<(), Fault> {
            if target as usize >= code_len {
                Err(Fault::BadJump)
            } else {
                Ok(())
            }
        };
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
                let v = *consts.get(idx as usize).ok_or(Fault::BadConst)?;
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

            Instr::And { d, a, b } => {
                let v = m.reg(a) & m.reg(b);
                m.set_reg(d, v);
            }
            Instr::Or { d, a, b } => {
                let v = m.reg(a) | m.reg(b);
                m.set_reg(d, v);
            }
            Instr::Xor { d, a, b } => {
                let v = m.reg(a) ^ m.reg(b);
                m.set_reg(d, v);
            }
            Instr::Not { d, a } => {
                let v = !m.reg(a);
                m.set_reg(d, v);
            }
            Instr::Shl { d, a, b } => {
                let v = m.reg(a) << (m.reg(b) & 63);
                m.set_reg(d, v);
            }
            Instr::Shr { d, a, b } => {
                let v = m.reg(a) >> (m.reg(b) & 63);
                m.set_reg(d, v);
            }
            Instr::Eq { d, a, b } => {
                let v = u64::from(m.reg(a) == m.reg(b));
                m.set_reg(d, v);
            }
            Instr::LtU { d, a, b } => {
                let v = u64::from(m.reg(a) < m.reg(b));
                m.set_reg(d, v);
            }
            Instr::GtU { d, a, b } => {
                let v = u64::from(m.reg(a) > m.reg(b));
                m.set_reg(d, v);
            }

            Instr::Push { a } => {
                let v = m.reg(a);
                if !m.push(v) {
                    return Err(Fault::StackOverflow);
                }
            }
            Instr::Pop { d } => {
                let v = m.pop().ok_or(Fault::StackUnderflow)?;
                m.set_reg(d, v);
            }
            Instr::MLoad { d, a } => {
                let v = m.mem_load(m.reg(a)).ok_or(Fault::BadMemory)?;
                m.set_reg(d, v);
            }
            Instr::MStore { a, b } => {
                if !m.mem_store(m.reg(a), m.reg(b)) {
                    return Err(Fault::BadMemory);
                }
            }

            Instr::Jmp { target } => {
                check(target)?;
                return Ok(Step::JumpTo(target));
            }
            Instr::Jz { a, target } => {
                if m.reg(a) == 0 {
                    check(target)?;
                    return Ok(Step::JumpTo(target));
                }
            }
            Instr::Jnz { a, target } => {
                if m.reg(a) != 0 {
                    check(target)?;
                    return Ok(Step::JumpTo(target));
                }
            }
            Instr::Call { target } => {
                check(target)?;
                let ret = u64::from(m.pc);
                if !m.push(ret) {
                    return Err(Fault::StackOverflow);
                }
                return Ok(Step::JumpTo(target));
            }
            Instr::Ret => {
                let ret = m.pop().ok_or(Fault::StackUnderflow)?;
                let target = u32::try_from(ret).map_err(|_| Fault::BadJump)?;
                check(target)?;
                return Ok(Step::JumpTo(target));
            }

            Instr::SLoad { d, a } => {
                let key = m.reg(a);
                let v = self.storage.get(&key).copied().unwrap_or(0);
                m.set_reg(d, v);
            }
            Instr::SStore { a, b } => {
                let key = m.reg(a);
                let val = m.reg(b);
                self.storage.insert(key, val);
            }

            // Message group. Enqueuing an asynchronous message to another contract is pending.
            Instr::Send { .. } => return Err(Fault::Pending(OpCode::Send)),

            other => return Err(Fault::Pending(other.opcode())),
        }
        Ok(Step::Next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

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

    #[test]
    fn logic_and_shift() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 0b1100 },
            Instr::Ldi { d: 1, imm: 0b1010 },
            Instr::And { d: 2, a: 0, b: 1 },
            Instr::Or { d: 3, a: 0, b: 1 },
            Instr::Xor { d: 4, a: 0, b: 1 },
            Instr::Ldi { d: 5, imm: 2 },
            Instr::Shl { d: 6, a: 0, b: 5 },
            Instr::Shr { d: 7, a: 0, b: 5 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 0b1000);
        assert_eq!(out.regs[3], 0b1110);
        assert_eq!(out.regs[4], 0b0110);
        assert_eq!(out.regs[6], 0b110000);
        assert_eq!(out.regs[7], 0b11);
    }

    #[test]
    fn shift_amount_is_masked() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 1 },
            Instr::Ldi { d: 1, imm: 64 },
            Instr::Shl { d: 2, a: 0, b: 1 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 1);
    }

    #[test]
    fn compare_produces_flags() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 3 },
            Instr::Ldi { d: 1, imm: 9 },
            Instr::Eq { d: 2, a: 0, b: 1 },
            Instr::LtU { d: 3, a: 0, b: 1 },
            Instr::GtU { d: 4, a: 0, b: 1 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 0);
        assert_eq!(out.regs[3], 1);
        assert_eq!(out.regs[4], 0);
    }

    #[test]
    fn stack_push_pop() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 77 },
            Instr::Push { a: 0 },
            Instr::Pop { d: 1 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[1], 77);
    }

    #[test]
    fn pop_empty_faults() {
        let code = program(&[Instr::Pop { d: 0 }, Instr::Halt]);
        assert_eq!(
            Interpreter::new(&code, &[], 100).run(),
            Err(Fault::StackUnderflow)
        );
    }

    #[test]
    fn memory_store_then_load() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 16 },
            Instr::Ldi { d: 1, imm: 0xabcd },
            Instr::MStore { a: 0, b: 1 },
            Instr::MLoad { d: 2, a: 0 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 0xabcd);
    }

    #[test]
    fn memory_out_of_bounds_faults() {
        let code = program(&[
            Instr::Ldi {
                d: 0,
                imm: u64::MAX,
            },
            Instr::Ldi { d: 1, imm: 1 },
            Instr::MStore { a: 0, b: 1 },
            Instr::Halt,
        ]);
        assert_eq!(
            Interpreter::new(&code, &[], 100).run(),
            Err(Fault::BadMemory)
        );
    }

    #[test]
    fn backward_branch_loop() {
        // Ldi is ten bytes, SubW and AddW are four, Jnz is six. The loop head is at offset 30.
        let code = program(&[
            Instr::Ldi { d: 0, imm: 3 },
            Instr::Ldi { d: 1, imm: 0 },
            Instr::Ldi { d: 2, imm: 1 },
            Instr::SubW { d: 0, a: 0, b: 2 },
            Instr::AddW { d: 1, a: 1, b: 2 },
            Instr::Jnz { a: 0, target: 30 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 1000).run().expect("halt");
        assert_eq!(out.regs[0], 0);
        assert_eq!(out.regs[1], 3);
    }

    #[test]
    fn call_and_return() {
        // Call is five bytes and Halt is one, so the subroutine begins at offset 6.
        let code = program(&[
            Instr::Call { target: 6 },
            Instr::Halt,
            Instr::Ldi { d: 0, imm: 42 },
            Instr::Ret,
        ]);
        let out = Interpreter::new(&code, &[], 1000).run().expect("halt");
        assert_eq!(out.regs[0], 42);
    }

    #[test]
    fn out_of_gas_faults() {
        let code = program(&[Instr::Jmp { target: 0 }]);
        assert_eq!(Interpreter::new(&code, &[], 10).run(), Err(Fault::OutOfGas));
    }

    #[test]
    fn jump_out_of_range_faults() {
        let code = program(&[Instr::Jmp { target: 9999 }]);
        assert_eq!(Interpreter::new(&code, &[], 100).run(), Err(Fault::BadJump));
    }

    #[test]
    fn storage_store_then_load() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 7 },
            Instr::Ldi { d: 1, imm: 99 },
            Instr::SStore { a: 0, b: 1 },
            Instr::SLoad { d: 2, a: 0 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 2000).run().expect("halt");
        assert_eq!(out.regs[2], 99);
        assert_eq!(out.storage.get(&7), Some(&99));
    }

    #[test]
    fn fault_rolls_back_storage() {
        let mut persistent = BTreeMap::new();
        persistent.insert(5, 1);
        let code = program(&[
            Instr::Ldi { d: 0, imm: 5 },
            Instr::Ldi { d: 1, imm: 123 },
            Instr::SStore { a: 0, b: 1 },
            Instr::Ldi {
                d: 2,
                imm: u64::MAX,
            },
            Instr::Ldi { d: 3, imm: 1 },
            Instr::Add { d: 4, a: 2, b: 3 },
            Instr::Halt,
        ]);
        let res = Interpreter::new(&code, &[], 2000)
            .with_storage(persistent.clone())
            .run();
        assert_eq!(res, Err(Fault::Overflow));
        assert_eq!(persistent.get(&5), Some(&1));
    }

    #[test]
    fn message_group_is_pending() {
        let code = program(&[Instr::Send { a: 0, b: 0, c: 0 }, Instr::Halt]);
        assert_eq!(
            Interpreter::new(&code, &[], 1000).run(),
            Err(Fault::Pending(OpCode::Send))
        );
    }

    #[test]
    fn out_of_gas_rolls_back_storage() {
        // The self loop at offset 23 burns gas after the write, so the fault discards the write.
        let mut persistent = BTreeMap::new();
        persistent.insert(5, 1);
        let code = program(&[
            Instr::Ldi { d: 0, imm: 5 },
            Instr::Ldi { d: 1, imm: 123 },
            Instr::SStore { a: 0, b: 1 },
            Instr::Jmp { target: 23 },
        ]);
        let res = Interpreter::new(&code, &[], 520)
            .with_storage(persistent.clone())
            .run();
        assert_eq!(res, Err(Fault::OutOfGas));
        assert_eq!(persistent.get(&5), Some(&1));
    }
}
