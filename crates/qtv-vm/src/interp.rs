
use std::collections::BTreeMap;

use crate::container::{Container, SELECTOR_BYTES};
use crate::isa::{decode, DecodeError, Instr, NUM_REGS};
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
    UnknownSelector,
    BadScheme,
    EffectsTooLarge,
    Decode(DecodeError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Transfer { to: Vec<u8>, amount: u64 },
    Event {
        selector: [u8; SELECTOR_BYTES],
        data: Vec<u8>,
    },
}

pub const STORAGE_KEY_BYTES: usize = 32;

pub type StorageKey = [u8; STORAGE_KEY_BYTES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub regs: [u64; NUM_REGS],
    pub gas_used: u64,
    pub storage: BTreeMap<StorageKey, u64>,
    pub effects: Vec<Effect>,
}

enum Step {
    Next,
    Halt,
    JumpTo(u32),
}

fn read_key(m: &Machine, offset: u64) -> Result<StorageKey, Fault> {
    let region = m
        .mem_region(offset, STORAGE_KEY_BYTES as u64)
        .ok_or(Fault::BadMemory)?;
    let mut key = [0u8; STORAGE_KEY_BYTES];
    key.copy_from_slice(region);
    Ok(key)
}

pub struct Interpreter<'a> {
    code: &'a [u8],
    consts: &'a [u64],
    machine: Machine,
    gas_limit: u64,
    gas_used: u64,
    storage: BTreeMap<StorageKey, u64>,
    effects: Vec<Effect>,
    effects_bytes: u64,
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
            effects: Vec::new(),
            effects_bytes: 0,
        }
    }

    pub fn for_entry(
        container: &'a Container,
        selector: [u8; SELECTOR_BYTES],
        gas_limit: u64,
    ) -> Result<Self, Fault> {
        let offset = container
            .entry_offset(&selector)
            .ok_or(Fault::UnknownSelector)?;
        if crate::gas::DISPATCH > gas_limit {
            return Err(Fault::OutOfGas);
        }
        let mut interp = Interpreter::new(&container.code, &container.consts, gas_limit);
        interp.machine.pc = offset;
        interp.gas_used = crate::gas::DISPATCH;
        Ok(interp)
    }

    pub fn with_storage(mut self, storage: BTreeMap<StorageKey, u64>) -> Self {
        self.storage = storage;
        self
    }

    pub fn with_memory(mut self, data: &[u8]) -> Self {
        let n = data.len().min(self.machine.mem.len());
        self.machine.mem[..n].copy_from_slice(&data[..n]);
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
                        effects: self.effects,
                    })
                }
                Step::JumpTo(target) => self.machine.pc = target,
            }
        }
    }

    fn charge_effect(&mut self, bytes: usize) -> Result<(), Fault> {
        let n = bytes as u64;
        let byte_cost = n
            .checked_mul(crate::gas::EFFECT_BYTE)
            .ok_or(Fault::OutOfGas)?;
        let spent = self.gas_used.checked_add(byte_cost).ok_or(Fault::OutOfGas)?;
        if spent > self.gas_limit {
            return Err(Fault::OutOfGas);
        }
        self.gas_used = spent;

        let retained = self
            .effects_bytes
            .checked_add(n)
            .ok_or(Fault::EffectsTooLarge)?;
        if retained > crate::gas::EFFECTS_BYTES_CAP {
            return Err(Fault::EffectsTooLarge);
        }
        self.effects_bytes = retained;
        Ok(())
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
            Instr::MulHi { d, a, b } => {
                let v = ((m.reg(a) as u128 * m.reg(b) as u128) >> 64) as u64;
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
                let key = read_key(m, m.reg(a))?;
                let v = self.storage.get(&key).copied().unwrap_or(0);
                m.set_reg(d, v);
            }
            Instr::SStore { a, b } => {
                let key = read_key(m, m.reg(a))?;
                let val = m.reg(b);
                self.storage.insert(key, val);
            }

            Instr::Send { a, b, c } => {
                let amount = m.reg(c);
                let to = m
                    .mem_region(m.reg(a), m.reg(b))
                    .ok_or(Fault::BadMemory)?
                    .to_vec();
                self.charge_effect(to.len())?;
                self.effects.push(Effect::Transfer { to, amount });
            }

            Instr::Emit { a, b, c } => {
                let selector = (m.reg(c) as u32).to_be_bytes();
                let data = m
                    .mem_region(m.reg(a), m.reg(b))
                    .ok_or(Fault::BadMemory)?
                    .to_vec();
                self.charge_effect(data.len())?;
                self.effects.push(Effect::Event { selector, data });
            }

            Instr::Hash { a, b, c } => crate::crypto::hash(m, a, b, c)?,
            Instr::VerifyMl { a, b, c } => crate::crypto::verify_ml(m, a, b, c)?,
            Instr::VerifySlh { a, b, c } => crate::crypto::verify_slh(m, a, b, c)?,
            Instr::MerkleVerify { a, b, c } => crate::crypto::merkle_verify(m, a, b, c)?,
            Instr::VrfVerify { a, b, c } => crate::crypto::verify_vrf(m, a, b, c)?,
            Instr::Kem { a, b, c } => crate::crypto::kem(m, a, b, c)?,
            Instr::Addr { a, b, c } => crate::crypto::address(m, a, b, c)?,
        }
        Ok(Step::Next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::OpCode;
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
    fn mulhi_gives_the_high_half() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 1u64 << 32 },
            Instr::Ldi { d: 1, imm: 1u64 << 32 },
            Instr::MulHi { d: 2, a: 0, b: 1 },
            Instr::MulW { d: 3, a: 0, b: 1 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 1);
        assert_eq!(out.regs[3], 0);
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
            Instr::Ldi { d: 1, imm: 43981 },
            Instr::MStore { a: 0, b: 1 },
            Instr::MLoad { d: 2, a: 0 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 43981);
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
        let key = crate::abi::scalar_key(7);
        let code = program(&[
            Instr::Ldi { d: 0, imm: 0 },
            Instr::Ldi { d: 1, imm: 99 },
            Instr::SStore { a: 0, b: 1 },
            Instr::SLoad { d: 2, a: 0 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 2000)
            .with_memory(&key)
            .run()
            .expect("halt");
        assert_eq!(out.regs[2], 99);
        assert_eq!(out.storage.get(&key), Some(&99));
    }

    #[test]
    fn keys_differing_past_the_leading_word_do_not_share_a_slot() {
        let mut a = [7u8; 32];
        let mut b = [7u8; 32];
        a[16] = 1;
        b[16] = 2;
        let mut mem = Vec::new();
        mem.extend_from_slice(&a);
        mem.extend_from_slice(&b);
        let code = program(&[
            Instr::Ldi { d: 0, imm: 0 },
            Instr::Ldi { d: 1, imm: 100 },
            Instr::SStore { a: 0, b: 1 },
            Instr::Ldi { d: 2, imm: 32 },
            Instr::Ldi { d: 3, imm: 200 },
            Instr::SStore { a: 2, b: 3 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 4000)
            .with_memory(&mem)
            .run()
            .expect("halt");
        assert_eq!(out.storage.get(&a), Some(&100));
        assert_eq!(out.storage.get(&b), Some(&200));
        assert_eq!(out.storage.len(), 2, "the two keys are distinct slots");
    }

    #[test]
    fn fault_rolls_back_storage() {
        let key = crate::abi::scalar_key(5);
        let mut persistent = BTreeMap::new();
        persistent.insert(key, 1);
        let code = program(&[
            Instr::Ldi { d: 0, imm: 0 },
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
            .with_memory(&key)
            .run();
        assert_eq!(res, Err(Fault::Overflow));
        assert_eq!(persistent.get(&key), Some(&1));
    }

    #[test]
    fn send_records_transfer_effect() {
        use crate::asm::assemble;
        let account = [171u8; 32];
        let code = assemble("LDI r0, 0\nLDI r1, 32\nLDI r2, 1000\nSEND r0, r1, r2\nHALT")
            .expect("assemble");
        let out = Interpreter::new(&code, &[], 1000)
            .with_memory(&account)
            .run()
            .expect("halt");
        assert_eq!(
            out.effects,
            vec![Effect::Transfer {
                to: account.to_vec(),
                amount: 1000,
            }]
        );
        assert_eq!(
            out.gas_used,
            3 * crate::gas::cost(OpCode::Ldi)
                + crate::gas::cost(OpCode::Send)
                + 32 * crate::gas::EFFECT_BYTE
                + crate::gas::cost(OpCode::Halt)
        );
    }

    #[test]
    fn send_out_of_bounds_target_faults() {
        let code = program(&[
            Instr::Ldi {
                d: 0,
                imm: u64::MAX,
            },
            Instr::Ldi { d: 1, imm: 32 },
            Instr::Ldi { d: 2, imm: 1 },
            Instr::Send { a: 0, b: 1, c: 2 },
            Instr::Halt,
        ]);
        assert_eq!(
            Interpreter::new(&code, &[], 1000).run(),
            Err(Fault::BadMemory)
        );
    }

    #[test]
    fn clean_run_records_no_effects() {
        let code = program(&[Instr::Ldi { d: 0, imm: 1 }, Instr::Halt]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert!(out.effects.is_empty());
    }

    #[test]
    fn emit_records_event_effect() {
        use crate::asm::assemble;
        let payload = [7u8; 16];
        let selector: u32 = 2882343476;
        let code = assemble(&format!(
            "LDI r0, 0\nLDI r1, 16\nLDI r2, {selector}\nEMIT r0, r1, r2\nHALT"
        ))
        .expect("assemble");
        let out = Interpreter::new(&code, &[], 1000)
            .with_memory(&payload)
            .run()
            .expect("halt");
        assert_eq!(
            out.effects,
            vec![Effect::Event {
                selector: selector.to_be_bytes(),
                data: payload.to_vec(),
            }]
        );
    }

    #[test]
    fn emit_out_of_bounds_payload_faults() {
        let code = program(&[
            Instr::Ldi {
                d: 0,
                imm: u64::MAX,
            },
            Instr::Ldi { d: 1, imm: 16 },
            Instr::Ldi { d: 2, imm: 1 },
            Instr::Emit { a: 0, b: 1, c: 2 },
            Instr::Halt,
        ]);
        assert_eq!(
            Interpreter::new(&code, &[], 1000).run(),
            Err(Fault::BadMemory)
        );
    }

    #[test]
    fn emit_charges_per_byte_and_a_small_event_is_priced_sanely() {
        use crate::asm::assemble;
        let payload = [9u8; 64];
        let code = assemble("LDI r0, 0\nLDI r1, 64\nLDI r2, 1\nEMIT r0, r1, r2\nHALT")
            .expect("assemble");
        let out = Interpreter::new(&code, &[], 10_000)
            .with_memory(&payload)
            .run()
            .expect("halt");
        assert_eq!(out.effects.len(), 1);
        assert_eq!(
            out.gas_used,
            3 * crate::gas::cost(OpCode::Ldi)
                + crate::gas::cost(OpCode::Emit)
                + 64 * crate::gas::EFFECT_BYTE
                + crate::gas::cost(OpCode::Halt)
        );
    }

    #[test]
    fn emit_loop_over_full_memory_faults_at_the_effects_cap() {
        use crate::asm::assemble;
        let code = assemble(
            "LDI r0, 0\nLDI r1, 65536\nLDI r2, 1\nloop:\nEMIT r0, r1, r2\nJMP loop\nHALT",
        )
        .expect("assemble");
        let res = Interpreter::new(&code, &[], u64::MAX).run();
        assert_eq!(res, Err(Fault::EffectsTooLarge));
    }

    #[test]
    fn emit_loop_runs_out_of_gas_at_the_proportional_cost() {
        use crate::asm::assemble;
        let code = assemble(
            "LDI r0, 0\nLDI r1, 65536\nLDI r2, 1\nloop:\nEMIT r0, r1, r2\nJMP loop\nHALT",
        )
        .expect("assemble");
        let res = Interpreter::new(&code, &[], 500_000).run();
        assert_eq!(res, Err(Fault::OutOfGas));
    }

    #[test]
    fn an_over_cap_emit_surfaces_no_effects_and_rolls_back_state() {
        use crate::asm::assemble;
        let key = crate::abi::scalar_key(5);
        let mut persistent = BTreeMap::new();
        persistent.insert(key, 1);
        let code = assemble(
            "LDI r0, 0\nLDI r1, 123\nSSTORE r0, r1\nLDI r2, 65536\nLDI r3, 1\nloop:\nEMIT r0, r2, r3\nJMP loop\nHALT",
        )
        .expect("assemble");
        let res = Interpreter::new(&code, &[], u64::MAX)
            .with_storage(persistent.clone())
            .with_memory(&key)
            .run();
        assert_eq!(res, Err(Fault::EffectsTooLarge));
        assert_eq!(persistent.get(&key), Some(&1));
    }

    #[test]
    fn send_charges_per_byte_and_is_bounded_by_the_effects_cap() {
        use crate::asm::assemble;
        let code = assemble(
            "LDI r0, 0\nLDI r1, 65536\nLDI r2, 1\nloop:\nSEND r0, r1, r2\nJMP loop\nHALT",
        )
        .expect("assemble");
        let res = Interpreter::new(&code, &[], u64::MAX).run();
        assert_eq!(res, Err(Fault::EffectsTooLarge));
    }

    #[test]
    fn hash_opcode_runs_metered() {
        let word: u64 = 72623859790382856;
        let code = program(&[
            Instr::Ldi { d: 0, imm: 0 },
            Instr::Ldi { d: 1, imm: word },
            Instr::MStore { a: 0, b: 1 },
            Instr::Ldi { d: 3, imm: 8 },
            Instr::Ldi { d: 4, imm: 64 },
            Instr::Hash { a: 0, b: 3, c: 4 },
            Instr::MLoad { d: 5, a: 4 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 1000).run().expect("halt");
        let digest = qtv_crypto::sha3::sha3_256(&word.to_be_bytes());
        let first = u64::from_be_bytes(digest[..8].try_into().unwrap());
        assert_eq!(out.regs[5], first);
        assert_eq!(
            out.gas_used,
            1 + 1 + 3 + 1 + 1 + crate::gas::cost(OpCode::Hash) + 3
        );
    }

    #[test]
    fn hand_assembled_hash_and_verify_runs_metered() {
        use crate::asm::assemble;
        use qtv_crypto::ml_dsa;

        let (pk, sk) = ml_dsa::keygen(&[9u8; 32]);
        let message = b"quantova hand assembled milestone";
        let signature = ml_dsa::sign(&sk, message, &[], &[0u8; 32]).expect("sign");

        let mut region = Vec::new();
        region.extend_from_slice(&pk);
        region.extend_from_slice(&signature);
        region.extend_from_slice(message);

        let msg_off = ml_dsa::PUBLIC_KEY_BYTES + ml_dsa::SIGNATURE_BYTES;
        let msg_len = message.len();
        let region_len = region.len();
        let digest_off = 32768;

        let src = format!(
            "LDI r0, {msg_off}\n\
             LDI r1, {msg_len}\n\
             LDI r2, {digest_off}\n\
             HASH r0, r1, r2\n\
             MLOAD r6, r2\n\
             LDI r3, 0\n\
             LDI r4, {region_len}\n\
             VERIFYML r3, r4, r5\n\
             HALT"
        );
        let code = assemble(&src).expect("assemble");
        let out = Interpreter::new(&code, &[], 100_000)
            .with_memory(&region)
            .run()
            .expect("halt");

        assert_eq!(out.regs[5], 1, "signature must verify");
        let digest = qtv_crypto::sha3::sha3_256(message);
        let first = u64::from_be_bytes(digest[..8].try_into().unwrap());
        assert_eq!(out.regs[6], first, "hash must match the crypto crate");
        let expected = 5 * crate::gas::cost(OpCode::Ldi)
            + crate::gas::cost(OpCode::Hash)
            + crate::gas::cost(OpCode::MLoad)
            + crate::gas::cost(OpCode::VerifyMl)
            + crate::gas::cost(OpCode::Halt);
        assert_eq!(out.gas_used, expected);
    }

    fn run_verify(mnemonic: &str, region: &[u8]) -> (u64, u64) {
        use crate::asm::assemble;
        let src = format!(
            "LDI r0, 0\nLDI r1, {}\n{} r0, r1, r2\nHALT",
            region.len(),
            mnemonic
        );
        let code = assemble(&src).expect("assemble");
        let out = Interpreter::new(&code, &[], 200_000)
            .with_memory(region)
            .run()
            .expect("halt");
        (out.regs[2], out.gas_used)
    }

    fn verify_gas(op: OpCode) -> u64 {
        2 * crate::gas::cost(OpCode::Ldi) + crate::gas::cost(op) + crate::gas::cost(OpCode::Halt)
    }

    #[test]
    fn slh_verify_opcode_runs_metered() {
        use qtv_crypto::slh_dsa;
        let (sk, pk) = slh_dsa::keygen(&[1u8; 24], &[2u8; 24], &[3u8; 24]);
        let message = b"quantova slh metered";
        let sig = slh_dsa::sign(&sk, message, &[], &[4u8; 24]).expect("sign");
        let mut region = Vec::new();
        region.extend_from_slice(&pk);
        region.extend_from_slice(&sig);
        region.extend_from_slice(message);
        let (result, gas) = run_verify("VERIFYSLH", &region);
        assert_eq!(result, 1);
        assert_eq!(gas, verify_gas(OpCode::VerifySlh));
    }

    #[test]
    fn vrf_verify_opcode_runs_metered() {
        use qtv_crypto::vrf;
        let (sk, pk) = vrf::keygen(b"quantova vrf metered seed");
        let input = b"metered input";
        let (output, proof) = vrf::prove(&sk, input);
        let mut region = Vec::new();
        region.extend_from_slice(&pk);
        region.extend_from_slice(&output);
        region.extend_from_slice(&proof);
        region.extend_from_slice(input);
        let (result, gas) = run_verify("VRFVERIFY", &region);
        assert_eq!(result, 1);
        assert_eq!(gas, verify_gas(OpCode::VrfVerify));
    }

    #[test]
    fn merkle_verify_opcode_runs_metered() {
        use qtv_crypto::sha3::sha3_256;
        fn node(left: &[u8], right: &[u8]) -> [u8; 32] {
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(left);
            pair[32..].copy_from_slice(right);
            sha3_256(&pair)
        }
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let p01 = node(&leaves[0], &leaves[1]);
        let p23 = node(&leaves[2], &leaves[3]);
        let root = node(&p01, &p23);
        let index: u64 = 2;
        let mut region = Vec::new();
        region.extend_from_slice(&root);
        region.extend_from_slice(&index.to_be_bytes());
        region.extend_from_slice(&leaves[2]);
        region.extend_from_slice(&leaves[3]);
        region.extend_from_slice(&p01);
        let (result, gas) = run_verify("MERKLEVERIFY", &region);
        assert_eq!(result, 1);
        assert_eq!(gas, verify_gas(OpCode::MerkleVerify));
    }

    #[test]
    fn kem_opcode_runs_metered() {
        use crate::asm::assemble;
        use qtv_crypto::ml_kem;
        let (ek, _dk) = ml_kem::keygen(&[4u8; 32], &[5u8; 32]);
        let msg = [6u8; 32];
        let mut region = Vec::new();
        region.extend_from_slice(&ek);
        region.extend_from_slice(&msg);
        let src = format!(
            "LDI r0, 0\nLDI r1, {}\nLDI r2, 8192\nKEM r0, r1, r2\nMLOAD r3, r2\nHALT",
            region.len()
        );
        let code = assemble(&src).expect("assemble");
        let out = Interpreter::new(&code, &[], 100_000)
            .with_memory(&region)
            .run()
            .expect("halt");
        let (want_ss, _ct) = ml_kem::encaps(&ek, &msg);
        let first = u64::from_be_bytes(want_ss[..8].try_into().unwrap());
        assert_eq!(out.regs[3], first);
        let expected = 3 * crate::gas::cost(OpCode::Ldi)
            + crate::gas::cost(OpCode::Kem)
            + crate::gas::cost(OpCode::MLoad)
            + crate::gas::cost(OpCode::Halt);
        assert_eq!(out.gas_used, expected);
    }

    #[test]
    fn addr_opcode_derives_the_account_address_metered() {
        use crate::asm::assemble;
        use qtv_crypto::ml_dsa;
        use qtv_crypto::sha3::sha3_256;

        let (pk, _sk) = ml_dsa::keygen(&[5u8; 32]);
        let out_off = 40000u64;
        let src = format!(
            "LDI r0, 0\nLDI r1, {}\nLDI r2, {out_off}\nADDR r0, r1, r2\nMLOAD r3, r2\nHALT",
            crate::crypto::SCHEME_ML_DSA
        );
        let code = assemble(&src).expect("assemble");
        let out = Interpreter::new(&code, &[], 100_000)
            .with_memory(&pk)
            .run()
            .expect("halt");

        let mut preimage = vec![crate::crypto::SCHEME_ML_DSA as u8];
        preimage.extend_from_slice(&pk);
        let want = sha3_256(&preimage);
        let first = u64::from_be_bytes(want[..8].try_into().unwrap());
        assert_eq!(out.regs[3], first, "address matches the account model digest");
        let expected = 3 * crate::gas::cost(OpCode::Ldi)
            + crate::gas::cost(OpCode::Addr)
            + crate::gas::cost(OpCode::MLoad)
            + crate::gas::cost(OpCode::Halt);
        assert_eq!(out.gas_used, expected);
    }

    #[test]
    fn out_of_gas_rolls_back_storage() {
        let key = crate::abi::scalar_key(5);
        let mut persistent = BTreeMap::new();
        persistent.insert(key, 1);
        let code = program(&[
            Instr::Ldi { d: 0, imm: 0 },
            Instr::Ldi { d: 1, imm: 123 },
            Instr::SStore { a: 0, b: 1 },
            Instr::Jmp { target: 23 },
        ]);
        let res = Interpreter::new(&code, &[], 520)
            .with_storage(persistent.clone())
            .with_memory(&key)
            .run();
        assert_eq!(res, Err(Fault::OutOfGas));
        assert_eq!(persistent.get(&key), Some(&1));
    }

    fn two_entry_container() -> (
        crate::container::Container,
        [u8; SELECTOR_BYTES],
        [u8; SELECTOR_BYTES],
    ) {
        use crate::container::{selector, Container, Entry, StateAccess};
        let first = program(&[Instr::Ldi { d: 0, imm: 111 }, Instr::Halt]);
        let second = program(&[Instr::Ldi { d: 0, imm: 222 }, Instr::Halt]);
        let offset = first.len() as u32;
        let mut code = first;
        code.extend_from_slice(&second);
        let alpha = selector("alpha()");
        let beta = selector("beta()");
        let container = Container::new(
            code,
            vec![],
            vec![
                Entry {
                    selector: alpha,
                    offset: 0,
                    access: StateAccess::default(),
                },
                Entry {
                    selector: beta,
                    offset,
                    access: StateAccess::default(),
                },
            ],
        );
        (container, alpha, beta)
    }

    #[test]
    fn dispatch_enters_entry_named_by_selector() {
        let (container, alpha, beta) = two_entry_container();
        let a = Interpreter::for_entry(&container, alpha, 1000)
            .expect("known selector")
            .run()
            .expect("halt");
        assert_eq!(a.regs[0], 111);
        let b = Interpreter::for_entry(&container, beta, 1000)
            .expect("known selector")
            .run()
            .expect("halt");
        assert_eq!(b.regs[0], 222);
        assert_eq!(
            b.gas_used,
            crate::gas::DISPATCH + crate::gas::cost(OpCode::Ldi) + crate::gas::cost(OpCode::Halt)
        );
    }

    #[test]
    fn unknown_selector_reverts() {
        use crate::container::selector;
        let (container, _alpha, _beta) = two_entry_container();
        let res = Interpreter::for_entry(&container, selector("missing()"), 1000);
        assert!(matches!(res, Err(Fault::UnknownSelector)));
    }

    #[test]
    fn dispatch_over_the_limit_runs_out_of_gas() {
        let (container, alpha, _beta) = two_entry_container();
        let res = Interpreter::for_entry(&container, alpha, crate::gas::DISPATCH - 1);
        assert!(matches!(res, Err(Fault::OutOfGas)));
    }

    #[test]
    fn single_entry_path_enters_at_offset_zero() {
        let code = program(&[Instr::Ldi { d: 0, imm: 7 }, Instr::Halt]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[0], 7);
    }
}
