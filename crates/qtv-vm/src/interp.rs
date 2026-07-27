// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::container::{Container, SELECTOR_BYTES};
use crate::isa::{decode, DecodeError, Instr, NUM_REGS};
use crate::state::Machine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    OutOfMeter,
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
    UndeclaredSlot,
    CryptoFault,
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
    pub meter_used: u64,
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

fn boundaries(code: &[u8]) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let off = match u32::try_from(pc) {
            Ok(o) => o,
            Err(_) => break,
        };
        match decode(code, pc) {
            Ok((_, len)) if len > 0 => {
                set.insert(off);
                pc += len;
            }
            _ => break,
        }
    }
    set
}

struct Manifest {
    reads: BTreeSet<StorageKey>,
    writes: BTreeSet<StorageKey>,
    keyed_reads: BTreeSet<u64>,
    keyed_writes: BTreeSet<u64>,
    boundaries: BTreeSet<u32>,
}

impl Manifest {
    fn can_read(&self, key: &StorageKey) -> bool {
        self.reads.contains(key) || self.writes.contains(key)
    }

    fn can_write(&self, key: &StorageKey) -> bool {
        self.writes.contains(key)
    }
}

pub struct Interpreter<'a> {
    code: &'a [u8],
    consts: &'a [u64],
    machine: Machine,
    meter_limit: u64,
    meter_used: u64,
    storage: BTreeMap<StorageKey, u64>,
    effects: Vec<Effect>,
    effects_bytes: u64,
    manifest: Option<Manifest>,
    keyed_authorized_reads: BTreeSet<StorageKey>,
    keyed_authorized_writes: BTreeSet<StorageKey>,
}

impl<'a> Interpreter<'a> {
    pub fn new(code: &'a [u8], consts: &'a [u64], meter_limit: u64) -> Self {
        Interpreter {
            code,
            consts,
            machine: Machine::new(),
            meter_limit,
            meter_used: 0,
            storage: BTreeMap::new(),
            effects: Vec::new(),
            effects_bytes: 0,
            manifest: None,
            keyed_authorized_reads: BTreeSet::new(),
            keyed_authorized_writes: BTreeSet::new(),
        }
    }

    pub fn for_entry(
        container: &'a Container,
        selector: [u8; SELECTOR_BYTES],
        meter_limit: u64,
    ) -> Result<Self, Fault> {
        let entry = container
            .entries
            .iter()
            .find(|e| e.selector == selector)
            .ok_or(Fault::UnknownSelector)?;
        if crate::meter::DISPATCH > meter_limit {
            return Err(Fault::OutOfMeter);
        }
        let reads = entry
            .access
            .reads
            .iter()
            .map(|&slot| crate::abi::scalar_key(slot))
            .collect();
        let writes = entry
            .access
            .writes
            .iter()
            .map(|&slot| crate::abi::scalar_key(slot))
            .collect();
        let keyed_reads = entry.access.keyed_reads.iter().copied().collect();
        let keyed_writes = entry.access.keyed_writes.iter().copied().collect();
        let mut interp = Interpreter::new(&container.code, &container.consts, meter_limit);
        interp.machine.pc = entry.offset;
        interp.meter_used = crate::meter::DISPATCH;
        interp.manifest = Some(Manifest {
            reads,
            writes,
            keyed_reads,
            keyed_writes,
            boundaries: boundaries(&container.code),
        });
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

            let cost = crate::meter::cost(instr.opcode());
            let spent = self.meter_used.checked_add(cost).ok_or(Fault::OutOfMeter)?;
            if spent > self.meter_limit {
                return Err(Fault::OutOfMeter);
            }
            self.meter_used = spent;

            let next = pc.checked_add(len).ok_or(Fault::BadJump)?;
            self.machine.pc = u32::try_from(next).map_err(|_| Fault::BadJump)?;

            match self.step(instr)? {
                Step::Next => {}
                Step::Halt => {
                    return Ok(Outcome {
                        regs: self.machine.regs,
                        meter_used: self.meter_used,
                        storage: self.storage,
                        effects: self.effects,
                    })
                }
                Step::JumpTo(target) => self.machine.pc = target,
            }
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), Fault> {
        let spent = self.meter_used.checked_add(amount).ok_or(Fault::OutOfMeter)?;
        if spent > self.meter_limit {
            return Err(Fault::OutOfMeter);
        }
        self.meter_used = spent;
        Ok(())
    }

    fn charge_effect(&mut self, bytes: usize) -> Result<(), Fault> {
        let n = bytes as u64;
        let byte_cost = n
            .checked_mul(crate::meter::EFFECT_BYTE)
            .ok_or(Fault::OutOfMeter)?;
        self.charge(byte_cost)?;

        let retained = self
            .effects_bytes
            .checked_add(n)
            .ok_or(Fault::EffectsTooLarge)?;
        if retained > crate::meter::EFFECTS_BYTES_CAP {
            return Err(Fault::EffectsTooLarge);
        }
        self.effects_bytes = retained;
        Ok(())
    }

    fn run_crypto<F>(&mut self, f: F) -> Result<(), Fault>
    where
        F: FnOnce(&mut Machine) -> Result<(), Fault>,
    {
        let machine = &mut self.machine;
        match catch_unwind(AssertUnwindSafe(|| f(machine))) {
            Ok(result) => result,
            Err(_) => Err(Fault::CryptoFault),
        }
    }

    // Keyed storage authorisation. A keyed slot lives at sha3 of a map base and a runtime key, which
    // cannot be listed as an exact slot, so an entry declares the base and the machine authorises any
    // key it derives from a declared base, that map's whole keyspace and nothing else. The base is the
    // first eight bytes of the hash preimage, written big endian by the code generator, and the machine
    // derives the key itself here, so a program cannot authorise a key outside a declared map. A declared
    // write base also grants read, matching the scalar rule that a declared write may be read.
    fn taint_keyed_from_hash(&mut self, preimage_ptr: u64, len: u64, out_ptr: u64) {
        if len < 8 {
            return;
        }
        let base = match self.machine.mem_region(preimage_ptr, 8) {
            Some(head) => u64::from_be_bytes(head.try_into().unwrap()),
            None => return,
        };
        let (is_write, is_read) = match &self.manifest {
            Some(man) => {
                let w = man.keyed_writes.contains(&base);
                (w, w || man.keyed_reads.contains(&base))
            }
            None => return,
        };
        if !is_write && !is_read {
            return;
        }
        let key = match self.machine.mem_region(out_ptr, STORAGE_KEY_BYTES as u64) {
            Some(region) => {
                let mut k = [0u8; STORAGE_KEY_BYTES];
                k.copy_from_slice(region);
                k
            }
            None => return,
        };
        if is_write {
            self.keyed_authorized_writes.insert(key);
        }
        if is_read {
            self.keyed_authorized_reads.insert(key);
        }
    }

    fn target_ok(&self, target: u32) -> bool {
        match &self.manifest {
            Some(man) => man.boundaries.contains(&target),
            None => (target as usize) < self.code.len(),
        }
    }

    fn step(&mut self, instr: Instr) -> Result<Step, Fault> {
        let consts = self.consts;
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
                if !self.target_ok(target) {
                    return Err(Fault::BadJump);
                }
                return Ok(Step::JumpTo(target));
            }
            Instr::Jz { a, target } => {
                if m.reg(a) == 0 {
                    if !self.target_ok(target) {
                        return Err(Fault::BadJump);
                    }
                    return Ok(Step::JumpTo(target));
                }
            }
            Instr::Jnz { a, target } => {
                if m.reg(a) != 0 {
                    if !self.target_ok(target) {
                        return Err(Fault::BadJump);
                    }
                    return Ok(Step::JumpTo(target));
                }
            }
            Instr::Call { target } => {
                let ret = u64::from(m.pc);
                if !m.push(ret) {
                    return Err(Fault::StackOverflow);
                }
                if !self.target_ok(target) {
                    return Err(Fault::BadJump);
                }
                return Ok(Step::JumpTo(target));
            }
            Instr::Ret => {
                let ret = m.pop().ok_or(Fault::StackUnderflow)?;
                let target = u32::try_from(ret).map_err(|_| Fault::BadJump)?;
                if !self.target_ok(target) {
                    return Err(Fault::BadJump);
                }
                return Ok(Step::JumpTo(target));
            }

            Instr::SLoad { d, a } => {
                let key = read_key(m, m.reg(a))?;
                if let Some(man) = &self.manifest {
                    if !man.can_read(&key) && !self.keyed_authorized_reads.contains(&key) {
                        return Err(Fault::UndeclaredSlot);
                    }
                }
                let v = self.storage.get(&key).copied().unwrap_or(0);
                m.set_reg(d, v);
            }
            Instr::SStore { a, b } => {
                let key = read_key(m, m.reg(a))?;
                let val = m.reg(b);
                if let Some(man) = &self.manifest {
                    if !man.can_write(&key) && !self.keyed_authorized_writes.contains(&key) {
                        return Err(Fault::UndeclaredSlot);
                    }
                }
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

            Instr::Hash { a, b, c } => {
                let preimage_ptr = m.reg(a);
                let len = m.reg(b);
                let out_ptr = m.reg(c);
                self.charge(crate::meter::hash_variable(len))?;
                self.run_crypto(|machine| crate::crypto::hash(machine, a, b, c))?;
                self.taint_keyed_from_hash(preimage_ptr, len, out_ptr);
            }
            Instr::VerifyMl { a, b, c } => {
                let tail = m.reg(b).saturating_sub(crate::crypto::ML_DSA_SIGNED_BYTES);
                self.charge(crate::meter::message_variable(tail))?;
                self.run_crypto(|machine| crate::crypto::verify_ml(machine, a, b, c))?;
            }
            Instr::VerifySlh { a, b, c } => {
                let tail = m.reg(b).saturating_sub(crate::crypto::SLH_DSA_SIGNED_BYTES);
                self.charge(crate::meter::message_variable(tail))?;
                self.run_crypto(|machine| crate::crypto::verify_slh(machine, a, b, c))?;
            }
            Instr::MerkleVerify { a, b, c } => {
                let path = m.reg(b).saturating_sub(crate::crypto::MERKLE_HEADER);
                self.charge(crate::meter::merkle_variable(path))?;
                self.run_crypto(|machine| crate::crypto::merkle_verify(machine, a, b, c))?;
            }
            Instr::Kem { a, b, c } => {
                self.run_crypto(|machine| crate::crypto::kem(machine, a, b, c))?;
            }
            Instr::Addr { a, b, c } => {
                self.run_crypto(|machine| crate::crypto::address(machine, a, b, c))?;
            }
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
        assert_eq!(out.meter_used, 1);
    }

    #[test]
    fn missing_halt_faults() {
        let code = program(&[Instr::Nop]);
        let err = Interpreter::new(&code, &[], 100).run().unwrap_err();
        assert_eq!(err, Fault::Decode(DecodeError::Truncated));
    }

    #[test]
    fn computes_value_and_reports_meter() {
        let code = program(&[
            Instr::Ldi { d: 0, imm: 5 },
            Instr::Ldi { d: 1, imm: 7 },
            Instr::Add { d: 2, a: 0, b: 1 },
            Instr::Halt,
        ]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 12);
        assert_eq!(out.meter_used, 1 + 1 + 2);
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
    fn out_of_meter_faults() {
        let code = program(&[Instr::Jmp { target: 0 }]);
        assert_eq!(Interpreter::new(&code, &[], 10).run(), Err(Fault::OutOfMeter));
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
            out.meter_used,
            3 * crate::meter::cost(OpCode::Ldi)
                + crate::meter::cost(OpCode::Send)
                + 32 * crate::meter::EFFECT_BYTE
                + crate::meter::cost(OpCode::Halt)
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
            out.meter_used,
            3 * crate::meter::cost(OpCode::Ldi)
                + crate::meter::cost(OpCode::Emit)
                + 64 * crate::meter::EFFECT_BYTE
                + crate::meter::cost(OpCode::Halt)
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
    fn emit_loop_runs_out_of_meter_at_the_proportional_cost() {
        use crate::asm::assemble;
        let code = assemble(
            "LDI r0, 0\nLDI r1, 65536\nLDI r2, 1\nloop:\nEMIT r0, r1, r2\nJMP loop\nHALT",
        )
        .expect("assemble");
        let res = Interpreter::new(&code, &[], 500_000).run();
        assert_eq!(res, Err(Fault::OutOfMeter));
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
            out.meter_used,
            1 + 1 + 3 + 1 + 1 + crate::meter::cost(OpCode::Hash) + crate::meter::hash_variable(8) + 3
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
        let expected = 5 * crate::meter::cost(OpCode::Ldi)
            + crate::meter::cost(OpCode::Hash)
            + crate::meter::hash_variable(msg_len as u64)
            + crate::meter::cost(OpCode::MLoad)
            + crate::meter::cost(OpCode::VerifyMl)
            + crate::meter::message_variable(msg_len as u64)
            + crate::meter::cost(OpCode::Halt);
        assert_eq!(out.meter_used, expected);
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
        (out.regs[2], out.meter_used)
    }

    fn verify_meter(op: OpCode, variable: u64) -> u64 {
        2 * crate::meter::cost(OpCode::Ldi)
            + crate::meter::cost(op)
            + variable
            + crate::meter::cost(OpCode::Halt)
    }

    fn merkle_leaf(data: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 33];
        buf[0] = 0x00;
        buf[1..].copy_from_slice(data);
        qtv_crypto::sha3::sha3_256(&buf)
    }

    fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 65];
        buf[0] = 0x01;
        buf[1..33].copy_from_slice(left);
        buf[33..].copy_from_slice(right);
        qtv_crypto::sha3::sha3_256(&buf)
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
        let (result, meter) = run_verify("VERIFYSLH", &region);
        assert_eq!(result, 1);
        assert_eq!(
            meter,
            verify_meter(
                OpCode::VerifySlh,
                crate::meter::message_variable(message.len() as u64)
            )
        );
    }

    #[test]
    fn merkle_verify_opcode_runs_metered() {
        use qtv_crypto::sha3::sha3_256;
        let data: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let tagged: Vec<[u8; 32]> = data.iter().map(merkle_leaf).collect();
        let p01 = merkle_node(&tagged[0], &tagged[1]);
        let p23 = merkle_node(&tagged[2], &tagged[3]);
        let root = merkle_node(&p01, &p23);
        let index: u64 = 2;
        let mut region = Vec::new();
        region.extend_from_slice(&root);
        region.extend_from_slice(&index.to_be_bytes());
        region.extend_from_slice(&data[2]);
        region.extend_from_slice(&tagged[3]);
        region.extend_from_slice(&p01);
        let path_bytes = (region.len() as u64) - crate::crypto::MERKLE_HEADER;
        let (result, meter) = run_verify("MERKLEVERIFY", &region);
        assert_eq!(result, 1);
        assert_eq!(
            meter,
            verify_meter(OpCode::MerkleVerify, crate::meter::merkle_variable(path_bytes))
        );
    }

    #[test]
    fn a_hash_scales_with_the_length_it_absorbs() {
        use crate::asm::assemble;
        let short = assemble("LDI r0, 0\nLDI r1, 8\nLDI r2, 40000\nHASH r0, r1, r2\nHALT")
            .expect("assemble");
        let long = assemble("LDI r0, 0\nLDI r1, 40000\nLDI r2, 40000\nHASH r0, r1, r2\nHALT")
            .expect("assemble");
        let short_meter = Interpreter::new(&short, &[], 1_000_000)
            .run()
            .expect("halt")
            .meter_used;
        let long_meter = Interpreter::new(&long, &[], 1_000_000)
            .run()
            .expect("halt")
            .meter_used;
        assert_eq!(
            long_meter - short_meter,
            crate::meter::hash_variable(40000) - crate::meter::hash_variable(8)
        );
        assert!(long_meter > short_meter);
    }

    #[test]
    fn a_hash_loop_over_full_memory_runs_out_of_meter() {
        use crate::asm::assemble;
        let code = assemble(
            "LDI r0, 0\nLDI r1, 65536\nLDI r2, 0\nloop:\nHASH r0, r1, r2\nJMP loop\nHALT",
        )
        .expect("assemble");
        let res = Interpreter::new(&code, &[], 500_000).run();
        assert_eq!(res, Err(Fault::OutOfMeter));
    }

    #[test]
    fn a_panicking_crypto_call_is_caught_and_mapped_to_a_fault() {
        let code = program(&[Instr::Halt]);
        let mut interp = Interpreter::new(&code, &[], 100);
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = interp.run_crypto(|_| panic!("adversarial input reached a primitive"));
        std::panic::set_hook(hook);
        assert_eq!(result, Err(Fault::CryptoFault));
    }

    #[test]
    fn a_dispatched_entry_may_only_write_declared_slots() {
        use crate::asm::assemble;
        use crate::container::{selector, Container, Entry, StateAccess};
        let code = assemble("LDI r0, 0\nLDI r1, 55\nSSTORE r0, r1\nHALT").expect("assemble");
        let sel = selector("store()");
        let container = Container::new(
            code,
            vec![],
            vec![Entry {
                selector: sel,
                offset: 0,
                access: StateAccess {
                    reads: vec![],
                    writes: vec![7],
                    ..Default::default()
                },
            }],
        );
        let key7 = crate::abi::scalar_key(7);
        let out = Interpreter::for_entry(&container, sel, 5000)
            .expect("entry")
            .with_memory(&key7)
            .run()
            .expect("halt");
        assert_eq!(out.storage.get(&key7), Some(&55));

        let key8 = crate::abi::scalar_key(8);
        let res = Interpreter::for_entry(&container, sel, 5000)
            .expect("entry")
            .with_memory(&key8)
            .run();
        assert_eq!(res, Err(Fault::UndeclaredSlot));
    }

    #[test]
    fn a_declared_map_base_authorises_its_whole_keyspace() {
        use crate::asm::assemble;
        use crate::container::{selector, Container, Entry, StateAccess};
        let base: u64 = 1 << 40;
        let mut mem = Vec::new();
        mem.extend_from_slice(&base.to_be_bytes());
        mem.extend_from_slice(&0x00AB_CDEFu64.to_be_bytes());
        let want = qtv_crypto::sha3::sha3_256(&mem);
        let code = assemble(
            "LDI r0, 0\nLDI r1, 16\nLDI r2, 64\nHASH r0, r1, r2\nLDI r3, 64\nLDI r4, 99\nSSTORE r3, r4\nHALT",
        )
        .expect("assemble");
        let sel = selector("credit()");
        let container = Container::new(
            code,
            vec![],
            vec![Entry {
                selector: sel,
                offset: 0,
                access: StateAccess {
                    keyed_writes: vec![base],
                    ..Default::default()
                },
            }],
        );
        let out = Interpreter::for_entry(&container, sel, 50_000)
            .expect("entry")
            .with_memory(&mem)
            .run()
            .expect("halt");
        let mut key = [0u8; STORAGE_KEY_BYTES];
        key.copy_from_slice(&want);
        assert_eq!(
            out.storage.get(&key),
            Some(&99),
            "a declared map base authorises writing that map at any key"
        );
    }

    #[test]
    fn an_undeclared_map_still_faults_on_a_keyed_write() {
        use crate::asm::assemble;
        use crate::container::{selector, Container, Entry, StateAccess};
        let written: u64 = 1 << 40;
        let declared: u64 = (1 << 40) + (1 << 32);
        let mut mem = Vec::new();
        mem.extend_from_slice(&written.to_be_bytes());
        mem.extend_from_slice(&0x00AB_CDEFu64.to_be_bytes());
        let code = assemble(
            "LDI r0, 0\nLDI r1, 16\nLDI r2, 64\nHASH r0, r1, r2\nLDI r3, 64\nLDI r4, 99\nSSTORE r3, r4\nHALT",
        )
        .expect("assemble");
        let sel = selector("credit()");
        let container = Container::new(
            code,
            vec![],
            vec![Entry {
                selector: sel,
                offset: 0,
                access: StateAccess {
                    keyed_writes: vec![declared],
                    ..Default::default()
                },
            }],
        );
        let res = Interpreter::for_entry(&container, sel, 50_000)
            .expect("entry")
            .with_memory(&mem)
            .run();
        assert_eq!(
            res,
            Err(Fault::UndeclaredSlot),
            "writing a map the entry did not declare must still fault"
        );
    }

    #[test]
    fn a_dispatched_entry_may_only_read_declared_slots() {
        use crate::asm::assemble;
        use crate::container::{selector, Container, Entry, StateAccess};
        let code = assemble("LDI r0, 0\nSLOAD r2, r0\nHALT").expect("assemble");
        let sel = selector("look()");
        let container = Container::new(
            code,
            vec![],
            vec![Entry {
                selector: sel,
                offset: 0,
                access: StateAccess {
                    reads: vec![7],
                    writes: vec![],
                    ..Default::default()
                },
            }],
        );
        let key7 = crate::abi::scalar_key(7);
        Interpreter::for_entry(&container, sel, 5000)
            .expect("entry")
            .with_memory(&key7)
            .run()
            .expect("halt");

        let key8 = crate::abi::scalar_key(8);
        let res = Interpreter::for_entry(&container, sel, 5000)
            .expect("entry")
            .with_memory(&key8)
            .run();
        assert_eq!(res, Err(Fault::UndeclaredSlot));
    }

    #[test]
    fn a_computed_jump_off_a_boundary_faults_under_dispatch() {
        use crate::asm::assemble;
        use crate::container::{selector, Container, Entry, StateAccess};
        let code = assemble("LDI r0, 3\nPUSH r0\nRET").expect("assemble");
        let sel = selector("jump()");
        let container = Container::new(
            code,
            vec![],
            vec![Entry {
                selector: sel,
                offset: 0,
                access: StateAccess::default(),
            }],
        );
        let res = Interpreter::for_entry(&container, sel, 5000).expect("entry").run();
        assert_eq!(res, Err(Fault::BadJump));
    }

    #[test]
    fn a_call_and_return_between_boundaries_still_runs_under_dispatch() {
        use crate::asm::assemble;
        use crate::container::{selector, Container, Entry, StateAccess};
        let code = assemble("CALL fn\nHALT\nfn:\nLDI r0, 9\nRET").expect("assemble");
        let sel = selector("go()");
        let container = Container::new(
            code,
            vec![],
            vec![Entry {
                selector: sel,
                offset: 0,
                access: StateAccess::default(),
            }],
        );
        let out = Interpreter::for_entry(&container, sel, 5000)
            .expect("entry")
            .run()
            .expect("halt");
        assert_eq!(out.regs[0], 9);
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
        let expected = 3 * crate::meter::cost(OpCode::Ldi)
            + crate::meter::cost(OpCode::Kem)
            + crate::meter::cost(OpCode::MLoad)
            + crate::meter::cost(OpCode::Halt);
        assert_eq!(out.meter_used, expected);
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
        let expected = 3 * crate::meter::cost(OpCode::Ldi)
            + crate::meter::cost(OpCode::Addr)
            + crate::meter::cost(OpCode::MLoad)
            + crate::meter::cost(OpCode::Halt);
        assert_eq!(out.meter_used, expected);
    }

    #[test]
    fn out_of_meter_rolls_back_storage() {
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
        assert_eq!(res, Err(Fault::OutOfMeter));
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
            b.meter_used,
            crate::meter::DISPATCH + crate::meter::cost(OpCode::Ldi) + crate::meter::cost(OpCode::Halt)
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
    fn dispatch_over_the_limit_runs_out_of_meter() {
        let (container, alpha, _beta) = two_entry_container();
        let res = Interpreter::for_entry(&container, alpha, crate::meter::DISPATCH - 1);
        assert!(matches!(res, Err(Fault::OutOfMeter)));
    }

    #[test]
    fn single_entry_path_enters_at_offset_zero() {
        let code = program(&[Instr::Ldi { d: 0, imm: 7 }, Instr::Halt]);
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[0], 7);
    }
}
