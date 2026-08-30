// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::isa::{Reg, NUM_REGS};

pub const STACK_LIMIT: usize = 1024;

pub const MEM_BYTES: usize = 65536;

pub const WORD_BYTES: usize = 8;

#[derive(Debug, Clone)]
pub struct Machine {
    pub regs: [u64; NUM_REGS],
    pub pc: u32,
    pub stack: Vec<u64>,
    pub mem: Vec<u8>,
}

impl Default for Machine {
    fn default() -> Self {
        Machine::new()
    }
}

impl Machine {
    pub fn new() -> Self {
        Machine {
            regs: [0; NUM_REGS],
            pc: 0,
            stack: Vec::new(),
            mem: vec![0; MEM_BYTES],
        }
    }

    pub fn reg(&self, r: Reg) -> u64 {
        self.regs[r as usize]
    }

    pub fn set_reg(&mut self, r: Reg, v: u64) {
        self.regs[r as usize] = v;
    }

    pub fn push(&mut self, v: u64) -> bool {
        if self.stack.len() >= STACK_LIMIT {
            return false;
        }
        self.stack.push(v);
        true
    }

    pub fn pop(&mut self) -> Option<u64> {
        self.stack.pop()
    }

    pub fn mem_load(&self, offset: u64) -> Option<u64> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(WORD_BYTES)?;
        let bytes = self.mem.get(start..end)?;
        let mut buf = [0u8; WORD_BYTES];
        buf.copy_from_slice(bytes);
        Some(u64::from_be_bytes(buf))
    }

    pub fn mem_region(&self, offset: u64, len: u64) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let len = usize::try_from(len).ok()?;
        let end = start.checked_add(len)?;
        self.mem.get(start..end)
    }

    pub fn mem_write(&mut self, offset: u64, bytes: &[u8]) -> bool {
        let start = match usize::try_from(offset) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let end = match start.checked_add(bytes.len()) {
            Some(e) => e,
            None => return false,
        };
        match self.mem.get_mut(start..end) {
            Some(slot) => {
                slot.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }

    pub fn mem_store(&mut self, offset: u64, v: u64) -> bool {
        let start = match usize::try_from(offset) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let end = match start.checked_add(WORD_BYTES) {
            Some(e) => e,
            None => return false,
        };
        match self.mem.get_mut(start..end) {
            Some(slot) => {
                slot.copy_from_slice(&v.to_be_bytes());
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_zeroed() {
        let m = Machine::new();
        assert_eq!(m.pc, 0);
        assert!(m.stack.is_empty());
        assert_eq!(m.mem.len(), MEM_BYTES);
        assert!(m.regs.iter().all(|&w| w == 0));
        assert!(m.mem.iter().all(|&b| b == 0));
    }

    #[test]
    fn registers_round_trip() {
        let mut m = Machine::new();
        m.set_reg(3, 42);
        assert_eq!(m.reg(3), 42);
        assert_eq!(m.reg(4), 0);
    }

    #[test]
    fn stack_respects_limit() {
        let mut m = Machine::new();
        for i in 0..STACK_LIMIT {
            assert!(m.push(i as u64));
        }
        assert!(!m.push(0));
        assert_eq!(m.pop(), Some((STACK_LIMIT - 1) as u64));
    }

    #[test]
    fn byte_region_round_trip_and_bounds() {
        let mut m = Machine::new();
        assert!(m.mem_write(10, &[1, 2, 3, 4]));
        assert_eq!(m.mem_region(10, 4), Some(&[1, 2, 3, 4][..]));
        assert_eq!(m.mem_region(0, MEM_BYTES as u64), Some(&m.mem[..]));
        assert_eq!(m.mem_region(MEM_BYTES as u64, 1), None);
        assert_eq!(m.mem_region(0, MEM_BYTES as u64 + 1), None);
        assert!(!m.mem_write(MEM_BYTES as u64, &[1]));
        assert!(!m.mem_write(u64::MAX, &[1]));
        assert_eq!(m.mem_region(4, 0), Some(&[][..]));
    }

    #[test]
    fn memory_round_trip_and_bounds() {
        let mut m = Machine::new();
        assert!(m.mem_store(0, 72623859790382856));
        assert_eq!(m.mem_load(0), Some(72623859790382856));
        assert_eq!(m.mem_load((MEM_BYTES - WORD_BYTES + 1) as u64), None);
        assert!(!m.mem_store(u64::MAX, 1));
    }
}
