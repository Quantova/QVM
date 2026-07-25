// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::collections::BTreeSet;

use qtv_crypto::sha3::sha3_256;

use crate::isa::{decode, Instr};

pub const SELECTOR_BYTES: usize = 4;

pub const GENESIS_SIGNATURE: &str = "@genesis()";

pub const MAX_CODE_BYTES: usize = 1 << 16;

pub const MAX_CONSTS: usize = 1 << 12;

pub const MAX_ENTRIES: usize = 1 << 8;

const FORMAT_TAG: [u8; 4] = *b"QVM1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    CodeTooLarge,
    ConstsTooLarge,
    EntriesTooLarge,
    UndecodableCode(usize),
    ConstIndexOutOfRange(u16),
    MisalignedTarget(u32),
    EntryOffsetMisaligned([u8; SELECTOR_BYTES]),
    DuplicateSelector([u8; SELECTOR_BYTES]),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateAccess {
    pub reads: Vec<u64>,
    pub writes: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub selector: [u8; SELECTOR_BYTES],
    pub offset: u32,
    pub access: StateAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Container {
    pub code: Vec<u8>,
    pub consts: Vec<u64>,
    pub entries: Vec<Entry>,
}

impl Container {
    pub fn new(code: Vec<u8>, consts: Vec<u64>, entries: Vec<Entry>) -> Self {
        Container {
            code,
            consts,
            entries,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&FORMAT_TAG);

        put_len(&mut out, self.code.len());
        out.extend_from_slice(&self.code);

        put_len(&mut out, self.consts.len());
        for c in &self.consts {
            out.extend_from_slice(&c.to_be_bytes());
        }

        put_len(&mut out, self.entries.len());
        for entry in &self.entries {
            out.extend_from_slice(&entry.selector);
            out.extend_from_slice(&entry.offset.to_be_bytes());
            put_slots(&mut out, &entry.access.reads);
            put_slots(&mut out, &entry.access.writes);
        }
        out
    }

    pub fn identifier(&self) -> [u8; 32] {
        sha3_256(&self.canonical_bytes())
    }

    pub fn entry_offset(&self, selector: &[u8; SELECTOR_BYTES]) -> Option<u32> {
        self.entries
            .iter()
            .find(|e| &e.selector == selector)
            .map(|e| e.offset)
    }

    pub fn verify(&self) -> Result<(), VerifyError> {
        if self.code.len() > MAX_CODE_BYTES {
            return Err(VerifyError::CodeTooLarge);
        }
        if self.consts.len() > MAX_CONSTS {
            return Err(VerifyError::ConstsTooLarge);
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(VerifyError::EntriesTooLarge);
        }

        let mut starts = BTreeSet::new();
        let mut targets: Vec<u32> = Vec::new();
        let mut pc = 0usize;
        while pc < self.code.len() {
            let (instr, len) =
                decode(&self.code, pc).map_err(|_| VerifyError::UndecodableCode(pc))?;
            starts.insert(pc as u32);
            match instr {
                Instr::Jmp { target } | Instr::Call { target } => targets.push(target),
                Instr::Jz { target, .. } | Instr::Jnz { target, .. } => targets.push(target),
                Instr::Ldc { idx, .. } => {
                    if idx as usize >= self.consts.len() {
                        return Err(VerifyError::ConstIndexOutOfRange(idx));
                    }
                }
                _ => {}
            }
            pc += len;
        }

        for target in targets {
            if !starts.contains(&target) {
                return Err(VerifyError::MisalignedTarget(target));
            }
        }

        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if !seen.insert(entry.selector) {
                return Err(VerifyError::DuplicateSelector(entry.selector));
            }
            if !starts.contains(&entry.offset) {
                return Err(VerifyError::EntryOffsetMisaligned(entry.selector));
            }
        }
        Ok(())
    }
}

pub fn selector(signature: &str) -> [u8; SELECTOR_BYTES] {
    let digest = sha3_256(signature.as_bytes());
    let mut sel = [0u8; SELECTOR_BYTES];
    sel.copy_from_slice(&digest[..SELECTOR_BYTES]);
    sel
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_be_bytes());
}

fn put_slots(out: &mut Vec<u8>, slots: &[u64]) {
    put_len(out, slots.len());
    for slot in slots {
        out.extend_from_slice(&slot.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Container {
        Container::new(
            vec![0, 1, 2],
            vec![10, 20],
            vec![Entry {
                selector: selector("transfer(Address,u64)"),
                offset: 0,
                access: StateAccess {
                    reads: vec![1],
                    writes: vec![2, 3],
                },
            }],
        )
    }

    #[test]
    fn identifier_is_deterministic() {
        assert_eq!(sample().identifier(), sample().identifier());
    }

    #[test]
    fn code_change_changes_identifier() {
        let a = sample();
        let mut b = sample();
        b.code.push(3);
        assert_ne!(a.identifier(), b.identifier());
    }

    #[test]
    fn manifest_change_changes_identifier() {
        let a = sample();
        let mut b = sample();
        b.entries[0].access.writes.push(9);
        assert_ne!(a.identifier(), b.identifier());
    }

    #[test]
    fn entry_offset_change_changes_identifier() {
        let a = sample();
        let mut b = sample();
        b.entries[0].offset = 16;
        assert_ne!(a.identifier(), b.identifier());
    }

    #[test]
    fn selector_is_deterministic() {
        assert_eq!(selector("mint(u64)"), selector("mint(u64)"));
        assert_ne!(selector("mint(u64)"), selector("burn(u64)"));
    }

    #[test]
    fn entry_offset_resolves_by_selector() {
        let container = Container::new(
            vec![],
            vec![],
            vec![
                Entry {
                    selector: selector("mint(u64)"),
                    offset: 0,
                    access: StateAccess::default(),
                },
                Entry {
                    selector: selector("burn(u64)"),
                    offset: 24,
                    access: StateAccess::default(),
                },
            ],
        );
        assert_eq!(container.entry_offset(&selector("mint(u64)")), Some(0));
        assert_eq!(container.entry_offset(&selector("burn(u64)")), Some(24));
        assert_eq!(container.entry_offset(&selector("pause()")), None);
    }

    fn one_entry(code: Vec<u8>, offset: u32) -> Container {
        Container::new(
            code,
            vec![],
            vec![Entry {
                selector: selector("run()"),
                offset,
                access: StateAccess::default(),
            }],
        )
    }

    #[test]
    fn verify_accepts_a_well_formed_container() {
        let code = crate::asm::assemble("LDI r0, 1\nJMP done\ndone:\nHALT").expect("assemble");
        assert_eq!(one_entry(code, 0).verify(), Ok(()));
    }

    #[test]
    fn verify_rejects_a_jump_into_the_middle_of_an_instruction() {
        let code = crate::asm::assemble("LDI r0, 1\nJMP 3\nHALT").expect("assemble");
        assert_eq!(one_entry(code, 0).verify(), Err(VerifyError::MisalignedTarget(3)));
    }

    #[test]
    fn verify_rejects_an_entry_offset_off_a_boundary() {
        let code = crate::asm::assemble("LDI r0, 1\nHALT").expect("assemble");
        let container = one_entry(code, 3);
        assert_eq!(
            container.verify(),
            Err(VerifyError::EntryOffsetMisaligned(selector("run()")))
        );
    }

    #[test]
    fn verify_rejects_a_truncated_tail() {
        let mut code = crate::asm::assemble("LDI r0, 1\nHALT").expect("assemble");
        code.push(crate::isa::OpCode::Add as u8);
        let container = one_entry(code, 0);
        assert!(matches!(
            container.verify(),
            Err(VerifyError::UndecodableCode(_))
        ));
    }

    #[test]
    fn verify_rejects_oversize_code() {
        let code = vec![crate::isa::OpCode::Nop as u8; MAX_CODE_BYTES + 1];
        assert_eq!(one_entry(code, 0).verify(), Err(VerifyError::CodeTooLarge));
    }

    #[test]
    fn verify_rejects_a_const_index_past_the_pool() {
        let code = crate::asm::assemble("LDC r0, 5\nHALT").expect("assemble");
        let container = Container::new(
            code,
            vec![1, 2],
            vec![Entry {
                selector: selector("run()"),
                offset: 0,
                access: StateAccess::default(),
            }],
        );
        assert_eq!(
            container.verify(),
            Err(VerifyError::ConstIndexOutOfRange(5))
        );
    }

    #[test]
    fn verify_rejects_duplicate_selectors() {
        let code = crate::asm::assemble("HALT").expect("assemble");
        let sel = selector("dup()");
        let container = Container::new(
            code,
            vec![],
            vec![
                Entry {
                    selector: sel,
                    offset: 0,
                    access: StateAccess::default(),
                },
                Entry {
                    selector: sel,
                    offset: 0,
                    access: StateAccess::default(),
                },
            ],
        );
        assert_eq!(container.verify(), Err(VerifyError::DuplicateSelector(sel)));
    }
}
