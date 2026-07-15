//! Bytecode container. Holds the code, a constant pool, a state access manifest, and an interface

use qtv_crypto::sha3::sha3_256;

/// Length of an entry or event selector in bytes.
pub const SELECTOR_BYTES: usize = 4;

/// Version tag bound into the canonical bytes so containers of different layouts never collide.
const FORMAT_TAG: [u8; 4] = *b"QVM1";

/// The declared reads and writes of one entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateAccess {
    pub reads: Vec<u64>,
    pub writes: Vec<u64>,
}

/// One callable entry named by its selector, with the code offset it begins at and its declared
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

    /// Deterministic serialization of the whole container. Every field is length prefixed so no two
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

    /// The container identifier. It is the raw digest surfaced later through the identifier format.
    pub fn identifier(&self) -> [u8; 32] {
        sha3_256(&self.canonical_bytes())
    }
}

/// The selector of an entry or event. It is the leading bytes of the SHA3 hash of the canonical
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
            vec![0x00, 0x01, 0x02],
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
        b.code.push(0x03);
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
}
