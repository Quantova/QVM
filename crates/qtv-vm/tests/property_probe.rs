// Independent property probe (bug-bounty research, not upstream).
use qtv_vm::isa::{decode, Instr};

fn roundtrip(i: Instr) -> bool {
    let mut buf = Vec::new();
    i.encode(&mut buf);
    match decode(&buf, 0) {
        Ok((j, used)) => used == buf.len() && j.opcode() == i.opcode(),
        Err(_) => false,
    }
}

#[test]
fn extreme_immediates_roundtrip() {
    let cases = [
        Instr::Ldi { d: 15, imm: u64::MAX },
        Instr::Ldi { d: 0, imm: 0 },
        Instr::Ldc { d: 15, idx: u16::MAX },
        Instr::Jmp { target: u32::MAX },
        Instr::Call { target: u32::MAX },
        Instr::Jz { a: 15, target: u32::MAX },
        Instr::Mov { d: 15, a: 15 },
        Instr::AddW { d: 15, a: 15, b: 15 },
        Instr::DivW { dlo: 15, dhi: 14, alo: 13, ahi: 12, blo: 11, bhi: 10 },
    ];
    for c in cases {
        assert!(roundtrip(c), "roundtrip failed for {:?}", c.opcode());
    }
}

#[test]
fn decode_never_panics_on_all_two_byte_prefixes() {
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            let bytes = [a as u8, b as u8];
            let _ = decode(&bytes, 0);
        }
    }
}

#[test]
fn decode_never_panics_on_three_byte_streams_sample() {
    for a in [0u8, 1, 2, 3, 15, 16, 32, 64, 128, 255] {
        for b in 0u8..=255 {
            for c in [0u8, 1, 255] {
                let bytes = [a, b, c];
                let _ = decode(&bytes, 0);
            }
        }
    }
}
