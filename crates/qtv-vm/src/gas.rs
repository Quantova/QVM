
use crate::isa::OpCode;

pub const DISPATCH: u64 = 4;

pub const EFFECT_BYTE: u64 = 2;

pub const EFFECTS_BYTES_CAP: u64 = 1 << 20;

pub const KECCAK_RATE: u64 = 136;

pub const HASH_BLOCK: u64 = 6;

pub const MERKLE_LEVEL: u64 = 8;

pub const VERIFY_MESSAGE_BLOCK: u64 = 6;

fn keccak_blocks(len: u64) -> u64 {
    len / KECCAK_RATE + 1
}

pub fn hash_variable(len: u64) -> u64 {
    keccak_blocks(len).saturating_mul(HASH_BLOCK)
}

pub fn message_variable(tail: u64) -> u64 {
    keccak_blocks(tail).saturating_mul(VERIFY_MESSAGE_BLOCK)
}

pub fn merkle_variable(path_bytes: u64) -> u64 {
    (path_bytes / 32).saturating_mul(MERKLE_LEVEL)
}

pub fn cost(op: OpCode) -> u64 {
    match op {
        OpCode::Halt => 0,
        OpCode::Nop => 1,

        OpCode::Mov => 1,
        OpCode::Ldi => 1,
        OpCode::Ldc => 1,

        OpCode::Add => 2,
        OpCode::Sub => 2,
        OpCode::Mul => 3,
        OpCode::Div => 4,
        OpCode::Rem => 4,
        OpCode::AddW => 2,
        OpCode::SubW => 2,
        OpCode::MulW => 3,
        OpCode::MulHi => 3,

        OpCode::And => 1,
        OpCode::Or => 1,
        OpCode::Xor => 1,
        OpCode::Not => 1,
        OpCode::Shl => 1,
        OpCode::Shr => 1,
        OpCode::Eq => 1,
        OpCode::LtU => 1,
        OpCode::GtU => 1,

        OpCode::Push => 2,
        OpCode::Pop => 2,
        OpCode::MLoad => 3,
        OpCode::MStore => 3,

        OpCode::Jmp => 2,
        OpCode::Jz => 2,
        OpCode::Jnz => 2,
        OpCode::Call => 3,
        OpCode::Ret => 2,

        OpCode::SLoad => 100,
        OpCode::SStore => 500,

        OpCode::Send => 200,
        OpCode::Emit => 200,

        OpCode::Hash => 32,
        OpCode::VerifyMl => 1600,
        OpCode::VerifySlh => 64000,
        OpCode::MerkleVerify => 512,
        OpCode::Kem => 640,
        OpCode::Addr => 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Instr;

    fn every_opcode() -> Vec<OpCode> {
        [
            Instr::Halt,
            Instr::Nop,
            Instr::Mov { d: 0, a: 0 },
            Instr::Ldi { d: 0, imm: 0 },
            Instr::Ldc { d: 0, idx: 0 },
            Instr::Add { d: 0, a: 0, b: 0 },
            Instr::Sub { d: 0, a: 0, b: 0 },
            Instr::Mul { d: 0, a: 0, b: 0 },
            Instr::Div { d: 0, a: 0, b: 0 },
            Instr::Rem { d: 0, a: 0, b: 0 },
            Instr::AddW { d: 0, a: 0, b: 0 },
            Instr::SubW { d: 0, a: 0, b: 0 },
            Instr::MulW { d: 0, a: 0, b: 0 },
            Instr::MulHi { d: 0, a: 0, b: 0 },
            Instr::And { d: 0, a: 0, b: 0 },
            Instr::Or { d: 0, a: 0, b: 0 },
            Instr::Xor { d: 0, a: 0, b: 0 },
            Instr::Not { d: 0, a: 0 },
            Instr::Shl { d: 0, a: 0, b: 0 },
            Instr::Shr { d: 0, a: 0, b: 0 },
            Instr::Eq { d: 0, a: 0, b: 0 },
            Instr::LtU { d: 0, a: 0, b: 0 },
            Instr::GtU { d: 0, a: 0, b: 0 },
            Instr::Push { a: 0 },
            Instr::Pop { d: 0 },
            Instr::MLoad { d: 0, a: 0 },
            Instr::MStore { a: 0, b: 0 },
            Instr::Jmp { target: 0 },
            Instr::Jz { a: 0, target: 0 },
            Instr::Jnz { a: 0, target: 0 },
            Instr::Call { target: 0 },
            Instr::Ret,
            Instr::SLoad { d: 0, a: 0 },
            Instr::SStore { a: 0, b: 0 },
            Instr::Send { a: 0, b: 0, c: 0 },
            Instr::Emit { a: 0, b: 0, c: 0 },
            Instr::Hash { a: 0, b: 0, c: 0 },
            Instr::VerifyMl { a: 0, b: 0, c: 0 },
            Instr::VerifySlh { a: 0, b: 0, c: 0 },
            Instr::MerkleVerify { a: 0, b: 0, c: 0 },
            Instr::Kem { a: 0, b: 0, c: 0 },
            Instr::Addr { a: 0, b: 0, c: 0 },
        ]
        .iter()
        .map(Instr::opcode)
        .collect()
    }

    #[test]
    fn only_halt_is_free() {
        for op in every_opcode() {
            if op == OpCode::Halt {
                assert_eq!(cost(op), 0);
            } else {
                assert!(cost(op) >= 1, "{op:?} must charge at least one gas");
            }
        }
    }
}
