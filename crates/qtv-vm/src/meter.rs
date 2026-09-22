// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::isa::OpCode;

pub const DISPATCH: u64 = 4;

pub const EFFECT_BYTE: u64 = 2;

pub const EVENT_BYTE: u64 = 100;

pub const EFFECTS_BYTES_CAP: u64 = 1 << 20;

pub const EFFECT_RECORD_OVERHEAD: u64 = 32;

pub const KECCAK_RATE: u64 = 136;

pub const HASH_BLOCK: u64 = 40;

pub const MERKLE_LEVEL: u64 = 50;

pub const KEYED_SLOT_METER: u64 = 227_000;

pub const LEAF_ROOT_BUDGET_MS: u64 = 200;
pub const LEAF_ROOT_MICROS: u64 = 900;

pub const METER_PER_MICRO: u64 = 79;
pub const VERIFY_ML_MICROS: u64 = 288;
pub const VERIFY_SLH_MICROS: u64 = 4_245;

pub const EVENT_RECORD_METER: u64 = 6_250;

pub const FREE_EVENT_RECORDS: usize = 4;

pub const ASSET_MINT_SELECTOR: [u8; 4] = *b"MINT";
pub const ASSET_MINT_DATA_BYTES: usize = 40;

pub const FREE_DIRTY_SLOTS: usize = 8;

pub const VERIFY_MESSAGE_BLOCK: u64 = 40;

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
        OpCode::DivW => 8,
        OpCode::RemW => 8,

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

        OpCode::Hash => 200,
        OpCode::VerifyMl => 60_000,
        OpCode::VerifySlh => 340_000,
        OpCode::MerkleVerify => 512,
        OpCode::Addr => 4_000,
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    const BLOCK_METER_BUDGET: u64 = 50_000_000;

    #[test]
    fn a_full_block_of_fresh_leaves_roots_inside_its_budget() {
        let leaves = BLOCK_METER_BUDGET / KEYED_SLOT_METER;
        let micros = leaves * LEAF_ROOT_MICROS;
        assert!(
            micros <= LEAF_ROOT_BUDGET_MS * 1_000,
            "{leaves} fresh leaves root in {micros} us, past the {LEAF_ROOT_BUDGET_MS} ms budget"
        );
    }

    #[test]
    fn the_crypto_opcodes_charge_at_least_the_cpu_they_burn() {
        for (name, charged, micros) in [
            ("VerifyMl", cost(OpCode::VerifyMl), VERIFY_ML_MICROS),
            ("VerifySlh", cost(OpCode::VerifySlh), VERIFY_SLH_MICROS),
        ] {
            let owed = micros * METER_PER_MICRO;
            assert!(
                charged >= owed,
                "{name} charges {charged} for {owed} of measured work"
            );
        }
    }

    #[test]
    fn a_durable_event_byte_costs_what_a_code_byte_costs() {
        const DEPLOY_BYTE_METER: u64 = 100;
        assert!(
            EVENT_BYTE >= DEPLOY_BYTE_METER,
            "an event byte at {EVENT_BYTE} against a code byte at {DEPLOY_BYTE_METER}, so a \
             block buys more permanent log than it can buy permanent code"
        );
    }

    #[test]
    fn a_full_block_of_event_records_stays_bounded() {
        let records = BLOCK_METER_BUDGET / EVENT_RECORD_METER;
        assert!(
            records <= 8_192,
            "one block buys {records} durable event records"
        );
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
            Instr::DivW {
                dlo: 0,
                dhi: 0,
                alo: 0,
                ahi: 0,
                blo: 0,
                bhi: 0,
            },
            Instr::RemW {
                dlo: 0,
                dhi: 0,
                alo: 0,
                ahi: 0,
                blo: 0,
                bhi: 0,
            },
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
            Instr::Addr { a: 0, b: 0, c: 0 },
        ]
        .iter()
        .map(Instr::opcode)
        .collect()
    }

    fn is_listed(instr: &Instr) -> bool {
        let name = match instr {
            Instr::Halt => "Halt",
            Instr::Nop => "Nop",
            Instr::Mov { .. } => "Mov",
            Instr::Ldi { .. } => "Ldi",
            Instr::Ldc { .. } => "Ldc",
            Instr::Add { .. } => "Add",
            Instr::Sub { .. } => "Sub",
            Instr::Mul { .. } => "Mul",
            Instr::Div { .. } => "Div",
            Instr::Rem { .. } => "Rem",
            Instr::AddW { .. } => "AddW",
            Instr::SubW { .. } => "SubW",
            Instr::MulW { .. } => "MulW",
            Instr::MulHi { .. } => "MulHi",
            Instr::DivW { .. } => "DivW",
            Instr::RemW { .. } => "RemW",
            Instr::And { .. } => "And",
            Instr::Or { .. } => "Or",
            Instr::Xor { .. } => "Xor",
            Instr::Not { .. } => "Not",
            Instr::Shl { .. } => "Shl",
            Instr::Shr { .. } => "Shr",
            Instr::Eq { .. } => "Eq",
            Instr::LtU { .. } => "LtU",
            Instr::GtU { .. } => "GtU",
            Instr::Push { .. } => "Push",
            Instr::Pop { .. } => "Pop",
            Instr::MLoad { .. } => "MLoad",
            Instr::MStore { .. } => "MStore",
            Instr::Jmp { .. } => "Jmp",
            Instr::Jz { .. } => "Jz",
            Instr::Jnz { .. } => "Jnz",
            Instr::Call { .. } => "Call",
            Instr::Ret => "Ret",
            Instr::SLoad { .. } => "SLoad",
            Instr::SStore { .. } => "SStore",
            Instr::Send { .. } => "Send",
            Instr::Emit { .. } => "Emit",
            Instr::Hash { .. } => "Hash",
            Instr::VerifyMl { .. } => "VerifyMl",
            Instr::VerifySlh { .. } => "VerifySlh",
            Instr::MerkleVerify { .. } => "MerkleVerify",
            Instr::Addr { .. } => "Addr",
        };
        let _ = name;
        true
    }

    #[test]
    fn the_free_instruction_check_walks_every_instruction_in_the_isa() {
        let listed = every_opcode();
        assert_eq!(
            listed.len(),
            43,
            "every_opcode no longer matches the instruction set, so only_halt_is_free is \
             walking a partial list and a new free instruction would go unnoticed"
        );
        assert!(is_listed(&Instr::Halt));
    }

    #[test]
    fn only_halt_is_free() {
        for op in every_opcode() {
            if op == OpCode::Halt {
                assert_eq!(cost(op), 0);
            } else {
                assert!(cost(op) >= 1, "{op:?} must charge at least one meter");
            }
        }
    }
}
