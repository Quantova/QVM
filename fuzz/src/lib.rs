// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::panic::catch_unwind;

use qtv_vm::interp::Interpreter;
use qtv_vm::isa::{decode, Instr, NUM_REGS};

pub const METER_BOUND: u64 = 100_000;

pub const CRYPTO_METER_BOUND: u64 = 50_000_000;

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Rng { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(11400714819323198485);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(13787848793156543929);
        z = (z ^ (z >> 27)).wrapping_mul(10723151780598845931);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

fn rand_reg(rng: &mut Rng) -> u8 {
    (rng.below(NUM_REGS as u64)) as u8
}

fn rand_bytes(rng: &mut Rng, max: usize) -> Vec<u8> {
    let len = rng.below((max + 1) as u64) as usize;
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

fn rand_consts(rng: &mut Rng) -> Vec<u64> {
    let len = rng.below(8) as usize;
    (0..len).map(|_| rng.next_u64()).collect()
}

fn rand_instr(rng: &mut Rng) -> Instr {
    let d = rand_reg(rng);
    let a = rand_reg(rng);
    let b = rand_reg(rng);
    let c = rand_reg(rng);
    let target = rng.below(64) as u32;
    match rng.below(44) {
        0 => Instr::Ldi {
            d,
            imm: rng.next_u64(),
        },
        1 => Instr::Mov { d, a },
        2 => Instr::Add { d, a, b },
        3 => Instr::Sub { d, a, b },
        4 => Instr::Mul { d, a, b },
        5 => Instr::Div { d, a, b },
        6 => Instr::AddW { d, a, b },
        7 => Instr::And { d, a, b },
        8 => Instr::Xor { d, a, b },
        9 => Instr::Shl { d, a, b },
        10 => Instr::Eq { d, a, b },
        11 => Instr::Push { a },
        12 => Instr::Pop { d },
        13 => Instr::MStore { a, b },
        14 => Instr::SStore { a, b },
        15 => Instr::SLoad { d, a },
        16 => Instr::Jz { a, target },
        17 => Instr::Jnz { a, target },
        18 => Instr::Ldc {
            d,
            idx: rng.below(10) as u16,
        },
        19 => Instr::Rem { d, a, b },
        20 => Instr::SubW { d, a, b },
        21 => Instr::MulW { d, a, b },
        22 => Instr::MulHi { d, a, b },
        23 => Instr::DivW {
            dlo: d,
            dhi: a,
            alo: b,
            ahi: c,
            blo: rand_reg(rng),
            bhi: rand_reg(rng),
        },
        24 => Instr::RemW {
            dlo: d,
            dhi: a,
            alo: b,
            ahi: c,
            blo: rand_reg(rng),
            bhi: rand_reg(rng),
        },
        25 => Instr::Or { d, a, b },
        26 => Instr::Not { d, a },
        27 => Instr::Shr { d, a, b },
        28 => Instr::LtU { d, a, b },
        29 => Instr::GtU { d, a, b },
        30 => Instr::MLoad { d, a },
        31 => Instr::Jmp { target },
        32 => Instr::Call { target },
        33 => Instr::Ret,
        34 => Instr::Send { a, b, c },
        35 => Instr::Emit { a, b, c },
        36 => Instr::Hash { a, b, c },
        37 => Instr::VerifyMl { a, b, c },
        38 => Instr::VerifySlh { a, b, c },
        39 => Instr::MerkleVerify { a, b, c },
        40 => Instr::Addr { a, b, c },
        41 => Instr::Nop,
        _ => Instr::Halt,
    }
}

fn loaded_value(key: &qtv_vm::interp::StorageKey) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&key[..8]);
    u64::from_le_bytes(head).rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15
}

fn rand_program(rng: &mut Rng) -> Vec<u8> {
    let count = rng.below(48) as usize;
    let mut code = Vec::new();
    for _ in 0..count {
        rand_instr(rng).encode(&mut code);
    }
    Instr::Halt.encode(&mut code);
    code
}

fn decode_sweep(code: &[u8]) {
    let mut pc = 0usize;
    while pc < code.len() {
        match decode(code, pc) {
            Ok((_, len)) => pc += len,
            Err(_) => break,
        }
    }
}

fn exercise(code: &[u8], consts: &[u64]) {
    decode_sweep(code);
    let loader = loaded_value;
    let first = Interpreter::for_unchecked_program(code, consts, METER_BOUND)
        .with_storage_loader(&loader)
        .run();
    let second = Interpreter::for_unchecked_program(code, consts, METER_BOUND)
        .with_storage_loader(&loader)
        .run();
    assert_eq!(first, second, "the interpreter is not deterministic");
    if let Ok(outcome) = first {
        assert!(outcome.meter_used <= METER_BOUND);
    }
}

pub fn run_batch(seed: u64, count: usize) {
    let mut rng = Rng::new(seed ^ 11936128518282651045);
    for i in 0..count {
        let consts = rand_consts(&mut rng);
        let code = if i % 2 == 0 {
            rand_bytes(&mut rng, 256)
        } else {
            rand_program(&mut rng)
        };
        let result = catch_unwind(|| exercise(&code, &consts));
        assert!(result.is_ok(), "panicked on seed {seed} at case {i}");
    }
}

fn rand_crypto_case(rng: &mut Rng) -> (Vec<u8>, Vec<u8>) {
    let mem: Vec<u8> = (0..qtv_vm::state::MEM_BYTES)
        .map(|_| rng.next_u64() as u8)
        .collect();
    let len = rng.below((qtv_vm::state::MEM_BYTES + 1) as u64);
    let out = rng.below((qtv_vm::state::MEM_BYTES + 1) as u64);
    let crypto = match rng.below(4) {
        0 => Instr::Hash { a: 0, b: 1, c: 2 },
        1 => Instr::VerifyMl { a: 0, b: 1, c: 2 },
        2 => Instr::VerifySlh { a: 0, b: 1, c: 2 },
        _ => Instr::MerkleVerify { a: 0, b: 1, c: 2 },
    };
    let mut code = Vec::new();
    Instr::Ldi { d: 0, imm: 0 }.encode(&mut code);
    Instr::Ldi { d: 1, imm: len }.encode(&mut code);
    Instr::Ldi { d: 2, imm: out }.encode(&mut code);
    crypto.encode(&mut code);
    Instr::Halt.encode(&mut code);
    (code, mem)
}

fn exercise_crypto(code: &[u8], mem: &[u8]) {
    let first = Interpreter::for_unchecked_program(code, &[], CRYPTO_METER_BOUND)
        .with_memory(mem)
        .run();
    let second = Interpreter::for_unchecked_program(code, &[], CRYPTO_METER_BOUND)
        .with_memory(mem)
        .run();
    assert_eq!(first, second, "the interpreter is not deterministic");
}

pub fn run_crypto_batch(seed: u64, count: usize) {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut rng = Rng::new(seed ^ 2870177450012600261);
    let mut escaped = Vec::new();
    for i in 0..count {
        let (code, mem) = rand_crypto_case(&mut rng);
        if catch_unwind(|| exercise_crypto(&code, &mem)).is_err() {
            escaped.push(i);
        }
    }
    std::panic::set_hook(hook);
    assert!(
        escaped.is_empty(),
        "interpreter unwound on crypto cases {escaped:?} for seed {seed}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_never_panics() {
        run_batch(72623859790382856, 5000);
    }

    #[test]
    fn batch_is_deterministic_across_seeds() {
        run_batch(1, 500);
        run_batch(2, 500);
        run_batch(u64::MAX, 500);
    }

    #[test]
    fn crypto_batch_never_panics() {
        run_crypto_batch(1311768467463790320, 256);
    }
}
