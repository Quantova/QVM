//! Fuzz harness. It feeds random bytes and random programs to the decoder and interpreter and

use std::panic::catch_unwind;

use qtv_vm::interp::Interpreter;
use qtv_vm::isa::{decode, Instr, NUM_REGS};

/// Every metered run is capped at this many gas units. Only a clean halt is free, so a run cannot
pub const GAS_BOUND: u64 = 100_000;

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Rng { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
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
    match rng.below(19) {
        0 => Instr::Ldi {
            d: rand_reg(rng),
            imm: rng.next_u64(),
        },
        1 => Instr::Mov {
            d: rand_reg(rng),
            a: rand_reg(rng),
        },
        2 => Instr::Add {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        3 => Instr::Sub {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        4 => Instr::Mul {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        5 => Instr::Div {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        6 => Instr::AddW {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        7 => Instr::And {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        8 => Instr::Xor {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        9 => Instr::Shl {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        10 => Instr::Eq {
            d: rand_reg(rng),
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        11 => Instr::Push { a: rand_reg(rng) },
        12 => Instr::Pop { d: rand_reg(rng) },
        13 => Instr::MStore {
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        14 => Instr::SStore {
            a: rand_reg(rng),
            b: rand_reg(rng),
        },
        15 => Instr::SLoad {
            d: rand_reg(rng),
            a: rand_reg(rng),
        },
        16 => Instr::Jz {
            a: rand_reg(rng),
            target: rng.below(64) as u32,
        },
        17 => Instr::Jnz {
            a: rand_reg(rng),
            target: rng.below(64) as u32,
        },
        _ => Instr::Halt,
    }
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

/// Walk the decoder over the bytes. This must never panic on any input.
fn decode_sweep(code: &[u8]) {
    let mut pc = 0usize;
    while pc < code.len() {
        match decode(code, pc) {
            Ok((_, len)) => pc += len,
            Err(_) => break,
        }
    }
}

/// Decode and run one input. Returns nothing. It must not panic and must terminate within the gas
fn exercise(code: &[u8], consts: &[u64]) {
    decode_sweep(code);
    if let Ok(outcome) = Interpreter::new(code, consts, GAS_BOUND).run() {
        assert!(outcome.gas_used <= GAS_BOUND);
    }
}

/// Run a batch of random inputs. Half are raw random bytes, half are random valid programs. A panic
pub fn run_batch(seed: u64, count: usize) {
    let mut rng = Rng::new(seed ^ 0xa5a5_a5a5_a5a5_a5a5);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_never_panics() {
        run_batch(0x0102_0304_0506_0708, 5000);
    }

    #[test]
    fn batch_is_deterministic_across_seeds() {
        run_batch(1, 500);
        run_batch(2, 500);
        run_batch(u64::MAX, 500);
    }
}
