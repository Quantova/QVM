// Independent deterministic random-program fuzz (bug-bounty research, not upstream).
// Generates 1000 programs from a small PRNG; requires no panic and identical
// outcomes across two runs (consensus determinism). Feature: unchecked-programs.
use qtv_vm::interp::{Fault, Interpreter, Outcome};
use qtv_vm::isa::Instr;

fn prng(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || { s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); s >> 33 }
}

fn program_from(r: &mut impl FnMut() -> u64) -> Vec<Instr> {
    let mut v = Vec::new();
    let n = (r() % 12) as usize + 1;
    for _ in 0..n {
        let op = r() % 14;
        let a = (r() % 16) as u8;
        let b = (r() % 16) as u8;
        let c = (r() % 16) as u8;
        let imm = r();
        v.push(match op {
            0 => Instr::Ldi{d:a, imm},
            1 => Instr::Mov{d:a, a:b},
            2 => Instr::Add{d:a, a:b, b:c},
            3 => Instr::Mul{d:a, a:b, b:c},
            4 => Instr::Div{d:a, a:b, b:c},
            5 => Instr::MStore{a, b},
            6 => Instr::MLoad{d:a, a},
            7 => Instr::Hash{a, b, c},
            8 => Instr::VerifyMl{a, b, c},
            9 => Instr::MerkleVerify{a, b, c},
            10 => Instr::SLoad{d:a, a},
            11 => Instr::SStore{a, b},
            12 => Instr::Emit{a, b, c},
            _ => Instr::Nop,
        });
    }
    v.push(Instr::Halt);
    v
}

#[test]
fn thousand_random_programs_are_panic_free_and_deterministic() {
    for seed in 0u64..1000 {
        let mut r = prng(seed + 1);
        let instrs = program_from(&mut r);
        let mut code = Vec::new();
        for i in &instrs { i.encode(&mut code); }
        let run = || Interpreter::for_unchecked_program(&code, &[], 5_000_000).run();
        let a: Result<Outcome, Fault> = run();
        let b: Result<Outcome, Fault> = run();
        assert_eq!(a, b, "nondeterministic program at seed {seed}: {instrs:?}");
    }
}
