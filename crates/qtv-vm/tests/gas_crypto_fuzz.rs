// Independent gas/crypto extreme-input probe (bug-bounty research, not upstream).
// Requires feature unchecked-programs. Tests that extreme register values never
// panic and produce deterministic outcomes (same code -> same meter/effects).
use qtv_vm::interp::{Fault, Interpreter};
use qtv_vm::isa::Instr;

fn prog(instrs: &[Instr]) -> Vec<u8> {
    let mut out = Vec::new();
    for i in instrs { i.encode(&mut out); }
    out
}

fn run_twice(code: &[u8], limit: u64) -> (Result<qtv_vm::interp::Outcome, Fault>, Result<qtv_vm::interp::Outcome, Fault>) {
    let a = Interpreter::for_unchecked_program(code, &[], limit).run();
    let b = Interpreter::for_unchecked_program(code, &[], limit).run();
    (a, b)
}

#[test]
fn extreme_len_and_ptr_do_not_panic_and_are_deterministic() {
    // Hash with u64::MAX len/ptr, Verify with u64::MAX, Merkle with u64::MAX,
    // Addr with extreme scheme, Send/Emit with extreme offsets.
    let cases: Vec<Vec<Instr>> = vec![
        vec![Instr::Ldi{d:0,imm:u64::MAX}, Instr::Ldi{d:1,imm:u64::MAX}, Instr::Ldi{d:2,imm:0}, Instr::Hash{a:0,b:1,c:2}, Instr::Halt],
        vec![Instr::Ldi{d:0,imm:u64::MAX}, Instr::Ldi{d:1,imm:u64::MAX}, Instr::Ldi{d:2,imm:0}, Instr::VerifyMl{a:0,b:1,c:2}, Instr::Halt],
        vec![Instr::Ldi{d:0,imm:u64::MAX}, Instr::Ldi{d:1,imm:u64::MAX}, Instr::Ldi{d:2,imm:0}, Instr::VerifySlh{a:0,b:1,c:2}, Instr::Halt],
        vec![Instr::Ldi{d:0,imm:u64::MAX}, Instr::Ldi{d:1,imm:u64::MAX}, Instr::Ldi{d:2,imm:0}, Instr::MerkleVerify{a:0,b:1,c:2}, Instr::Halt],
        vec![Instr::Ldi{d:0,imm:u64::MAX}, Instr::Ldi{d:1,imm:u64::MAX}, Instr::Ldi{d:2,imm:u64::MAX}, Instr::Addr{a:0,b:1,c:2}, Instr::Halt],
        vec![Instr::Ldi{d:0,imm:u64::MAX}, Instr::Ldi{d:1,imm:u64::MAX}, Instr::Ldi{d:2,imm:u64::MAX}, Instr::Send{a:0,b:1,c:2}, Instr::Halt],
        vec![Instr::Ldi{d:0,imm:u64::MAX}, Instr::Ldi{d:1,imm:u64::MAX}, Instr::Ldi{d:2,imm:u64::MAX}, Instr::Emit{a:0,b:1,c:2}, Instr::Halt],
    ];
    for c in cases {
        let code = prog(&c);
        let (a, b) = run_twice(&code, 50_000_000);
        // Outcome derives PartialEq; both runs must agree.
        assert_eq!(a, b, "nondeterministic outcome for {:?}", c[3].opcode());
    }
}
