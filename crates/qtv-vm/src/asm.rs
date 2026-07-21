//! Small assembler from a plain text mnemonic form to bytecode. It is enough to write test

use std::collections::HashMap;

use crate::isa::{Instr, Reg, NUM_REGS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsmError {
    UnknownMnemonic(usize, String),
    WrongOperands(usize, String),
    BadRegister(usize, String),
    BadNumber(usize, String),
    UnknownLabel(usize, String),
    DuplicateLabel(usize, String),
    ProgramTooLarge(usize),
}

/// Assemble a program into bytecode. A line ending in a colon defines a label. A line beginning
pub fn assemble(src: &str) -> Result<Vec<u8>, AsmError> {
    let lines = logical_lines(src);

    let mut labels: HashMap<String, u32> = HashMap::new();
    let mut offset: u32 = 0;
    for (no, content) in &lines {
        if let Some(name) = content.strip_suffix(':') {
            let name = name.trim().to_string();
            if labels.insert(name.clone(), offset).is_some() {
                return Err(AsmError::DuplicateLabel(*no, name));
            }
        } else {
            let instr = parse_instr(*no, content, &labels, true)?;
            let len = instr.encoded_len() as u32;
            offset = offset
                .checked_add(len)
                .ok_or(AsmError::ProgramTooLarge(*no))?;
        }
    }

    let mut code = Vec::new();
    for (no, content) in &lines {
        if content.ends_with(':') {
            continue;
        }
        let instr = parse_instr(*no, content, &labels, false)?;
        instr.encode(&mut code);
    }
    Ok(code)
}

fn logical_lines(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, raw) in src.lines().enumerate() {
        let no_comment = match raw.find('#') {
            Some(pos) => &raw[..pos],
            None => raw,
        };
        let trimmed = no_comment.trim();
        if !trimmed.is_empty() {
            out.push((i + 1, trimmed.to_string()));
        }
    }
    out
}

fn parse_instr(
    no: usize,
    content: &str,
    labels: &HashMap<String, u32>,
    allow_unknown: bool,
) -> Result<Instr, AsmError> {
    let normalized = content.replace(',', " ");
    let mut parts = normalized.split_whitespace();
    let mnemonic = parts
        .next()
        .ok_or_else(|| AsmError::UnknownMnemonic(no, content.to_string()))?
        .to_ascii_uppercase();
    let ops: Vec<&str> = parts.collect();

    let want = |n: usize| -> Result<(), AsmError> {
        if ops.len() == n {
            Ok(())
        } else {
            Err(AsmError::WrongOperands(no, content.to_string()))
        }
    };

    let instr = match mnemonic.as_str() {
        "HALT" => {
            want(0)?;
            Instr::Halt
        }
        "NOP" => {
            want(0)?;
            Instr::Nop
        }
        "RET" => {
            want(0)?;
            Instr::Ret
        }
        "MOV" => {
            want(2)?;
            Instr::Mov {
                d: reg(no, ops[0])?,
                a: reg(no, ops[1])?,
            }
        }
        "LDI" => {
            want(2)?;
            Instr::Ldi {
                d: reg(no, ops[0])?,
                imm: num_u64(no, ops[1])?,
            }
        }
        "LDC" => {
            want(2)?;
            Instr::Ldc {
                d: reg(no, ops[0])?,
                idx: num_u16(no, ops[1])?,
            }
        }
        "ADD" => {
            want(3)?;
            triple(no, &ops, Triple::Add)?
        }
        "SUB" => {
            want(3)?;
            triple(no, &ops, Triple::Sub)?
        }
        "MUL" => {
            want(3)?;
            triple(no, &ops, Triple::Mul)?
        }
        "DIV" => {
            want(3)?;
            triple(no, &ops, Triple::Div)?
        }
        "REM" => {
            want(3)?;
            triple(no, &ops, Triple::Rem)?
        }
        "ADDW" => {
            want(3)?;
            triple(no, &ops, Triple::AddW)?
        }
        "SUBW" => {
            want(3)?;
            triple(no, &ops, Triple::SubW)?
        }
        "MULW" => {
            want(3)?;
            triple(no, &ops, Triple::MulW)?
        }
        "MULHI" => {
            want(3)?;
            triple(no, &ops, Triple::MulHi)?
        }
        "AND" => {
            want(3)?;
            triple(no, &ops, Triple::And)?
        }
        "OR" => {
            want(3)?;
            triple(no, &ops, Triple::Or)?
        }
        "XOR" => {
            want(3)?;
            triple(no, &ops, Triple::Xor)?
        }
        "SHL" => {
            want(3)?;
            triple(no, &ops, Triple::Shl)?
        }
        "SHR" => {
            want(3)?;
            triple(no, &ops, Triple::Shr)?
        }
        "EQ" => {
            want(3)?;
            triple(no, &ops, Triple::Eq)?
        }
        "LTU" => {
            want(3)?;
            triple(no, &ops, Triple::LtU)?
        }
        "GTU" => {
            want(3)?;
            triple(no, &ops, Triple::GtU)?
        }
        "SEND" => {
            want(3)?;
            triple(no, &ops, Triple::Send)?
        }
        "EMIT" => {
            want(3)?;
            triple(no, &ops, Triple::Emit)?
        }
        "HASH" => {
            want(3)?;
            triple(no, &ops, Triple::Hash)?
        }
        "VERIFYML" => {
            want(3)?;
            triple(no, &ops, Triple::VerifyMl)?
        }
        "VERIFYSLH" => {
            want(3)?;
            triple(no, &ops, Triple::VerifySlh)?
        }
        "MERKLEVERIFY" => {
            want(3)?;
            triple(no, &ops, Triple::MerkleVerify)?
        }
        "VRFVERIFY" => {
            want(3)?;
            triple(no, &ops, Triple::VrfVerify)?
        }
        "KEM" => {
            want(3)?;
            triple(no, &ops, Triple::Kem)?
        }
        "ADDR" => {
            want(3)?;
            triple(no, &ops, Triple::Addr)?
        }
        "NOT" => {
            want(2)?;
            Instr::Not {
                d: reg(no, ops[0])?,
                a: reg(no, ops[1])?,
            }
        }
        "PUSH" => {
            want(1)?;
            Instr::Push {
                a: reg(no, ops[0])?,
            }
        }
        "POP" => {
            want(1)?;
            Instr::Pop {
                d: reg(no, ops[0])?,
            }
        }
        "MLOAD" => {
            want(2)?;
            Instr::MLoad {
                d: reg(no, ops[0])?,
                a: reg(no, ops[1])?,
            }
        }
        "MSTORE" => {
            want(2)?;
            Instr::MStore {
                a: reg(no, ops[0])?,
                b: reg(no, ops[1])?,
            }
        }
        "SLOAD" => {
            want(2)?;
            Instr::SLoad {
                d: reg(no, ops[0])?,
                a: reg(no, ops[1])?,
            }
        }
        "SSTORE" => {
            want(2)?;
            Instr::SStore {
                a: reg(no, ops[0])?,
                b: reg(no, ops[1])?,
            }
        }
        "JMP" => {
            want(1)?;
            Instr::Jmp {
                target: target(no, ops[0], labels, allow_unknown)?,
            }
        }
        "CALL" => {
            want(1)?;
            Instr::Call {
                target: target(no, ops[0], labels, allow_unknown)?,
            }
        }
        "JZ" => {
            want(2)?;
            Instr::Jz {
                a: reg(no, ops[0])?,
                target: target(no, ops[1], labels, allow_unknown)?,
            }
        }
        "JNZ" => {
            want(2)?;
            Instr::Jnz {
                a: reg(no, ops[0])?,
                target: target(no, ops[1], labels, allow_unknown)?,
            }
        }
        _ => return Err(AsmError::UnknownMnemonic(no, mnemonic)),
    };
    Ok(instr)
}

enum Triple {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    AddW,
    SubW,
    MulW,
    MulHi,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    LtU,
    GtU,
    Send,
    Emit,
    Hash,
    VerifyMl,
    VerifySlh,
    MerkleVerify,
    VrfVerify,
    Kem,
    Addr,
}

fn triple(no: usize, ops: &[&str], kind: Triple) -> Result<Instr, AsmError> {
    let d = reg(no, ops[0])?;
    let a = reg(no, ops[1])?;
    let b = reg(no, ops[2])?;
    let instr = match kind {
        Triple::Add => Instr::Add { d, a, b },
        Triple::Sub => Instr::Sub { d, a, b },
        Triple::Mul => Instr::Mul { d, a, b },
        Triple::Div => Instr::Div { d, a, b },
        Triple::Rem => Instr::Rem { d, a, b },
        Triple::AddW => Instr::AddW { d, a, b },
        Triple::SubW => Instr::SubW { d, a, b },
        Triple::MulW => Instr::MulW { d, a, b },
        Triple::MulHi => Instr::MulHi { d, a, b },
        Triple::And => Instr::And { d, a, b },
        Triple::Or => Instr::Or { d, a, b },
        Triple::Xor => Instr::Xor { d, a, b },
        Triple::Shl => Instr::Shl { d, a, b },
        Triple::Shr => Instr::Shr { d, a, b },
        Triple::Eq => Instr::Eq { d, a, b },
        Triple::LtU => Instr::LtU { d, a, b },
        Triple::GtU => Instr::GtU { d, a, b },
        Triple::Send => Instr::Send { a: d, b: a, c: b },
        Triple::Emit => Instr::Emit { a: d, b: a, c: b },
        Triple::Hash => Instr::Hash { a: d, b: a, c: b },
        Triple::VerifyMl => Instr::VerifyMl { a: d, b: a, c: b },
        Triple::VerifySlh => Instr::VerifySlh { a: d, b: a, c: b },
        Triple::MerkleVerify => Instr::MerkleVerify { a: d, b: a, c: b },
        Triple::VrfVerify => Instr::VrfVerify { a: d, b: a, c: b },
        Triple::Kem => Instr::Kem { a: d, b: a, c: b },
        Triple::Addr => Instr::Addr { a: d, b: a, c: b },
    };
    Ok(instr)
}

fn reg(no: usize, tok: &str) -> Result<Reg, AsmError> {
    let rest = tok
        .strip_prefix('r')
        .or_else(|| tok.strip_prefix('R'))
        .ok_or_else(|| AsmError::BadRegister(no, tok.to_string()))?;
    let idx: usize = rest
        .parse()
        .map_err(|_| AsmError::BadRegister(no, tok.to_string()))?;
    if idx >= NUM_REGS {
        return Err(AsmError::BadRegister(no, tok.to_string()));
    }
    Ok(idx as Reg)
}

fn num_u64(no: usize, tok: &str) -> Result<u64, AsmError> {
    tok.parse::<u64>()
        .map_err(|_| AsmError::BadNumber(no, tok.to_string()))
}

fn num_u16(no: usize, tok: &str) -> Result<u16, AsmError> {
    u16::try_from(num_u64(no, tok)?).map_err(|_| AsmError::BadNumber(no, tok.to_string()))
}

fn target(
    no: usize,
    tok: &str,
    labels: &HashMap<String, u32>,
    allow_unknown: bool,
) -> Result<u32, AsmError> {
    let first = tok
        .chars()
        .next()
        .ok_or_else(|| AsmError::BadNumber(no, tok.to_string()))?;
    if first.is_ascii_digit() {
        u32::try_from(num_u64(no, tok)?).map_err(|_| AsmError::BadNumber(no, tok.to_string()))
    } else if let Some(&off) = labels.get(tok) {
        Ok(off)
    } else if allow_unknown {
        Ok(0)
    } else {
        Err(AsmError::UnknownLabel(no, tok.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::Interpreter;

    #[test]
    fn assembles_and_computes() {
        let code = assemble(
            "
            LDI r0, 5
            LDI r1, 7
            ADD r2, r0, r1
            HALT
            ",
        )
        .expect("assemble");
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 12);
    }

    #[test]
    fn hex_immediate() {
        let code = assemble("LDI r0, 255\nHALT").expect("assemble");
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[0], 255);
    }

    #[test]
    fn labels_resolve_for_loops() {
        let code = assemble(
            "
            LDI r0, 3    # counter
            LDI r1, 0    # accumulator
            LDI r2, 1
            loop:
            SUBW r0, r0, r2
            ADDW r1, r1, r2
            JNZ r0, loop
            HALT
            ",
        )
        .expect("assemble");
        let out = Interpreter::new(&code, &[], 1000).run().expect("halt");
        assert_eq!(out.regs[1], 3);
    }

    #[test]
    fn unknown_mnemonic_errors() {
        assert_eq!(
            assemble("FOO r0"),
            Err(AsmError::UnknownMnemonic(1, "FOO".to_string()))
        );
    }

    #[test]
    fn bad_register_errors() {
        assert_eq!(
            assemble("LDI r99, 1\nHALT"),
            Err(AsmError::BadRegister(1, "r99".to_string()))
        );
    }

    #[test]
    fn unknown_label_errors() {
        assert_eq!(
            assemble("JMP nowhere\nHALT"),
            Err(AsmError::UnknownLabel(1, "nowhere".to_string()))
        );
    }
}
