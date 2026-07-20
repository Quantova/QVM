//! Instruction set. Opcodes have a fixed byte encoding over 64 bit words.

/// Number of general registers. A register operand outside this range is a decode fault.
pub const NUM_REGS: usize = 16;

/// A register index. Valid values are `0..NUM_REGS`.
pub type Reg = u8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Halt = 0,
    Nop = 1,
    Mov = 2,
    Ldi = 3,
    Ldc = 4,

    Add = 16,
    Sub = 17,
    Mul = 18,
    Div = 19,
    Rem = 20,
    AddW = 24,
    SubW = 25,
    MulW = 26,
    MulHi = 27,

    And = 32,
    Or = 33,
    Xor = 34,
    Not = 35,
    Shl = 36,
    Shr = 37,
    Eq = 40,
    LtU = 41,
    GtU = 42,

    Push = 48,
    Pop = 49,
    MLoad = 56,
    MStore = 57,

    Jmp = 64,
    Jz = 65,
    Jnz = 66,
    Call = 67,
    Ret = 68,

    SLoad = 80,
    SStore = 81,

    Send = 96,
    Emit = 97,

    Hash = 112,
    VerifyMl = 113,
    VerifySlh = 114,
    MerkleVerify = 115,
    VrfVerify = 116,
    Kem = 117,
}

impl OpCode {
    pub fn from_byte(b: u8) -> Option<OpCode> {
        let op = match b {
            0 => OpCode::Halt,
            1 => OpCode::Nop,
            2 => OpCode::Mov,
            3 => OpCode::Ldi,
            4 => OpCode::Ldc,
            16 => OpCode::Add,
            17 => OpCode::Sub,
            18 => OpCode::Mul,
            19 => OpCode::Div,
            20 => OpCode::Rem,
            24 => OpCode::AddW,
            25 => OpCode::SubW,
            26 => OpCode::MulW,
            27 => OpCode::MulHi,
            32 => OpCode::And,
            33 => OpCode::Or,
            34 => OpCode::Xor,
            35 => OpCode::Not,
            36 => OpCode::Shl,
            37 => OpCode::Shr,
            40 => OpCode::Eq,
            41 => OpCode::LtU,
            42 => OpCode::GtU,
            48 => OpCode::Push,
            49 => OpCode::Pop,
            56 => OpCode::MLoad,
            57 => OpCode::MStore,
            64 => OpCode::Jmp,
            65 => OpCode::Jz,
            66 => OpCode::Jnz,
            67 => OpCode::Call,
            68 => OpCode::Ret,
            80 => OpCode::SLoad,
            81 => OpCode::SStore,
            96 => OpCode::Send,
            97 => OpCode::Emit,
            112 => OpCode::Hash,
            113 => OpCode::VerifyMl,
            114 => OpCode::VerifySlh,
            115 => OpCode::MerkleVerify,
            116 => OpCode::VrfVerify,
            117 => OpCode::Kem,
            _ => return None,
        };
        Some(op)
    }
}

/// A decoded instruction with its operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instr {
    Halt,
    Nop,
    Mov { d: Reg, a: Reg },
    Ldi { d: Reg, imm: u64 },
    Ldc { d: Reg, idx: u16 },

    Add { d: Reg, a: Reg, b: Reg },
    Sub { d: Reg, a: Reg, b: Reg },
    Mul { d: Reg, a: Reg, b: Reg },
    Div { d: Reg, a: Reg, b: Reg },
    Rem { d: Reg, a: Reg, b: Reg },
    AddW { d: Reg, a: Reg, b: Reg },
    SubW { d: Reg, a: Reg, b: Reg },
    MulW { d: Reg, a: Reg, b: Reg },
    MulHi { d: Reg, a: Reg, b: Reg },

    And { d: Reg, a: Reg, b: Reg },
    Or { d: Reg, a: Reg, b: Reg },
    Xor { d: Reg, a: Reg, b: Reg },
    Not { d: Reg, a: Reg },
    Shl { d: Reg, a: Reg, b: Reg },
    Shr { d: Reg, a: Reg, b: Reg },
    Eq { d: Reg, a: Reg, b: Reg },
    LtU { d: Reg, a: Reg, b: Reg },
    GtU { d: Reg, a: Reg, b: Reg },

    Push { a: Reg },
    Pop { d: Reg },
    MLoad { d: Reg, a: Reg },
    MStore { a: Reg, b: Reg },

    Jmp { target: u32 },
    Jz { a: Reg, target: u32 },
    Jnz { a: Reg, target: u32 },
    Call { target: u32 },
    Ret,

    SLoad { d: Reg, a: Reg },
    SStore { a: Reg, b: Reg },

    Send { a: Reg, b: Reg, c: Reg },
    Emit { a: Reg, b: Reg, c: Reg },

    Hash { a: Reg, b: Reg, c: Reg },
    VerifyMl { a: Reg, b: Reg, c: Reg },
    VerifySlh { a: Reg, b: Reg, c: Reg },
    MerkleVerify { a: Reg, b: Reg, c: Reg },
    VrfVerify { a: Reg, b: Reg, c: Reg },
    Kem { a: Reg, b: Reg, c: Reg },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    UnknownOpcode(u8),
    BadRegister(u8),
    Truncated,
}

impl Instr {
    pub fn opcode(&self) -> OpCode {
        match self {
            Instr::Halt => OpCode::Halt,
            Instr::Nop => OpCode::Nop,
            Instr::Mov { .. } => OpCode::Mov,
            Instr::Ldi { .. } => OpCode::Ldi,
            Instr::Ldc { .. } => OpCode::Ldc,
            Instr::Add { .. } => OpCode::Add,
            Instr::Sub { .. } => OpCode::Sub,
            Instr::Mul { .. } => OpCode::Mul,
            Instr::Div { .. } => OpCode::Div,
            Instr::Rem { .. } => OpCode::Rem,
            Instr::AddW { .. } => OpCode::AddW,
            Instr::SubW { .. } => OpCode::SubW,
            Instr::MulW { .. } => OpCode::MulW,
            Instr::MulHi { .. } => OpCode::MulHi,
            Instr::And { .. } => OpCode::And,
            Instr::Or { .. } => OpCode::Or,
            Instr::Xor { .. } => OpCode::Xor,
            Instr::Not { .. } => OpCode::Not,
            Instr::Shl { .. } => OpCode::Shl,
            Instr::Shr { .. } => OpCode::Shr,
            Instr::Eq { .. } => OpCode::Eq,
            Instr::LtU { .. } => OpCode::LtU,
            Instr::GtU { .. } => OpCode::GtU,
            Instr::Push { .. } => OpCode::Push,
            Instr::Pop { .. } => OpCode::Pop,
            Instr::MLoad { .. } => OpCode::MLoad,
            Instr::MStore { .. } => OpCode::MStore,
            Instr::Jmp { .. } => OpCode::Jmp,
            Instr::Jz { .. } => OpCode::Jz,
            Instr::Jnz { .. } => OpCode::Jnz,
            Instr::Call { .. } => OpCode::Call,
            Instr::Ret => OpCode::Ret,
            Instr::SLoad { .. } => OpCode::SLoad,
            Instr::SStore { .. } => OpCode::SStore,
            Instr::Send { .. } => OpCode::Send,
            Instr::Emit { .. } => OpCode::Emit,
            Instr::Hash { .. } => OpCode::Hash,
            Instr::VerifyMl { .. } => OpCode::VerifyMl,
            Instr::VerifySlh { .. } => OpCode::VerifySlh,
            Instr::MerkleVerify { .. } => OpCode::MerkleVerify,
            Instr::VrfVerify { .. } => OpCode::VrfVerify,
            Instr::Kem { .. } => OpCode::Kem,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.opcode() as u8);
        match *self {
            Instr::Halt | Instr::Nop | Instr::Ret => {}
            Instr::Mov { d, a }
            | Instr::Not { d, a }
            | Instr::MLoad { d, a }
            | Instr::SLoad { d, a } => {
                out.push(d);
                out.push(a);
            }
            Instr::MStore { a, b } | Instr::SStore { a, b } => {
                out.push(a);
                out.push(b);
            }
            Instr::Ldi { d, imm } => {
                out.push(d);
                out.extend_from_slice(&imm.to_be_bytes());
            }
            Instr::Ldc { d, idx } => {
                out.push(d);
                out.extend_from_slice(&idx.to_be_bytes());
            }
            Instr::Add { d, a, b }
            | Instr::Sub { d, a, b }
            | Instr::Mul { d, a, b }
            | Instr::Div { d, a, b }
            | Instr::Rem { d, a, b }
            | Instr::AddW { d, a, b }
            | Instr::SubW { d, a, b }
            | Instr::MulW { d, a, b }
            | Instr::MulHi { d, a, b }
            | Instr::And { d, a, b }
            | Instr::Or { d, a, b }
            | Instr::Xor { d, a, b }
            | Instr::Shl { d, a, b }
            | Instr::Shr { d, a, b }
            | Instr::Eq { d, a, b }
            | Instr::LtU { d, a, b }
            | Instr::GtU { d, a, b } => {
                out.push(d);
                out.push(a);
                out.push(b);
            }
            Instr::Push { a } => out.push(a),
            Instr::Pop { d } => out.push(d),
            Instr::Jmp { target } | Instr::Call { target } => {
                out.extend_from_slice(&target.to_be_bytes());
            }
            Instr::Jz { a, target } | Instr::Jnz { a, target } => {
                out.push(a);
                out.extend_from_slice(&target.to_be_bytes());
            }
            Instr::Send { a, b, c }
            | Instr::Emit { a, b, c }
            | Instr::Hash { a, b, c }
            | Instr::VerifyMl { a, b, c }
            | Instr::VerifySlh { a, b, c }
            | Instr::MerkleVerify { a, b, c }
            | Instr::VrfVerify { a, b, c }
            | Instr::Kem { a, b, c } => {
                out.push(a);
                out.push(b);
                out.push(c);
            }
        }
    }

    pub fn encoded_len(&self) -> usize {
        let mut v = Vec::new();
        self.encode(&mut v);
        v.len()
    }
}

/// Decode one instruction at `pc`. Returns the instruction and the number of bytes consumed.
pub fn decode(code: &[u8], pc: usize) -> Result<(Instr, usize), DecodeError> {
    let mut c = Cursor { code, at: pc };
    let op_byte = c.byte()?;
    let op = OpCode::from_byte(op_byte).ok_or(DecodeError::UnknownOpcode(op_byte))?;
    let instr = match op {
        OpCode::Halt => Instr::Halt,
        OpCode::Nop => Instr::Nop,
        OpCode::Ret => Instr::Ret,
        OpCode::Mov => Instr::Mov {
            d: c.reg()?,
            a: c.reg()?,
        },
        OpCode::Not => Instr::Not {
            d: c.reg()?,
            a: c.reg()?,
        },
        OpCode::MLoad => Instr::MLoad {
            d: c.reg()?,
            a: c.reg()?,
        },
        OpCode::SLoad => Instr::SLoad {
            d: c.reg()?,
            a: c.reg()?,
        },
        OpCode::MStore => Instr::MStore {
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::SStore => Instr::SStore {
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Ldi => Instr::Ldi {
            d: c.reg()?,
            imm: c.u64()?,
        },
        OpCode::Ldc => Instr::Ldc {
            d: c.reg()?,
            idx: c.u16()?,
        },
        OpCode::Add => Instr::Add {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Sub => Instr::Sub {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Mul => Instr::Mul {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Div => Instr::Div {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Rem => Instr::Rem {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::AddW => Instr::AddW {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::SubW => Instr::SubW {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::MulW => Instr::MulW {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::MulHi => Instr::MulHi {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::And => Instr::And {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Or => Instr::Or {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Xor => Instr::Xor {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Shl => Instr::Shl {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Shr => Instr::Shr {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Eq => Instr::Eq {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::LtU => Instr::LtU {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::GtU => Instr::GtU {
            d: c.reg()?,
            a: c.reg()?,
            b: c.reg()?,
        },
        OpCode::Push => Instr::Push { a: c.reg()? },
        OpCode::Pop => Instr::Pop { d: c.reg()? },
        OpCode::Jmp => Instr::Jmp { target: c.u32()? },
        OpCode::Call => Instr::Call { target: c.u32()? },
        OpCode::Jz => Instr::Jz {
            a: c.reg()?,
            target: c.u32()?,
        },
        OpCode::Jnz => Instr::Jnz {
            a: c.reg()?,
            target: c.u32()?,
        },
        OpCode::Send => Instr::Send {
            a: c.reg()?,
            b: c.reg()?,
            c: c.reg()?,
        },
        OpCode::Emit => Instr::Emit {
            a: c.reg()?,
            b: c.reg()?,
            c: c.reg()?,
        },
        OpCode::Hash => Instr::Hash {
            a: c.reg()?,
            b: c.reg()?,
            c: c.reg()?,
        },
        OpCode::VerifyMl => Instr::VerifyMl {
            a: c.reg()?,
            b: c.reg()?,
            c: c.reg()?,
        },
        OpCode::VerifySlh => Instr::VerifySlh {
            a: c.reg()?,
            b: c.reg()?,
            c: c.reg()?,
        },
        OpCode::MerkleVerify => Instr::MerkleVerify {
            a: c.reg()?,
            b: c.reg()?,
            c: c.reg()?,
        },
        OpCode::VrfVerify => Instr::VrfVerify {
            a: c.reg()?,
            b: c.reg()?,
            c: c.reg()?,
        },
        OpCode::Kem => Instr::Kem {
            a: c.reg()?,
            b: c.reg()?,
            c: c.reg()?,
        },
    };
    Ok((instr, c.at - pc))
}

struct Cursor<'a> {
    code: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.code.get(self.at).ok_or(DecodeError::Truncated)?;
        self.at += 1;
        Ok(b)
    }

    fn reg(&mut self) -> Result<Reg, DecodeError> {
        let b = self.byte()?;
        if (b as usize) >= NUM_REGS {
            return Err(DecodeError::BadRegister(b));
        }
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes([self.byte()?, self.byte()?]))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes([
            self.byte()?,
            self.byte()?,
            self.byte()?,
            self.byte()?,
        ]))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let mut buf = [0u8; 8];
        for slot in buf.iter_mut() {
            *slot = self.byte()?;
        }
        Ok(u64::from_be_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_set() -> Vec<Instr> {
        vec![
            Instr::Halt,
            Instr::Nop,
            Instr::Ret,
            Instr::Mov { d: 1, a: 2 },
            Instr::Ldi {
                d: 3,
                imm: 72623859790382856,
            },
            Instr::Ldc { d: 4, idx: 4660 },
            Instr::Add { d: 5, a: 6, b: 7 },
            Instr::Sub { d: 5, a: 6, b: 7 },
            Instr::Mul { d: 5, a: 6, b: 7 },
            Instr::Div { d: 5, a: 6, b: 7 },
            Instr::Rem { d: 5, a: 6, b: 7 },
            Instr::AddW { d: 5, a: 6, b: 7 },
            Instr::SubW { d: 5, a: 6, b: 7 },
            Instr::MulW { d: 5, a: 6, b: 7 },
            Instr::MulHi { d: 5, a: 6, b: 7 },
            Instr::And { d: 8, a: 9, b: 10 },
            Instr::Or { d: 8, a: 9, b: 10 },
            Instr::Xor { d: 8, a: 9, b: 10 },
            Instr::Not { d: 8, a: 9 },
            Instr::Shl { d: 8, a: 9, b: 10 },
            Instr::Shr { d: 8, a: 9, b: 10 },
            Instr::Eq {
                d: 11,
                a: 12,
                b: 13,
            },
            Instr::LtU {
                d: 11,
                a: 12,
                b: 13,
            },
            Instr::GtU {
                d: 11,
                a: 12,
                b: 13,
            },
            Instr::Push { a: 14 },
            Instr::Pop { d: 15 },
            Instr::MLoad { d: 0, a: 1 },
            Instr::MStore { a: 0, b: 1 },
            Instr::Jmp {
                target: 3735928559,
            },
            Instr::Jz {
                a: 2,
                target: 12648430,
            },
            Instr::Jnz {
                a: 2,
                target: 12648430,
            },
            Instr::Call {
                target: 4096,
            },
            Instr::SLoad { d: 3, a: 4 },
            Instr::SStore { a: 3, b: 4 },
            Instr::Send { a: 1, b: 2, c: 3 },
            Instr::Emit { a: 1, b: 2, c: 3 },
            Instr::Hash { a: 1, b: 2, c: 3 },
            Instr::VerifyMl { a: 1, b: 2, c: 3 },
            Instr::VerifySlh { a: 1, b: 2, c: 3 },
            Instr::MerkleVerify { a: 1, b: 2, c: 3 },
            Instr::VrfVerify { a: 1, b: 2, c: 3 },
            Instr::Kem { a: 1, b: 2, c: 3 },
        ]
    }

    #[test]
    fn round_trip_each_opcode() {
        for instr in sample_set() {
            let mut bytes = Vec::new();
            instr.encode(&mut bytes);
            assert_eq!(bytes.len(), instr.encoded_len());
            let (decoded, used) = decode(&bytes, 0).expect("decode");
            assert_eq!(decoded, instr);
            assert_eq!(used, bytes.len());
            assert_eq!(decoded.opcode(), instr.opcode());
        }
    }

    #[test]
    fn round_trip_within_stream() {
        let mut bytes = Vec::new();
        let program = sample_set();
        for instr in &program {
            instr.encode(&mut bytes);
        }
        let mut pc = 0usize;
        for instr in &program {
            let (decoded, used) = decode(&bytes, pc).expect("decode");
            assert_eq!(&decoded, instr);
            pc += used;
        }
        assert_eq!(pc, bytes.len());
    }

    #[test]
    fn unknown_opcode_faults() {
        assert_eq!(decode(&[255], 0), Err(DecodeError::UnknownOpcode(255)));
    }

    #[test]
    fn truncated_faults() {
        assert_eq!(
            decode(&[OpCode::Add as u8, 1, 2], 0),
            Err(DecodeError::Truncated)
        );
        assert_eq!(decode(&[], 0), Err(DecodeError::Truncated));
    }

    #[test]
    fn bad_register_faults() {
        assert_eq!(
            decode(&[OpCode::Mov as u8, 16, 0], 0),
            Err(DecodeError::BadRegister(16))
        );
    }
}
