//! Cryptographic opcode group. Each opcode reads its inputs from a scratch memory region addressed
//! by a pointer and a length in registers, calls the matching primitive in the crypto crate, and
//! writes a boolean acceptance into a register or bytes into memory. Every primitive is post-quantum
//! and comes from qtv-crypto. A digest stays raw bytes and is never formatted.

use qtv_crypto::sha3::sha3_256;

use crate::interp::Fault;
use crate::isa::Reg;
use crate::state::Machine;

/// SHA3 256 of a scratch memory region. Register `a` holds the input pointer, `b` the input length,
/// and `c` the output pointer. Writes the 32 byte digest at the output pointer.
pub(crate) fn hash(m: &mut Machine, a: Reg, b: Reg, c: Reg) -> Result<(), Fault> {
    let ptr = m.reg(a);
    let len = m.reg(b);
    let out = m.reg(c);
    let digest = {
        let region = m.mem_region(ptr, len).ok_or(Fault::BadMemory)?;
        sha3_256(region)
    };
    if !m.mem_write(out, &digest) {
        return Err(Fault::BadMemory);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine_with(region: &[u8], at: u64) -> Machine {
        let mut m = Machine::new();
        assert!(m.mem_write(at, region));
        m
    }

    #[test]
    fn hash_reproduces_the_crypto_crate_digest() {
        let input = b"quantova hash opcode over a region";
        let mut m = machine_with(input, 0);
        m.set_reg(0, 0);
        m.set_reg(1, input.len() as u64);
        m.set_reg(2, 4096);
        hash(&mut m, 0, 1, 2).expect("hash");
        let want = sha3_256(input);
        assert_eq!(m.mem_region(4096, 32).unwrap(), &want[..]);
    }

    #[test]
    fn hash_of_empty_region_is_defined() {
        let mut m = Machine::new();
        m.set_reg(0, 0);
        m.set_reg(1, 0);
        m.set_reg(2, 0);
        hash(&mut m, 0, 1, 2).expect("hash");
        assert_eq!(m.mem_region(0, 32).unwrap(), &sha3_256(b"")[..]);
    }

    #[test]
    fn hash_rejects_out_of_bounds_output() {
        let mut m = Machine::new();
        m.set_reg(0, 0);
        m.set_reg(1, 8);
        m.set_reg(2, u64::MAX);
        assert_eq!(hash(&mut m, 0, 1, 2), Err(Fault::BadMemory));
    }
}
