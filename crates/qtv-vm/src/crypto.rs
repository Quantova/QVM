//! Cryptographic opcode group. Each opcode reads its inputs from a scratch memory region addressed

use qtv_crypto::sha3::sha3_256;
use qtv_crypto::{ml_dsa, ml_kem, slh_dsa, vrf};

use crate::interp::Fault;
use crate::isa::Reg;
use crate::state::Machine;

/// SHA3 256 of a scratch memory region. Register `a` holds the input pointer, `b` the input length,
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

/// ML-DSA verify. Register `a` holds the input pointer, `b` the input length, and `c` the
pub(crate) fn verify_ml(m: &mut Machine, a: Reg, b: Reg, c: Reg) -> Result<(), Fault> {
    const PK: usize = ml_dsa::PUBLIC_KEY_BYTES;
    const SIG: usize = ml_dsa::SIGNATURE_BYTES;
    let ptr = m.reg(a);
    let len = m.reg(b);
    let (pk, sig, message) = {
        let region = m.mem_region(ptr, len).ok_or(Fault::BadMemory)?;
        if region.len() < PK + SIG {
            return Err(Fault::BadMemory);
        }
        let pk: [u8; PK] = region[..PK].try_into().map_err(|_| Fault::BadMemory)?;
        let sig: [u8; SIG] = region[PK..PK + SIG]
            .try_into()
            .map_err(|_| Fault::BadMemory)?;
        (pk, sig, region[PK + SIG..].to_vec())
    };
    let ok = ml_dsa::verify(&pk, &message, &sig, &[]);
    m.set_reg(c, u64::from(ok));
    Ok(())
}

/// SLH-DSA verify. Register `a` holds the input pointer, `b` the input length, and `c` the
pub(crate) fn verify_slh(m: &mut Machine, a: Reg, b: Reg, c: Reg) -> Result<(), Fault> {
    const PK: usize = slh_dsa::PUBLIC_KEY_BYTES;
    const SIG: usize = slh_dsa::SIGNATURE_BYTES;
    let ptr = m.reg(a);
    let len = m.reg(b);
    let (pk, sig, message) = {
        let region = m.mem_region(ptr, len).ok_or(Fault::BadMemory)?;
        if region.len() < PK + SIG {
            return Err(Fault::BadMemory);
        }
        let pk: [u8; PK] = region[..PK].try_into().map_err(|_| Fault::BadMemory)?;
        (
            pk,
            region[PK..PK + SIG].to_vec(),
            region[PK + SIG..].to_vec(),
        )
    };
    let ok = slh_dsa::verify(&pk, &message, &sig, &[]);
    m.set_reg(c, u64::from(ok));
    Ok(())
}

/// Merkle proof verify. Register `a` holds the input pointer, `b` the input length, and `c` the
pub(crate) fn merkle_verify(m: &mut Machine, a: Reg, b: Reg, c: Reg) -> Result<(), Fault> {
    const H: usize = 32;
    const HEADER: usize = 2 * H + 8;
    let ptr = m.reg(a);
    let len = m.reg(b);
    let (root, index, leaf, path) = {
        let region = m.mem_region(ptr, len).ok_or(Fault::BadMemory)?;
        if region.len() < HEADER || (region.len() - HEADER) % H != 0 {
            return Err(Fault::BadMemory);
        }
        let mut root = [0u8; H];
        root.copy_from_slice(&region[..H]);
        let mut index = [0u8; 8];
        index.copy_from_slice(&region[H..H + 8]);
        let mut leaf = [0u8; H];
        leaf.copy_from_slice(&region[H + 8..HEADER]);
        (
            root,
            u64::from_be_bytes(index),
            leaf,
            region[HEADER..].to_vec(),
        )
    };
    let mut node = leaf;
    for (level, sibling) in path.chunks_exact(H).enumerate() {
        let mut pair = [0u8; 2 * H];
        let node_on_left = level >= 64 || (index >> level) & 1 == 0;
        if node_on_left {
            pair[..H].copy_from_slice(&node);
            pair[H..].copy_from_slice(sibling);
        } else {
            pair[..H].copy_from_slice(sibling);
            pair[H..].copy_from_slice(&node);
        }
        node = sha3_256(&pair);
    }
    m.set_reg(c, u64::from(node == root));
    Ok(())
}

/// Random function verify. Register `a` holds the input pointer, `b` the input length, and `c` the
pub(crate) fn verify_vrf(m: &mut Machine, a: Reg, b: Reg, c: Reg) -> Result<(), Fault> {
    const PK: usize = vrf::PUBLIC_KEY_BYTES;
    const OUT: usize = vrf::OUTPUT_BYTES;
    const PROOF: usize = vrf::PROOF_BYTES;
    let ptr = m.reg(a);
    let len = m.reg(b);
    let (pk, output, proof, input) = {
        let region = m.mem_region(ptr, len).ok_or(Fault::BadMemory)?;
        if region.len() < PK + OUT + PROOF {
            return Err(Fault::BadMemory);
        }
        let pk: [u8; PK] = region[..PK].try_into().map_err(|_| Fault::BadMemory)?;
        let output: [u8; OUT] = region[PK..PK + OUT]
            .try_into()
            .map_err(|_| Fault::BadMemory)?;
        let proof: [u8; PROOF] = region[PK + OUT..PK + OUT + PROOF]
            .try_into()
            .map_err(|_| Fault::BadMemory)?;
        (pk, output, proof, region[PK + OUT + PROOF..].to_vec())
    };
    let ok = vrf::verify(&pk, &input, &output, &proof);
    m.set_reg(c, u64::from(ok));
    Ok(())
}

/// Key encapsulation. Register `a` holds the input pointer, `b` the input length, and `c` the output
pub(crate) fn kem(m: &mut Machine, a: Reg, b: Reg, c: Reg) -> Result<(), Fault> {
    const EK: usize = ml_kem::ENCAPS_KEY_BYTES;
    const MSG: usize = ml_kem::SEED_BYTES;
    let ptr = m.reg(a);
    let len = m.reg(b);
    let out = m.reg(c);
    let (ek, msg) = {
        let region = m.mem_region(ptr, len).ok_or(Fault::BadMemory)?;
        if region.len() < EK + MSG {
            return Err(Fault::BadMemory);
        }
        let ek: [u8; EK] = region[..EK].try_into().map_err(|_| Fault::BadMemory)?;
        let msg: [u8; MSG] = region[EK..EK + MSG]
            .try_into()
            .map_err(|_| Fault::BadMemory)?;
        (ek, msg)
    };
    let (shared, ciphertext) = ml_kem::encaps(&ek, &msg);
    let mut output = [0u8; ml_kem::SHARED_SECRET_BYTES + ml_kem::CIPHERTEXT_BYTES];
    output[..ml_kem::SHARED_SECRET_BYTES].copy_from_slice(&shared);
    output[ml_kem::SHARED_SECRET_BYTES..].copy_from_slice(&ciphertext);
    if !m.mem_write(out, &output) {
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

    // Build a public key, signature, message region and load it at offset zero, returning the region
    // length. Register 0 points at the region and register 1 holds its length.
    fn load_ml(m: &mut Machine, pk: &[u8], sig: &[u8], msg: &[u8]) -> u64 {
        let mut region = Vec::new();
        region.extend_from_slice(pk);
        region.extend_from_slice(sig);
        region.extend_from_slice(msg);
        assert!(m.mem_write(0, &region));
        m.set_reg(0, 0);
        m.set_reg(1, region.len() as u64);
        region.len() as u64
    }

    #[test]
    fn verify_ml_accepts_valid_and_rejects_tampered() {
        let (pk, sk) = ml_dsa::keygen(&[7u8; 32]);
        let msg = b"quantova ml-dsa verify opcode";
        let sig = ml_dsa::sign(&sk, msg, &[], &[0u8; 32]).expect("sign");

        let mut m = Machine::new();
        load_ml(&mut m, &pk, &sig, msg);
        verify_ml(&mut m, 0, 1, 2).expect("verify");
        assert_eq!(m.reg(2), 1);

        let mut bad = sig;
        bad[0] ^= 1;
        let mut m = Machine::new();
        load_ml(&mut m, &pk, &bad, msg);
        verify_ml(&mut m, 0, 1, 2).expect("verify");
        assert_eq!(m.reg(2), 0);
    }

    #[test]
    fn verify_ml_rejects_short_region() {
        let mut m = Machine::new();
        m.set_reg(0, 0);
        m.set_reg(1, 16);
        assert_eq!(verify_ml(&mut m, 0, 1, 2), Err(Fault::BadMemory));
    }

    // Load a public key, signature, message region at offset zero for a verify opcode.
    fn load_region(m: &mut Machine, parts: &[&[u8]]) {
        let mut region = Vec::new();
        for part in parts {
            region.extend_from_slice(part);
        }
        assert!(m.mem_write(0, &region));
        m.set_reg(0, 0);
        m.set_reg(1, region.len() as u64);
    }

    #[test]
    fn verify_slh_accepts_valid_and_rejects_tampered() {
        let (sk, pk) = slh_dsa::keygen(&[1u8; 24], &[2u8; 24], &[3u8; 24]);
        let msg = b"quantova slh-dsa verify opcode";
        let sig = slh_dsa::sign(&sk, msg, &[], &[4u8; 24]).expect("sign");

        let mut m = Machine::new();
        load_region(&mut m, &[&pk, &sig, msg]);
        verify_slh(&mut m, 0, 1, 2).expect("verify");
        assert_eq!(m.reg(2), 1);

        let mut bad = sig;
        bad[0] ^= 1;
        let mut m = Machine::new();
        load_region(&mut m, &[&pk, &bad, msg]);
        verify_slh(&mut m, 0, 1, 2).expect("verify");
        assert_eq!(m.reg(2), 0);
    }

    #[test]
    fn verify_slh_rejects_short_region() {
        let mut m = Machine::new();
        m.set_reg(0, 0);
        m.set_reg(1, 64);
        assert_eq!(verify_slh(&mut m, 0, 1, 2), Err(Fault::BadMemory));
    }

    // The SHA3 256 parent of two ordered child digests.
    fn node(left: &[u8], right: &[u8]) -> [u8; 32] {
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(left);
        pair[32..].copy_from_slice(right);
        sha3_256(&pair)
    }

    fn merkle_region(root: &[u8], index: u64, leaf: &[u8], path: &[[u8; 32]]) -> Vec<u8> {
        let mut region = Vec::new();
        region.extend_from_slice(root);
        region.extend_from_slice(&index.to_be_bytes());
        region.extend_from_slice(leaf);
        for sibling in path {
            region.extend_from_slice(sibling);
        }
        region
    }

    #[test]
    fn merkle_verify_accepts_valid_and_rejects_tampered() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let p01 = node(&leaves[0], &leaves[1]);
        let p23 = node(&leaves[2], &leaves[3]);
        let root = node(&p01, &p23);

        // Proof for the leaf at index two, siblings from the leaf upward.
        let path = [leaves[3], p01];
        let region = merkle_region(&root, 2, &leaves[2], &path);

        let mut m = Machine::new();
        assert!(m.mem_write(0, &region));
        m.set_reg(0, 0);
        m.set_reg(1, region.len() as u64);
        merkle_verify(&mut m, 0, 1, 2).expect("merkle");
        assert_eq!(m.reg(2), 1);

        let mut bad = region;
        bad[0] ^= 1;
        let mut m = Machine::new();
        assert!(m.mem_write(0, &bad));
        m.set_reg(0, 0);
        m.set_reg(1, bad.len() as u64);
        merkle_verify(&mut m, 0, 1, 2).expect("merkle");
        assert_eq!(m.reg(2), 0);
    }

    #[test]
    fn merkle_verify_rejects_misshaped_region() {
        let mut m = Machine::new();
        m.set_reg(0, 0);
        m.set_reg(1, (2 * 32 + 8 + 5) as u64);
        assert_eq!(merkle_verify(&mut m, 0, 1, 2), Err(Fault::BadMemory));
        m.set_reg(1, 8);
        assert_eq!(merkle_verify(&mut m, 0, 1, 2), Err(Fault::BadMemory));
    }

    #[test]
    fn verify_vrf_accepts_valid_and_rejects_wrong() {
        let (sk, pk) = vrf::keygen(b"quantova vrf verify opcode seed");
        let input = b"committee sampling input";
        let (output, proof) = vrf::prove(&sk, input);

        let mut m = Machine::new();
        load_region(&mut m, &[&pk, &output, &proof, input]);
        verify_vrf(&mut m, 0, 1, 2).expect("vrf");
        assert_eq!(m.reg(2), 1);

        let mut bad = output;
        bad[0] ^= 1;
        let mut m = Machine::new();
        load_region(&mut m, &[&pk, &bad, &proof, input]);
        verify_vrf(&mut m, 0, 1, 2).expect("vrf");
        assert_eq!(m.reg(2), 0);
    }

    #[test]
    fn verify_vrf_rejects_short_region() {
        let mut m = Machine::new();
        m.set_reg(0, 0);
        m.set_reg(1, 80);
        assert_eq!(verify_vrf(&mut m, 0, 1, 2), Err(Fault::BadMemory));
    }

    #[test]
    fn kem_encapsulates_and_matches_decapsulation() {
        let (ek, dk) = ml_kem::keygen(&[4u8; 32], &[5u8; 32]);
        let msg = [6u8; 32];

        let mut region = Vec::new();
        region.extend_from_slice(&ek);
        region.extend_from_slice(&msg);
        let mut m = Machine::new();
        assert!(m.mem_write(0, &region));
        m.set_reg(0, 0);
        m.set_reg(1, region.len() as u64);
        m.set_reg(2, 4096);
        kem(&mut m, 0, 1, 2).expect("kem");

        let total = ml_kem::SHARED_SECRET_BYTES + ml_kem::CIPHERTEXT_BYTES;
        let out = m.mem_region(4096, total as u64).unwrap();
        let shared = &out[..ml_kem::SHARED_SECRET_BYTES];
        let ciphertext: [u8; ml_kem::CIPHERTEXT_BYTES] =
            out[ml_kem::SHARED_SECRET_BYTES..].try_into().unwrap();
        // The encapsulated shared secret decapsulates to the same value.
        assert_eq!(&ml_kem::decaps(&dk, &ciphertext)[..], shared);
        // And it equals a direct encapsulation with the crypto crate.
        let (want_ss, want_ct) = ml_kem::encaps(&ek, &msg);
        assert_eq!(shared, &want_ss[..]);
        assert_eq!(&ciphertext[..], &want_ct[..]);
    }

    #[test]
    fn kem_rejects_short_region() {
        let mut m = Machine::new();
        m.set_reg(0, 0);
        m.set_reg(1, 100);
        m.set_reg(2, 4096);
        assert_eq!(kem(&mut m, 0, 1, 2), Err(Fault::BadMemory));
    }

    #[test]
    fn kem_rejects_out_of_bounds_output() {
        let (ek, _dk) = ml_kem::keygen(&[4u8; 32], &[5u8; 32]);
        let mut region = Vec::new();
        region.extend_from_slice(&ek);
        region.extend_from_slice(&[6u8; 32]);
        let mut m = Machine::new();
        assert!(m.mem_write(0, &region));
        m.set_reg(0, 0);
        m.set_reg(1, region.len() as u64);
        m.set_reg(2, u64::MAX);
        assert_eq!(kem(&mut m, 0, 1, 2), Err(Fault::BadMemory));
    }
}
