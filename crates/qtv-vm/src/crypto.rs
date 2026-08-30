// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::sha3::sha3_256;
use qtv_crypto::{ml_dsa, ml_kem, slh_dsa};

use crate::interp::Fault;
use crate::isa::Reg;
use crate::state::Machine;

pub const SCHEME_ML_DSA: u64 = 1;
pub const SCHEME_SLH_DSA: u64 = 2;

pub const ML_DSA_SIGNED_BYTES: u64 = (ml_dsa::PUBLIC_KEY_BYTES + ml_dsa::SIGNATURE_BYTES) as u64;
pub const SLH_DSA_SIGNED_BYTES: u64 = (slh_dsa::PUBLIC_KEY_BYTES + slh_dsa::SIGNATURE_BYTES) as u64;
pub const MERKLE_HEADER: u64 = (2 * 32 + 8) as u64;

const MERKLE_LEAF_TAG: u8 = 0x00;
const MERKLE_NODE_TAG: u8 = 0x01;

fn merkle_leaf(leaf: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[0] = MERKLE_LEAF_TAG;
    buf[1..].copy_from_slice(leaf);
    sha3_256(&buf)
}

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = MERKLE_NODE_TAG;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    sha3_256(&buf)
}

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
    if path.is_empty() {
        m.set_reg(c, 0);
        return Ok(());
    }
    let mut node = merkle_leaf(&leaf);
    for (level, sibling) in path.chunks_exact(H).enumerate() {
        let sib: [u8; H] = sibling.try_into().map_err(|_| Fault::BadMemory)?;
        let node_on_left = level >= 64 || (index >> level) & 1 == 0;
        node = if node_on_left {
            merkle_node(&node, &sib)
        } else {
            merkle_node(&sib, &node)
        };
    }
    m.set_reg(c, u64::from(node == root));
    Ok(())
}

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
    let (shared, ciphertext) = ml_kem::encaps(&ek, &msg).ok_or(Fault::CryptoFault)?;
    let mut output = [0u8; ml_kem::SHARED_SECRET_BYTES + ml_kem::CIPHERTEXT_BYTES];
    output[..ml_kem::SHARED_SECRET_BYTES].copy_from_slice(&shared);
    output[ml_kem::SHARED_SECRET_BYTES..].copy_from_slice(&ciphertext);
    if !m.mem_write(out, &output) {
        return Err(Fault::BadMemory);
    }
    Ok(())
}

pub(crate) fn address(m: &mut Machine, a: Reg, b: Reg, c: Reg) -> Result<(), Fault> {
    let ptr = m.reg(a);
    let scheme = m.reg(b);
    let out = m.reg(c);
    let pk_len = match scheme {
        SCHEME_ML_DSA => ml_dsa::PUBLIC_KEY_BYTES,
        SCHEME_SLH_DSA => slh_dsa::PUBLIC_KEY_BYTES,
        _ => return Err(Fault::BadScheme),
    };
    let digest = {
        let pk = m.mem_region(ptr, pk_len as u64).ok_or(Fault::BadMemory)?;
        let mut input = Vec::with_capacity(1 + pk_len);
        input.push(scheme as u8);
        input.extend_from_slice(pk);
        sha3_256(&input)
    };
    if !m.mem_write(out, &digest) {
        return Err(Fault::BadMemory);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_address(scheme: u8, public_key: &[u8]) -> [u8; 32] {
        let mut input = Vec::with_capacity(1 + public_key.len());
        input.push(scheme);
        input.extend_from_slice(public_key);
        sha3_256(&input)
    }

    #[test]
    fn address_matches_the_account_model_for_ml_dsa() {
        let (pk, _sk) = ml_dsa::keygen(&[7u8; 32]);
        let mut region = pk.to_vec();
        region.extend_from_slice(b"signature and message follow the key");
        let mut m = Machine::new();
        assert!(m.mem_write(0, &region));
        m.set_reg(0, 0);
        m.set_reg(1, SCHEME_ML_DSA);
        m.set_reg(2, 40000);
        address(&mut m, 0, 1, 2).expect("derive");
        assert_eq!(
            m.mem_region(40000, 32).unwrap(),
            &expected_address(1, &pk)[..]
        );
    }

    #[test]
    fn address_matches_the_account_model_for_slh_dsa() {
        let (_sk, pk) = slh_dsa::keygen(&[1u8; 24], &[2u8; 24], &[3u8; 24]);
        let mut m = Machine::new();
        assert!(m.mem_write(0, &pk));
        m.set_reg(0, 0);
        m.set_reg(1, SCHEME_SLH_DSA);
        m.set_reg(2, 40000);
        address(&mut m, 0, 1, 2).expect("derive");
        assert_eq!(
            m.mem_region(40000, 32).unwrap(),
            &expected_address(2, &pk)[..]
        );
    }

    #[test]
    fn a_different_public_key_derives_a_different_address() {
        let (pk_a, _) = ml_dsa::keygen(&[1u8; 32]);
        let (pk_b, _) = ml_dsa::keygen(&[2u8; 32]);
        let derive = |pk: &[u8]| {
            let mut m = Machine::new();
            assert!(m.mem_write(0, pk));
            m.set_reg(0, 0);
            m.set_reg(1, SCHEME_ML_DSA);
            m.set_reg(2, 40000);
            address(&mut m, 0, 1, 2).expect("derive");
            m.mem_region(40000, 32).unwrap().to_vec()
        };
        assert_ne!(derive(&pk_a), derive(&pk_b));
    }

    #[test]
    fn an_unknown_scheme_faults() {
        let (pk, _) = ml_dsa::keygen(&[9u8; 32]);
        let mut m = Machine::new();
        assert!(m.mem_write(0, &pk));
        m.set_reg(0, 0);
        m.set_reg(1, 3); // reserved FN-DSA, no address derivation in the tagged machine
        m.set_reg(2, 40000);
        assert_eq!(address(&mut m, 0, 1, 2), Err(Fault::BadScheme));
    }

    #[test]
    fn a_region_too_short_for_the_public_key_faults() {
        let mut m = Machine::new();
        m.set_reg(0, 0);
        m.set_reg(1, SCHEME_ML_DSA);
        m.set_reg(2, 40000);
        m.set_reg(0, (crate::state::MEM_BYTES - 16) as u64);
        assert_eq!(address(&mut m, 0, 1, 2), Err(Fault::BadMemory));
    }

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
        let data: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let tagged: Vec<[u8; 32]> = data.iter().map(merkle_leaf).collect();
        let p01 = merkle_node(&tagged[0], &tagged[1]);
        let p23 = merkle_node(&tagged[2], &tagged[3]);
        let root = merkle_node(&p01, &p23);

        let path = [tagged[3], p01];
        let region = merkle_region(&root, 2, &data[2], &path);

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
    fn merkle_verify_rejects_an_internal_node_presented_as_a_leaf() {
        let data: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let tagged: Vec<[u8; 32]> = data.iter().map(merkle_leaf).collect();
        let p01 = merkle_node(&tagged[0], &tagged[1]);
        let p23 = merkle_node(&tagged[2], &tagged[3]);
        let root = merkle_node(&p01, &p23);

        let path = [p23];
        let region = merkle_region(&root, 0, &p01, &path);
        let mut m = Machine::new();
        assert!(m.mem_write(0, &region));
        m.set_reg(0, 0);
        m.set_reg(1, region.len() as u64);
        merkle_verify(&mut m, 0, 1, 2).expect("merkle");
        assert_eq!(m.reg(2), 0, "an internal node must not verify as a leaf");
    }

    #[test]
    fn merkle_verify_rejects_a_zero_length_path() {
        let root = sha3_256(b"a committed root");
        let region = merkle_region(&root, 0, &root, &[]);
        let mut m = Machine::new();
        assert!(m.mem_write(0, &region));
        m.set_reg(0, 0);
        m.set_reg(1, region.len() as u64);
        merkle_verify(&mut m, 0, 1, 2).expect("merkle");
        assert_eq!(m.reg(2), 0, "a proof with no siblings must not verify");
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
        assert_eq!(&ml_kem::decaps(&dk, &ciphertext)[..], shared);
        let (want_ss, want_ct) = ml_kem::encaps(&ek, &msg).expect("a canonical encapsulation key");
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
