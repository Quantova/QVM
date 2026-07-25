// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_crypto::{ml_dsa, slh_dsa};

pub const SCHEME_ML_DSA: u64 = crate::crypto::SCHEME_ML_DSA;
pub const SCHEME_SLH_DSA: u64 = crate::crypto::SCHEME_SLH_DSA;

pub fn scalar_key(slot: u64) -> crate::interp::StorageKey {
    let mut key = [0u8; crate::interp::STORAGE_KEY_BYTES];
    key[crate::interp::STORAGE_KEY_BYTES - 8..].copy_from_slice(&slot.to_be_bytes());
    key
}

pub const ML_DSA_PUBLIC_KEY_BYTES: usize = ml_dsa::PUBLIC_KEY_BYTES;
pub const ML_DSA_SIGNATURE_BYTES: usize = ml_dsa::SIGNATURE_BYTES;
pub const SLH_DSA_PUBLIC_KEY_BYTES: usize = slh_dsa::PUBLIC_KEY_BYTES;
pub const SLH_DSA_SIGNATURE_BYTES: usize = slh_dsa::SIGNATURE_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_identifiers_are_the_ones_the_opcodes_dispatch_on() {
        assert_eq!(SCHEME_ML_DSA, 1);
        assert_eq!(SCHEME_SLH_DSA, 2);
    }

    #[test]
    fn the_region_lengths_are_non_zero() {
        assert!(ML_DSA_PUBLIC_KEY_BYTES > 0 && ML_DSA_SIGNATURE_BYTES > 0);
        assert!(SLH_DSA_PUBLIC_KEY_BYTES > 0 && SLH_DSA_SIGNATURE_BYTES > 0);
    }
}
