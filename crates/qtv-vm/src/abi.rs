//! The cryptographic ABI of the machine, the byte lengths a caller must respect when it lays out a

use qtv_crypto::{ml_dsa, slh_dsa};

/// The scheme identifier of the module lattice signature, ML-DSA, the default scheme.
pub const SCHEME_ML_DSA: u64 = crate::crypto::SCHEME_ML_DSA;
/// The scheme identifier of the hash based signature, SLH-DSA.
pub const SCHEME_SLH_DSA: u64 = crate::crypto::SCHEME_SLH_DSA;

/// The public key byte length of an ML-DSA verify region, the prefix the verify and address opcodes
pub const ML_DSA_PUBLIC_KEY_BYTES: usize = ml_dsa::PUBLIC_KEY_BYTES;
/// The signature byte length that follows an ML-DSA public key in a verify region.
pub const ML_DSA_SIGNATURE_BYTES: usize = ml_dsa::SIGNATURE_BYTES;
/// The public key byte length of an SLH-DSA verify region under scheme two.
pub const SLH_DSA_PUBLIC_KEY_BYTES: usize = slh_dsa::PUBLIC_KEY_BYTES;
/// The signature byte length that follows an SLH-DSA public key in a verify region.
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
