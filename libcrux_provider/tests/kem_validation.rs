//! Regression tests for the libcrux KEM dependency's input and entropy checks.
use hpke_rs_crypto::{error::Error as HpkeError, types::KemAlgorithm, HpkeCrypto};
use hpke_rs_libcrux::HpkeLibcrux;
use libcrux_kem::{Algorithm, Error, PrivateKey, PublicKey};

#[test]
#[allow(deprecated)]
fn malformed_xwing_public_keys_return_errors() {
    for alg in [
        KemAlgorithm::XWingDraft06,
        KemAlgorithm::XWingDraft06Obsolete,
    ] {
        for len in [0, 1, 31, 32, 1183, 1184, 1215, 1217] {
            let result = HpkeLibcrux::kem_encaps(alg, &vec![0; len], &mut HpkeLibcrux::prng());
            assert!(matches!(result, Err(HpkeError::KemInvalidPublicKey)));
        }
    }
}

#[test]
fn malformed_hybrid_private_keys_return_errors() {
    for len in [0, 1, 31, 32, 2399, 2400, 2431, 2433] {
        assert!(matches!(
            PrivateKey::decode(Algorithm::X25519MlKem768Draft00, &vec![0; len]),
            Err(Error::InvalidPrivateKey)
        ));
    }
}

#[test]
fn hybrid_encapsulation_requires_exact_seed_length() {
    for alg in [Algorithm::X25519MlKem768Draft00, Algorithm::XWingKemDraft06] {
        let (_, pk) = libcrux_kem::key_gen(alg, &mut HpkeLibcrux::prng()).unwrap();
        let stored_pk = pk.encode();
        let pk = PublicKey::decode(alg, &stored_pk).unwrap();
        for len in [0, 1, 31, 32, 63, 65] {
            assert!(matches!(
                pk.encapsulate_derand(&vec![0; len]),
                Err(Error::KeyGen)
            ));
        }
        assert!(pk.encapsulate_derand(&[7; 64]).is_ok());
    }
}

struct FailedEntropy;

impl rand::TryRng for FailedEntropy {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(std::io::Error::other("test entropy failure"))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(std::io::Error::other("test entropy failure"))
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(std::io::Error::other("test entropy failure"))
    }
}
impl rand::TryCryptoRng for FailedEntropy {}

#[test]
fn entropy_failure_returns_an_error() {
    let alg = Algorithm::XWingKemDraft06;
    assert!(matches!(
        libcrux_kem::key_gen(alg, &mut FailedEntropy),
        Err(Error::KeyGen)
    ));
    let (_, pk) = libcrux_kem::key_gen(alg, &mut HpkeLibcrux::prng()).unwrap();
    assert!(matches!(
        pk.encapsulate(&mut FailedEntropy),
        Err(Error::KeyGen)
    ));
}
