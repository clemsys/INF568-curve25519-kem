//! ElGamal style public key encryption on the Edwards curve

use super::utils::{encrypt, hash};
use curve25519_dalek::{constants::X25519_BASEPOINT, MontgomeryPoint, Scalar};

#[derive(PartialEq)]
pub struct ElGamalCiphertext<const N: usize>(MontgomeryPoint, [u8; N]);

pub struct ElGamalPlaintext<const N: usize>([u8; N]);

impl<const N: usize> ElGamalCiphertext<N> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut c = Vec::with_capacity(N + 32);
        c[..32].copy_from_slice(self.0.as_bytes());
        c[32..].copy_from_slice(&self.1);
        assert_eq!(c.len(), N + 32, "Invalid length for ElGamalCiphertext");
        c
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N + 32, "Invalid length for ElGamalCiphertext");
        ElGamalCiphertext(
            MontgomeryPoint(bytes[..32].try_into().unwrap()),
            bytes[32..].try_into().unwrap(),
        )
    }
}

impl<const N: usize> ElGamalPlaintext<N> {
    pub fn as_bytes(&self) -> [u8; N] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; N]) -> Self {
        ElGamalPlaintext(bytes)
    }
}

/// Returns (public_key: MontgomeryPoint, secret_key: Scalar)
pub fn keygen() -> (MontgomeryPoint, Scalar) {
    let secret_key = Scalar::random(&mut rand::thread_rng());
    let public_key = secret_key * X25519_BASEPOINT;
    (public_key, secret_key)
}

pub fn encaps<const N: usize>(
    plaintext: &ElGamalPlaintext<N>,
    public_key: &MontgomeryPoint,
    randomness: &Scalar,
) -> ElGamalCiphertext<N> {
    let shared_secret = randomness * public_key;
    let symmetric_key = hash::<32>(shared_secret.as_bytes());

    // encrypt plain with symmetric_key
    let ciphertext = encrypt(&plaintext.0, &symmetric_key);

    // return [r]G (so that the receiver can compute the shared secret) and the ciphertext
    ElGamalCiphertext(randomness * X25519_BASEPOINT, ciphertext)
}

pub fn decaps<const N: usize>(
    ciphertext: &ElGamalCiphertext<N>,
    secret_key: &Scalar,
) -> ElGamalPlaintext<N> {
    let shared_secret = secret_key * ciphertext.0;
    let symmetric_key = hash::<32>(shared_secret.as_bytes());

    // decrypt ciphertext with symmetric_key
    ElGamalPlaintext(encrypt(&ciphertext.1, &symmetric_key))
}
