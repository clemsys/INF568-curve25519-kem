//! ElGamal style public key encryption on the Edwards curve

use super::utils::{encrypt, hash};
use curve25519_dalek::{constants::X25519_BASEPOINT, MontgomeryPoint, Scalar};

pub fn keygen() -> (MontgomeryPoint, Scalar) {
    let sk = Scalar::random(&mut rand::thread_rng());
    let pk = &sk * X25519_BASEPOINT;
    (pk, sk)
}

pub fn encaps<const N: usize>(
    plaintext: &[u8; N],
    public_key: &MontgomeryPoint,
    randomness: &Scalar,
) -> (MontgomeryPoint, [u8; N]) {
    let shared_secret = randomness * public_key;
    let symmetric_key = hash::<32>(shared_secret.as_bytes());

    // encrypt plain with symmetric_key
    let ciphertext = encrypt(plaintext, &symmetric_key);

    // return [r]G (so that the receiver can compute the shared secret) and the ciphertext
    (randomness * X25519_BASEPOINT, ciphertext)
}

pub fn decaps<const N: usize>(
    ciphertext: (MontgomeryPoint, &[u8; N]),
    secret_key: &Scalar,
) -> [u8; N] {
    let shared_secret = secret_key * ciphertext.0;
    let symmetric_key = hash::<32>(shared_secret.as_bytes());

    // decrypt ciphertext with symmetric_key
    encrypt(ciphertext.1, &symmetric_key)
}
