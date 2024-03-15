use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

const NONCE: [u8; 12] = [0u8; 12]; // key expected to be chosen independently and uniformly at random for each message so it is safe to use a fixed nonce zero

/// hash using shake128
pub(super) fn hash<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut hasher = Shake128::default();
    hasher.update(bytes.as_ref());
    let mut reader = hasher.finalize_xof();
    let mut pkh = vec![0u8; N];
    reader.read(&mut pkh);
    pkh.try_into().unwrap()
}

/// encrypt/decrypt using chacha20
pub(super) fn encrypt<const N: usize>(plaintext: &[u8; N], key: &[u8; 32]) -> [u8; N] {
    let mut cipher = ChaCha20::new(key.into(), &NONCE.into());
    let mut buffer = *plaintext;
    cipher.apply_keystream(&mut buffer);
    buffer
}
