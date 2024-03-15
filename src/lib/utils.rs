use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use std::fmt::Write;

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

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02X}");
        output
    })
}

pub fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
