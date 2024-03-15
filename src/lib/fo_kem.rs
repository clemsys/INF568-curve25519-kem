use super::{elgamal_pke, utils::hash};
use curve25519_dalek::{MontgomeryPoint, Scalar};
use rand::Rng;

const L_S: usize = 32; // in bytes
const G1_OUT_LEN: usize = 32; // number of output bytes for G1
const G2_OUT_LEN: usize = 64; // number of output bytes for G2, must be > 32
const F_OUT_LEN: usize = 16; // number of output bytes for F, required to be 16 bytes
const SECRET_LEN: usize = L_S + G1_OUT_LEN + 64; // in bytes
const CIPHERTEXT_LEN: usize = 64; // in bytes, must be > 32

pub struct SecretKey(Scalar, [u8; L_S], MontgomeryPoint, [u8; G1_OUT_LEN]);

impl SecretKey {
    pub fn as_bytes(&self) -> [u8; SECRET_LEN] {
        let mut bytes = Vec::with_capacity(SECRET_LEN);
        // add self.0, self.1, self.2, self.3 to bytes
        bytes.extend_from_slice(self.0.as_bytes());
        bytes.extend_from_slice(&self.1);
        bytes.extend_from_slice(self.2.as_bytes());
        bytes.extend_from_slice(&self.3);
        bytes.try_into().unwrap()
    }
}

pub fn keygen() -> (MontgomeryPoint, SecretKey) {
    let (pk, sk) = elgamal_pke::keygen();
    let s = {
        let mut s = [0u8; L_S];
        rand::thread_rng().fill(&mut s);
        s
    };
    let pkh = hash(pk.as_bytes());
    let sk2 = SecretKey(sk, s, pk, pkh);
    (pk, sk2)
}

pub fn encaps(pk: &MontgomeryPoint) -> ([u8; CIPHERTEXT_LEN], [u8; F_OUT_LEN]) {
    let m = {
        let mut m = [0u8; CIPHERTEXT_LEN - 32];
        rand::thread_rng().fill(&mut m);
        m
    };

    // compute (r || k) = G2(G1(pk) || m)
    let h1 = {
        let mut h1 = [0u8; G1_OUT_LEN + CIPHERTEXT_LEN - 32];
        h1[..G1_OUT_LEN].copy_from_slice(&hash::<G1_OUT_LEN>(pk.as_bytes()));
        h1[G1_OUT_LEN..].copy_from_slice(&m);
        h1
    };
    let rk = hash::<G2_OUT_LEN>(&h1);
    let (r, k) = {
        let (r, k) = rk.split_at(32);
        (Scalar::from_bytes_mod_order(r.try_into().unwrap()), k)
    };

    let c = {
        let (c1, c2) = elgamal_pke::encaps(&m, pk, &r);
        let mut c = [0u8; CIPHERTEXT_LEN];
        c[..32].copy_from_slice(c1.as_bytes());
        c[32..].copy_from_slice(&c2);
        c
    };

    let shared_key = {
        let mut d = [0u8; CIPHERTEXT_LEN + G2_OUT_LEN - 32]; // d = c || k
        d[..CIPHERTEXT_LEN].copy_from_slice(&c);
        d[CIPHERTEXT_LEN..].copy_from_slice(k);
        hash::<F_OUT_LEN>(&d)
    };

    (c, shared_key)
}

pub fn decaps(sk: &SecretKey, ciphertext: [u8; CIPHERTEXT_LEN]) -> [u8; F_OUT_LEN] {
    let m: [u8; CIPHERTEXT_LEN - 32] = elgamal_pke::decaps(
        (
            MontgomeryPoint(ciphertext[..32].try_into().unwrap()),
            ciphertext[32..].try_into().unwrap(),
        ),
        &sk.0,
    );

    // r || k = G2(pkh || m)
    let rk = {
        let mut h1 = [0u8; G1_OUT_LEN + CIPHERTEXT_LEN - 32];
        h1[..G1_OUT_LEN].copy_from_slice(&sk.3);
        h1[G1_OUT_LEN..].copy_from_slice(&m);
        hash::<G2_OUT_LEN>(&h1)
    };
    let (r, k) = {
        let (r, k) = rk.split_at(32);
        (Scalar::from_bytes_mod_order(r.try_into().unwrap()), k)
    };

    let k_0 = {
        let mut d = [0u8; CIPHERTEXT_LEN + G2_OUT_LEN - 32]; // d = c || k
        d[..CIPHERTEXT_LEN].copy_from_slice(&ciphertext);
        d[CIPHERTEXT_LEN..].copy_from_slice(k);
        hash::<F_OUT_LEN>(&d)
    };

    let k_1 = {
        let mut d = [0u8; CIPHERTEXT_LEN + G2_OUT_LEN - 32]; // d = c || s
        d[..CIPHERTEXT_LEN].copy_from_slice(&ciphertext);
        d[CIPHERTEXT_LEN..].copy_from_slice(&sk.1);
        hash::<F_OUT_LEN>(&d)
    };

    let condition = {
        let (p, c) = elgamal_pke::encaps(&m, &sk.2, &r);
        let mut bytes = [0u8; CIPHERTEXT_LEN];
        bytes[..32].copy_from_slice(p.as_bytes());
        bytes[32..].copy_from_slice(&c);
        u8::from(bytes == ciphertext)
    };

    // return k0 if condition else k1 in constant time
    let mut shared_key = [0u8; F_OUT_LEN];
    for i in 0..F_OUT_LEN {
        shared_key[i] = k_0[i] * condition + k_1[i] * (1 - condition);
    }
    shared_key
}
