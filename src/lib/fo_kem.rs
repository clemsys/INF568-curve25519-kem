use super::{
    elgamal_pke::{self, ElGamalCiphertext, ElGamalPlaintext},
    utils::hash,
};
use curve25519_dalek::{MontgomeryPoint, Scalar};
use rand::Rng;

const L_S: usize = 32; // in bytes
const G1_OUT_LEN: usize = 32; // number of output bytes for G1
const G2_OUT_LEN: usize = 64; // number of output bytes for G2, must be > 32
const F_OUT_LEN: usize = 16; // number of output bytes for F, required to be 16 bytes
const SECRET_LEN: usize = L_S + G1_OUT_LEN + 64; // in bytes
const PLAINTEXT_LEN: usize = 64; // in bytes, must be > 32, add 32 for ElGamalCiphertext

// pub struct SecretKey(Scalar, [u8; L_S], MontgomeryPoint, [u8; G1_OUT_LEN]);
pub struct SecretKey {
    sk: Scalar,
    s: [u8; L_S],
    pk: MontgomeryPoint,
    pkh: [u8; G1_OUT_LEN],
}

impl SecretKey {
    pub fn as_bytes(&self) -> [u8; SECRET_LEN] {
        let mut bytes = [0u8; SECRET_LEN];
        // add self.0, self.1, self.2, self.3 to bytes
        bytes[..32].copy_from_slice(self.sk.as_bytes());
        bytes[32..(L_S + 32)].copy_from_slice(&self.s);
        bytes[(L_S + 32)..(L_S + 64)].copy_from_slice(self.pk.as_bytes());
        bytes[(L_S + 64)..].copy_from_slice(&self.pkh);
        bytes
    }

    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        let (sk, rest) = bytes.split_at(32);
        let (s, rest) = rest.split_at(L_S);
        let (pk, pkh) = rest.split_at(32);
        SecretKey {
            sk: Scalar::from_bytes_mod_order(sk.try_into().unwrap()),
            s: s.try_into().unwrap(),
            pk: MontgomeryPoint(pk.try_into().unwrap()),
            pkh: pkh.try_into().unwrap(),
        }
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
    let sk2 = SecretKey { sk, s, pk, pkh };
    (pk, sk2)
}

pub fn encaps(public_key: &MontgomeryPoint) -> (ElGamalCiphertext<PLAINTEXT_LEN>, [u8; F_OUT_LEN]) {
    let m = {
        let mut m = [0u8; PLAINTEXT_LEN];
        rand::thread_rng().fill(&mut m);
        ElGamalPlaintext::from_bytes(m)
    };

    // compute (r || k) = G2(G1(pk) || m)
    let h1 = {
        let mut h1 = [0u8; G1_OUT_LEN + PLAINTEXT_LEN];
        h1[..G1_OUT_LEN].copy_from_slice(&hash::<G1_OUT_LEN>(public_key.as_bytes()));
        h1[G1_OUT_LEN..].copy_from_slice(&m.as_bytes());
        h1
    };
    let rk = hash::<G2_OUT_LEN>(&h1);
    let (r, k) = {
        let (r, k) = rk.split_at(32);
        (Scalar::from_bytes_mod_order(r.try_into().unwrap()), k)
    };

    let c = elgamal_pke::encaps(&m, public_key, &r);

    let shared_key = {
        let mut d = [0u8; PLAINTEXT_LEN + G2_OUT_LEN]; // d = c || k
        d[..(PLAINTEXT_LEN + 32)].copy_from_slice(&c.as_bytes());
        d[(PLAINTEXT_LEN + 32)..].copy_from_slice(k);
        hash::<F_OUT_LEN>(&d)
    };

    (c, shared_key)
}

pub fn decaps(
    secret_key: &SecretKey,
    ciphertext: ElGamalCiphertext<PLAINTEXT_LEN>,
) -> [u8; F_OUT_LEN] {
    let m: ElGamalPlaintext<PLAINTEXT_LEN> = elgamal_pke::decaps(&ciphertext, &secret_key.sk);

    // r || k = G2(pkh || m)
    let rk = {
        let mut h1 = [0u8; G1_OUT_LEN + PLAINTEXT_LEN];
        h1[..G1_OUT_LEN].copy_from_slice(&secret_key.pkh);
        h1[G1_OUT_LEN..].copy_from_slice(&m.as_bytes());
        hash::<G2_OUT_LEN>(&h1)
    };
    let (r, k) = {
        let (r, k) = rk.split_at(32);
        (Scalar::from_bytes_mod_order(r.try_into().unwrap()), k)
    };

    let k_0 = {
        let mut d = [0u8; PLAINTEXT_LEN + G2_OUT_LEN]; // d = c || k
        d[..(PLAINTEXT_LEN + 32)].copy_from_slice(&ciphertext.as_bytes());
        d[(PLAINTEXT_LEN + 32)..].copy_from_slice(k);
        hash::<F_OUT_LEN>(&d)
    };

    let k_1 = {
        let mut d = [0u8; PLAINTEXT_LEN + G2_OUT_LEN]; // d = c || s
        d[..(PLAINTEXT_LEN + 32)].copy_from_slice(&ciphertext.as_bytes());
        d[(PLAINTEXT_LEN + 32)..].copy_from_slice(&secret_key.s);
        hash::<F_OUT_LEN>(&d)
    };

    let condition = {
        let c = elgamal_pke::encaps(&m, &secret_key.pk, &r);
        u8::from(c == ciphertext)
    };

    // return k0 if condition else k1 in constant time
    let mut shared_key = [0u8; F_OUT_LEN];
    for i in 0..F_OUT_LEN {
        shared_key[i] = k_0[i] * condition + k_1[i] * (1 - condition);
    }
    shared_key
}
