use crate::lib::pke;
use rand::Rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use x25519_dalek::PublicKey;

const L_S: usize = 32; // 32 bits
const G1_OUT_LEN: usize = 32; // number of output bytes for G1
const STATIC_SECRET_LEN: usize = L_S + G1_OUT_LEN + 64;

pub struct StaticSecret(
    x25519_dalek::StaticSecret,
    [u8; L_S],
    PublicKey,
    [u8; G1_OUT_LEN],
);

impl StaticSecret {
    pub fn as_bytes(&self) -> [u8; STATIC_SECRET_LEN] {
        let mut bytes = Vec::with_capacity(STATIC_SECRET_LEN);
        // add self.0, self.1, self.2, self.3 to bytes
        bytes.extend_from_slice(self.0.as_bytes());
        bytes.extend_from_slice(&self.1);
        bytes.extend_from_slice(self.2.as_bytes());
        bytes.extend_from_slice(&self.3);
        bytes.try_into().unwrap()
    }
}

pub fn keygen() -> (PublicKey, StaticSecret) {
    let (pk, sk) = pke::keygen::keygen();

    let s = {
        let mut s = [0u8; L_S];
        rand::thread_rng().fill(&mut s);
        s
    };

    let pkh: [u8; G1_OUT_LEN] = {
        let mut hasher = Shake128::default();
        hasher.update(pk.as_bytes());
        let mut reader = hasher.finalize_xof();
        let mut pkh = vec![0u8; G1_OUT_LEN];
        reader.read(&mut pkh);
        pkh.try_into().unwrap()
    };

    let sk2 = StaticSecret(sk, s, pk, pkh);
    (pk, sk2)
}
