use x25519_dalek::{PublicKey, StaticSecret};

pub fn gen_sk() -> StaticSecret {
    StaticSecret::random()
}

pub fn gen_pk(sk: &StaticSecret) -> PublicKey {
    sk.into()
}
