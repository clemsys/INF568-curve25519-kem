use x25519_dalek::{PublicKey, StaticSecret};

fn gen_sk() -> StaticSecret {
    StaticSecret::random()
}

fn gen_pk(sk: &StaticSecret) -> PublicKey {
    sk.into()
}

pub fn keygen() -> (PublicKey, StaticSecret) {
    let sk = gen_sk();
    (gen_pk(&sk), sk)
}
