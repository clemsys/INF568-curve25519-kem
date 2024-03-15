use clap::Parser;
use curve25519_dalek::MontgomeryPoint;
use curve25519_kem::lib::{
    fo_kem::encaps,
    utils::{hex_decode, hex_encode},
};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(help = "32-byte hex-encoded public key")]
    public_key: String,
}

fn main() {
    let args = Args::parse();
    let (c, k) = encaps(&MontgomeryPoint(
        hex_decode(&args.public_key).try_into().unwrap(),
    ));
    println!("{}", hex_encode(&c.as_bytes()));
    println!("{}", hex_encode(&k))
}
