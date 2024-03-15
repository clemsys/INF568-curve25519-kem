use clap::Parser;
use curve25519_kem::lib::{
    elgamal_pke::ElGamalCiphertext,
    fo_kem::{decaps, SecretKey},
    utils::{hex_decode, hex_encode},
};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(help = "Name of the file containing the private key")]
    private_key_file: String,

    #[arg(help = "32-byte hex-encoded ciphertext")]
    ciphertext: String,
}

fn main() {
    let args = Args::parse();

    let secret_key = std::fs::read(&args.private_key_file)
        .unwrap_or_else(|_| {
            eprintln!("Error reading private key file");
            std::process::exit(1);
        })
        .try_into()
        .unwrap_or_else(|_| {
            eprintln!("Invalid private key file");
            std::process::exit(1);
        });

    let sym_key = decaps(
        &SecretKey::from_bytes(secret_key),
        ElGamalCiphertext::from_bytes(&hex_decode(&args.ciphertext)),
    );
    println!("{}", hex_encode(&sym_key))
}
