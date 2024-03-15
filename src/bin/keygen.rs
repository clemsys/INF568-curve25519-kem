use clap::Parser;
use curve25519_kem::lib::fo_kem::keygen;
use curve25519_kem::lib::utils::hex_encode;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(help = "Name of the file in which the private key should be stored")]
    private_key_file: String,
}

fn main() {
    let args = Args::parse();

    let (pk, sk) = keygen();

    std::fs::write(args.private_key_file, sk.as_bytes()).unwrap_or_else(|_| {
        eprintln!("Error writing private key file");
        std::process::exit(1);
    });
    println!("{}", hex_encode(pk.as_bytes()));
}
