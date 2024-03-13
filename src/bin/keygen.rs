use clap::Parser;
use curve25519_kem::lib::kem;
use std::fmt::Write;

// TODO : add description

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(help = "Name of the file in which the private key should be stored")]
    private_key_file: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02X}");
        output
    })
}

fn main() {
    let args = Args::parse();

    let (pk, sk) = kem::keygen::keygen();

    std::fs::write(args.private_key_file, sk.as_bytes()).unwrap();
    println!("{}", hex_encode(pk.as_bytes()));
}
