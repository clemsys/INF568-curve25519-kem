use clap::Parser;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(help = "32-byte hex-encoded public key")]
    public_key: String,
}

fn main() {
    let args = Args::parse();
}
