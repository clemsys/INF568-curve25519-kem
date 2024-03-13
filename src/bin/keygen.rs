use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(help = "Name of the file in which the private key should be stored")]
    private_key_file: String,
}

fn main() {
    let args = Args::parse();
}
