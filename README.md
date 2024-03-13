# INF568 Assignment 9 - curve25519-based KEM

Author: [Clément CHAPOT](mailto:clement.chapot@polytechnique.edu)<br>
Description: KEM derived from a basic ElGamal-style PKE using curve25519 by apply the FO transformation as part of INF568 course at École polytechnique

## Building

Build the project using `make`.

This calls `cargo build --release` and copies the three binaries `keygen`, `encaps` and `decaps` from `target/release/` into the project root.

## Usage

- `./keygen <PRIVATE_KEY_FILE>` generates a KEM key pair, prints the public key on `stdout` and stores the private key in `<PRIVATE_KEY_FILE>`

For more precise usage information, use `--help` on the relevant binary.

## Project structure

The core of the project can be found in `src/lib/`.

Files in `src/bin/` are only here to produce the binaries, so they mostly contain a main function, which calls functions from `src/lib/` directly.
