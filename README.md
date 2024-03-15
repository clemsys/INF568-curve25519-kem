# INF568 Assignment 9 - curve25519-based KEM

Author: [Clément CHAPOT](mailto:clement.chapot@polytechnique.edu)<br>
Description: KEM targeting 128-bit security, derived from a basic hash-ElGamal-style PKE using curve25519 by apply the FO transformation. This project was done as part of INF568 course at École polytechnique

## Building

Build the project using `make`.

This calls `cargo build --release` and copies the three binaries `keygen`, `encaps` and `decaps` from `target/release/` into the project root.

## Usage

- `./keygen <PRIVATE_KEY_FILE>` generates a KEM key pair, prints the public key on `stdout` and stores the private key in `<PRIVATE_KEY_FILE>`
- `./encaps <PUBLIC_KEY>` generates a N-byte ciphertext and a 16-byte symmetric encryption key from a 32-byte hex-encoded public key, and prints them both on separate lines, in a hex-encoded format
- `./decaps <PRIVATE_KEY_FILE> <CIPHERTEXT>` generates a 16-byte symmetric encryption key from a private key (generated with `./keygen`) and a N-byte ciphertext, and prints it in a hex-encoded format

For more precise usage information, use `--help` on the relevant binary.

## Project structure

The core of the project can be found in `src/lib/`.

Files in `src/bin/` are only here to produce the binaries, so they mostly contain a main function, which calls functions from `src/lib/` directly.

A basic hash-ElGamal-style PKE is implemented in `src/liblelgamal_pke.rs`. It is used to construct an IND-CCA2-secure PKE in `src/lib/fo_kem.rs` thanks to the _Fujisaki–Okamoto (FO) Transform_.

## Design choices

The hash functions _G_1_, _G_2_ and _F_ of the FO transform are all implemented using _shake128_, from the `sha3` crate.

The hash-ElGamal-style PKE uses _Chacha20_, from the `chacha20` crate, to encrypt the plaintext using a symmetric key derived from the hash of the shared_secret.

The _Montgomery arithmetic_ is implemented using functions, constants and types provided by the `curve25519-dalek` crate.
