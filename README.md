# Holocron

## What is this?

A program to encrypt and decrypt messages with a hybrid cryptosystem, combining a conventional key-exchange mechanism with one of the proposed, experimental post-quantum algorithms. In this way, messages should be at least as secure as they are with current, well-established methods, and hopefully also secure against even a powerful quantum computer.

## Usage

Follow GitHub's unstructions to clone this repository. Then `cd holocron`, and run `cargo build --release` to compile. Then `cd target/release` and run `./holocron` to run the program as follows:

`./holocron -g alice` to generate keys for Alice and save them as `alice_sec.asc` and `alice_pub.asc`.

`./holocron -e "We're in a spot of bother." bob` to encrypt a message for Bob and print the resulting wire message.

`./holocron -ef plaintext bob` to encrypt the message in `plaintext.txt` or `ciphertext.asc` with the public key `bob_pub.asc`.

`./holocron -df ciphertext bob` to decrypt the message in `ciphertext.asc` with the secret key `bob_sec.asc`.

## What is it for?

Primarily a learning exercise. I'm not a security expert, so please don't rely on it. Some dependencies that implement the core algorithms have not yet been independently audited. One describes itself as under construction and has open security issues.

For now, I'm using the pure-Rust implementations of the `ml_kem` crate (specifically ML-KEM1024) for the post-quantum key exchange and their `rsa` crate for the classical key exchange, `aes-gcm` (specifically AES256-GCM) for symmetric encryption, and `sha2` (specifically SHA256) as a hash function for generating the ephemeral keys. They state that `ml_kem` has not yet been independently audited. At some point, I may switch to using the reference implementation of ML-KEM, which is written in C, or the `liboqs` version (also in C), based on that, and likewise look for a safer implementation of RSA, given the security issues mentioned in its [README](https://github.com/RustCrypto/RSA?tab=readme-ov-file#%EF%B8%8Fsecurity-warning).

## What state is it in?

I've just set up a demo with a hardcoded message. Yet to do:

- Turn prototype with hardcoded message into an integration test. Add tests for success and failure of each operation.
- Add logic for reading and writing keys to files.
- Accept command-line arguments.
- Store public and private keys in text files.

## In detail

I'm using the following algorithms:

- Post-quantum asymmetric: ML-KEM-1024, aka Kyber
- Classical aymmetric: RSA
- Ephemeral key generation: SHA-256
- Symmetric: AES-256-GCM

The encrypted message consists of the following items concatenated:

- Kyber encapsulated key
- Kyber nonce
- RSA encapsulated key
- RSA nonce
- Message

Note that the `zeroize` crate is being used by the RustCrypto library to wipe memory before dropping variables.

## Further

Possible further developments include:

- Switch to SQLite storage: one table for public keys and one for private.
- Allow keys to be imported and deleted.
- Switch to accept `stdin` inputs.
- Encrypt database.
- Add signature option and verification.
- Rustle up some proper UI to replace the terminal interface.
- Review security of the system: is there a better way to combine the keys than simply concatenating them? Look into how Apple and Signal and Chrome are doing it.
