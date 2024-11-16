# Holocron

## What is this?

A program that will allow the user to encrypt and decrypt messages with a hybrid system, combining a conventional cryptosystem with one of the proposed, experimental post-quantum systems. In this way, messages should be at least as secure as they are with current, well-established methods, and hopefully also secure against even a powerful quantum computer.

## What is it for?

Primarily a learning exercise: learning Rust and hopefully picking up some cybersecurity concepts along the way; a proof of concept; fun. I'm not a security expert, so please don't rely on it.

For now, I'm using the pure-Rust implementations of the `ml_kem` crate for the post-quantum key exchange amd their `p256` crate for the classical key exchange, `aes-gcm` for symmetric encryption and `sha2` for key derivation. They state that `ml_kem` and `p256` have not yet been independently audited. At some point, until they have been verified, I may temporarily switch to using the reference implementation of ML-KEM, which is written in C, or the `liboqs` version (also in C), based on that, and likewise look for better-verified versions of p256 and any other algorithms I use that RustCrypto warns have not been independently checked.

## What state is it in?

Under construction. Early days. So far, I've just set up a little demo of the purely post-quantum system ML-KEM, aka Kyber. Yet to do:

- Start separating code into functions.
- Generate two quantum key pairs, one for Alice and one for Bob.
- Add classical p256.
- Accept command-line arguments and store public and private keys in text files.
- Use `zeroize` crate to wipe memory before dropping variables.
- Switch to SQLite storage: one table for public keys and one for private.
- Allow keys to be imported and deleted.
- Switch to accept stdin inputs.
- Encrypt database.
- Add signature option and verification.
- Rustle up some proper UI to replace the terminal interface.
- Review security of the system: is there a better way to combine the keys than simply concatenating them? Look into how Apple and Signal and Chrome are doing it.
