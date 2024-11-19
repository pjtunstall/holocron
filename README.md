# Holocron

## What is this?

A program that will eventually allow the user to encrypt and decrypt messages with a hybrid cryptosystem, combining a conventional key-exchange mechanism with one of the proposed, experimental post-quantum algorithms. In this way, messages should be at least as secure as they are with current, well-established methods, and hopefully also secure against even a powerful quantum computer.

## What is it for?

Primarily a learning exercise: learning Rust and hopefully picking up some cybersecurity concepts along the way; a proof of concept; fun. I'm not a security expert, so please don't rely on it.

For now, I'm using the pure-Rust implementations of the `ml_kem` crate (specifically ML-KEM1024) for the post-quantum key exchange and their `p256` crate for the classical key exchange, `aes-gcm` (specifically AES256-GCM) for symmetric encryption and `sha2` (specifically SHA256) as a hash function for generating the ephemeral keys. They state that `ml_kem` and `p256` have not yet been independently audited. At some point, until they have been verified, I may temporarily switch to using the reference implementation of ML-KEM, which is written in C, or the `liboqs` version (also in C), based on that, and likewise look for better-verified versions of p256 and any other algorithms I end up using that RustCrypto warns have not been independently checked.

## What state is it in?

Under construction. Early days. So far, I've just set up a little demo of the purely post-quantum system ML-KEM, aka Kyber. Yet to do:

- Turn prototype with hardcoded message into unit tests, adding tests for success and failure, then continue writing tests as I go along.
- Check hyphenation conventions of algorithm names.
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

## In detail

For now, I'm going to concatenate three items: two ephemeral keys, one encrypted with the post-quantum algorithm and the other with the conventional system, and finally the cyphertext itself, encrypted with both systems. There will be a divider between each item. This may well be a naive approach. It's something to get started with. Eventually, I'll compare how the professionals are doing it.

I'm using the following algorithms:

- Post-quantum asymmetric: ML-KEM-1024, aka Kyber
- Classical aymmetric: P-256 (Elliptic Curve Diffie-Hellman)
- Ephemeral key generation: SHA-256
- Symmetric: AES-256 GCM
