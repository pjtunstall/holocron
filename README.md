# Holocron

## What is this?

A program to encrypt and decrypt messages with a hybrid cryptosystem, combining a conventional key-exchange mechanism with one of the proposed, experimental post-quantum algorithms. In this way, in principle, messages should be at least as secure as they are with current, well-established methods, and hopefully also secure against even a powerful quantum computer.

## What's it for?

Fun. An exercise to help me learn Rust.

## Should I trust my life to it?

No! Don't expect this to be a secure cryptosystem. I'm an amateur in these matters. Look elsewhere for something you can rely on. Even some dependencies that implement the core algorithms have not yet been independently audited. One, the `rsa` crate (which actually handles the classical key exchange), describes itself as under construction and has open security issues.

## Usage

Make sure you have [Rust](https://www.rust-lang.org/tools/install) installed.

Clone this repository with `git clone https://github.com/pjtunstall/holocron`. Then navigate into the project directory with `cd holocron`, and run `cargo build --release` to compile. Navigate into the directory containing the compiled binary with `cd target/release` and run the program with `./holocron` as follows:

`./holocron -g bob` to generate keys for Bob and save them as `bob_secret.asc` and `bob_public.asc` in the `keys` folder, creating the `keys` folder if it doesn't already exist.

`./holocron -g bob` to generate keys for Bob and save them as `bob_secret.asc` and `bob_public.asc` in the folder `keys`, creating the folder `keys` if it doesn't exist.

`./holocron -eff hello.txt bob` to encrypt the message in `hello.txt` with the public key `bob_public.asc`, located in the folder `keys`, and save the resulting ciphertext to `hello.asc`.

`./holocron -etf "We're in a spot of bother." bob` to encrypt the given message for Bob with the public key `bob_public.asc`, located in the folder `keys`, and save the resulting ciphertext to `ciphertext.asc`.

`./holocron -ett "We're in a spot of bother." bob` to encrypt the given message for Bob with the public key `bob_public.asc`, located in the folder `keys`, and print the resulting ciphertext to the terminal.

`./holocron -dff hello.asc bob` to decrypt the message in `hello.asc` with the secret key `bob_secret.asc`, located in the folder `keys`, and save the resulting plaintext to `hello.txt`.

`./holocron -dft hello.asc bob` to decrypt the message in `hello.asc` with the secret key `bob_secret.asc`, located in the folder `keys`, and print the resulting plaintext to the terminal.

`./holocron -c` to clear all keys, i.e. delete the `keys` folder in the current directory.

Note that if you compile in debug mode with `cargo run`, you'll need to prefix any arguments with `--`, thus: `./holocron -- -g bob`.

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

For now, I'm using the pure-Rust implementations of the `ml_kem` crate (specifically ML-KEM1024) for the post-quantum key exchange and their `rsa` crate for the classical key exchange, `aes-gcm` (specifically AES-256-GCM) for symmetric encryption, and `sha2` (specifically SHA256) as a hash function for generating the ephemeral keys. They state that `ml_kem` has not yet been independently audited. At some point, I may switch to using the reference implementation of ML-KEM, which is written in C, or the `liboqs` version (also in C), based on that, and likewise look for a safer implementation of RSA, given the security issues mentioned in its [README](https://github.com/RustCrypto/RSA?tab=readme-ov-file#%EF%B8%8Fsecurity-warning).

## Further

Definitely to do:

- Structure: modularize, e.g. into `encryption`, `decryption`, `keys`, `options`, and maybe split the first two into their Kyber and RSA parts.
- Check variable names for consistency and expressiveness.
- Add more tests: of success and failure responses to each operation.

Possible further developments include:

Basic features:

- Add option to sign and verify messages.

Better key handling:

- Switch to SQLite storage: one table for public keys and one for private.
- Allow keys to be imported and deleted.
- Switch to accept `stdin` inputs.
- Encrypt database.

Better security:

- Check anywhere the stack needs to be explicitly cleaned with `zeroize`, including especially bytes from private keys. Some dependencies use `zeroize` when certain types are dropped, but I need to make sure I'm cleaning up anything else that requires it.
- Review security of the system: is concatenating the keys enough? Look into how Apple and Signal and Chrome are doing it.
- Switch to more reliable dependencies for the core algorithms.

UI:

- Rustle up some proper UI to replace the terminal interface.

Messaging:

- Build a messaging syste on top of it.
