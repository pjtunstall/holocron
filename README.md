# Holocron

## What is this?

A command-line interface for encrypting and decrypting messages with a hybrid cryptosystem, combining a conventional key-exchange mechanism with one of the proposed, experimental post-quantum algorithms. In this way, in principle, messages should be at least as safe as they are with current, well-established methods, and hopefully also secure against even a powerful quantum computer.

## What's it for?

Fun. An exercise to help me learn Rust. Maybe also, in some small way, to raise awareness.

(https://en.wikipedia.org/wiki/Quantum_computing)[Quantum computers] are a reality. Whether it takes 5 years or 30, eventually they'll be big enough to render current public-key cryptosystems ineffective. This is not just a concern for the future: data collected today may then be exposed to prying eyes.

If online banking, commerce, etc. are to survive, they'll need new systems. Several have been proposed. Some have proved ineffective even against classical computers, but a few possibilities remain. At present (late 2024), these potentially quantum-proof algorithms are not widely used, but it's likely that, in the near future, hybrid systems will become common. [Signal](https://signal.org/docs/specifications/pqxdh/), [https://security.apple.com/blog/imessage-pq3/](Apple), and the latest [Chrome](https://blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html) desktop versions have all recently implemented systems that combine well-establish classical algorithms with a hopefully quantum-proof component.

This project is my attempt.

## Should I trust my life to it?

No! Don't expect this to be a secure cryptosystem. I'm an amateur in these matters. Look elsewhere for something you can rely on. Even some dependencies that implement the core algorithms have not yet been independently audited. One, the `rsa` crate (which actually handles the classical key exchange), describes itself as under construction and has open security issues. As I learn more, I hope to improve it, but, for now and the foreseeable future, consider it just a learning exercise.

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

Cryptographic algorithms can be classified as either symmetric or asymmetric.

A symmetric algorithm is one where the same key is used to encrypt and decrypt. Symmetric algorithms are reletively fast. Their disadvantage is that if Alice wants to send a message to Bob, she needs a way to safely share that key.

Asymmetric (aka public-key) algorithms don't have this problem. In an asymmetric system, Bob creates a mathematically related pair of keys: a secret key and a public key. Bob makes his public key public. Anyone can use it to encrypt a message for him that he can then decrypt with his secret key, thanks to that mathematical relationship. The downside of asymmetric algorithms is that they're slow.

Modern cryptosystems, therefore, use an asymmetric algorithm to encrypt a symmetric key, which is then used to encrypt the message itself. Thus, Alice creates a symmetric key and encrypts her message with it. She encrypts the symmetric key with Bob's public key. She then sends the (asymmetrically encrypted) symmetric key along with the (symmetrically encrypted) message to Bob. Bob decrypts the symmetric key with his public key. Finally, he decrypts the message with the symmetric key.

Alice then sends the encrypted symmetric key and message to Bob. Bob decrypts the symmetric key with his secret key and uses it to decrypt the message.

This is the basic idea. Actual systems may include further subtleties. For example, asymemtric systems often use a combination of static (i.e. persistent) keys and ephemeral/session keys to ensure [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy). That is, to ensure that previous messages can't be read even if the notorious Eve gains access to Bob's static secret key.

Now, symmetric algorithms are thought to be resistant to quantum attack, provided a reasonably large key is used. It's the asymmetric algorithms that are at risk. The current standard, widely-used public-key exchange mechanisms, such as RSA, will be vulnerable when quantum computers reacha certain size. In the last couple of years, a few quantum-proof key-exchange mechanisms have been proposed, but it's early days and it's possible that flaws will be found. Already some supposedly quantum-proof algorithms, have been cracked with classical (non-quantum) techniques.

Given this situation, the first attempts at quantum-proof cryptosystems have combined well-established classical algorithms with the new, hopefully post-quantum algorithms, to ensure that they're no less secure than current systems. I've followed this pattern too. My system uses RSA for the classical part of the key exchange and ML-KEM, also known as Kyber, for the post-quantum part.

In total, these are the algorithms I've used:

- Post-quantum asymmetric: formally ML-KEM, aka (CRYSTALS-)Kyber
- Classical aymmetric: RSA
- Symmetric key generation: SHA-256
- Symmetric encryption/decryption: AES-256-GCM

The encrypted message consists of the following items concatenated:

- Kyber encapsulated key
- Kyber nonce
- RSA encapsulated key
- RSA nonce
- Message

For now, I'm using the pure-Rust implementations of the RustCrypto library's `ml_kem` crate (specifically ML-KEM-1024) for the post-quantum key exchange and their `rsa` crate for the classical key exchange, `aes-gcm` (specifically AES-256-GCM) for symmetric encryption, and `sha2` (specifically SHA256) as a hash function for generating the symmetric key. RustCrypto state that `ml_kem` has not yet been independently audited. At some point, I may switch to using the reference implementation of ML-KEM, which is written in C, or the `liboqs` version (also in C), based on that, and likewise look for a safer implementation of RSA, given the security issues mentioned in its [README](https://github.com/RustCrypto/RSA?tab=readme-ov-file#%EF%B8%8Fsecurity-warning).

## Todo

- Add more tests: of success and failure responses to each operation. Test the various options, including encrypting from and to a file.

## Possible further developments

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
