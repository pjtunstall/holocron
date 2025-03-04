# Holocron

- [What is this?](#what-is-this)
- [What's it for?](#whats-it-for)
- [Should I trust my life/freedom/well-hodled bitcoins to it?](#should-i-trust-my-lifefreedomwell-hodled-bitcoins-to-it)
- [Usage](#usage)
- [In detail](#in-detail)
- [Possible further developments](#possible-further-developments)
  - [Basic features](#basic-features)
  - [Better key-handling](#better-key-handling)
  - [Better security](#better-security)
  - [UI](#ui)
  - [Messaging](#messaging)
  - [Tests](#tests)

## What is this?

Consider this a student coding exercise rather than a secure cryoptosystem. It's a command-line interface for encrypting and decrypting messages with a hybrid cryptosystem, combining a conventional key-exchange mechanism with one of the proposed, experimental post-quantum algorithms. The pupose of such a combination is that messages should be at least as safe as they are with current, well-established methods, and hopefully also secure against even a powerful quantum computer. However ...

WARNING: While RSA is, in principle secure, RustCrypto's implementation, on which this project depends has been [found vulnerable](https://github.com/RustCrypto/RSA/issues/19#issuecomment-1822995643) to the [Marvin Attack](https://people.redhat.com/~hkario/marvin/), a side-channel attack "that allows performing RSA decryption and signing operations as an attacker with the ability to observe only the time of the decryption operation performed with the private key." RustCrypto report that work is underway to resolve this and that it's only an issue in settings where attackers are able to observe timing information: "local use on a non-compromised computer is fine."[^1]

## Background

[Quantum computers](https://en.wikipedia.org/wiki/Quantum_computing) are a reality. Whether it takes 5 years or 30, eventually they'll be powerful enough to render current public-key cryptosystems ineffective. This is not just a concern for the future: data collected today may then be exposed.

If online banking, commerce, etc. are to survive, they'll need new methods of encryption. Several have been proposed. Some have proved ineffective even against classical computers, but a few possibilities remain. At present (late 2024), these potentially quantum-proof algorithms are not widely used, but it's likely that, in the near future, hybrid systems will become common. [Signal](https://signal.org/docs/specifications/pqxdh), [Apple](https://security.apple.com/blog/imessage-pq3/), [Cloudflare](https://blog.cloudflare.com/post-quantum-to-origins), [AWS](https://www.amazon.science/blog/preparing-today-for-a-post-quantum-cryptographic-future), [Firefox](https://www.mozilla.org/en-US/firefox/135.0/releasenotes/), and the latest [Chrome](https://blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html) desktop versions have all recently implemented systems that combine well-establish classical algorithms with a hopefully quantum-proof component.

UPDATE: See [here](https://blog.cloudflare.com/pq-2024/) for a detailed summary of the state of affairs in March 2024, and [here](https://www.netmeister.org/blog/pqc-2025-02.html) for a shorter summary from February 2025. To test whether your browser supports post-quantum encryption, check [here](https://pq.cloudflareresearch.com/) or [here](https://isitquantumsafe.info/).[^2]

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

Run `cargo test` to test the code.

## In detail

Cryptographic algorithms can be classified as either symmetric or asymmetric.

A symmetric algorithm is one where the same key is used to encrypt and decrypt. Symmetric algorithms are reletively fast. Their disadvantage is that if Alice wants to send a message to Bob, she needs a way to safely share that key.

Asymmetric (aka public-key) algorithms don't have this problem. In an asymmetric system, Bob creates a mathematically related pair of keys: a secret key and a public key. Bob makes his public key public. Anyone can use it to encrypt a message for him that he can then decrypt with his secret key, thanks to that mathematical relationship. The downside of asymmetric algorithms is that they're slow.

Modern cryptosystems, therefore, use an asymmetric algorithm to encrypt a symmetric key, which is then used to encrypt the message itself. Thus, Alice creates a symmetric key and encrypts her message with it. She encrypts the symmetric key with Bob's public key. She then sends the (asymmetrically encrypted) symmetric key along with the (symmetrically encrypted) message to Bob. Bob decrypts the symmetric key with his public key. Finally, he decrypts the message with the symmetric key.

Alice then sends the encrypted symmetric key and message to Bob. Bob decrypts the symmetric key with his secret key and uses it to decrypt the message.

This is the basic idea. Actual systems may include further subtleties. For example, asymemtric systems such a Diffie-Hellman use a combination of static (i.e. persistent) keys and ephemeral/session keys to ensure [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy). That is, to ensure that previous messages can't be read even if the notorious Eve gains access to Bob's static secret key.

Now, symmetric algorithms are thought to be resistant to quantum attack, provided a reasonably large key is used. It's the asymmetric algorithms that are at risk. The current standard, widely-used public-key exchange mechanisms, such as RSA, will be vulnerable when quantum computers reach a certain size. In the last couple of years, a few quantum-proof key-exchange mechanisms have been proposed, but it's early days and it could happen that flaws will be found. Already some supposedly quantum-proof algorithms, have been cracked with classical (non-quantum) techniques.

Given this situation, the first attempts at quantum-proof cryptosystems have combined well-established classical algorithms with the new, hopefully post-quantum algorithms, to ensure that they're no less secure than current systems. I've followed this pattern too. I've used RSA for the classical part of the key exchange and ML-KEM, also known as Kyber, for the post-quantum part.

In total, these are the algorithms I've used:

- Post-quantum asymmetric: formally ML-KEM-1024, aka (CRYSTALS-)[Kyber](https://en.wikipedia.org/wiki/Kyber)-1024
- Classical asymmetric: [RSA](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>)-4096
- Symmetric key generation: [SHA](https://en.wikipedia.org/wiki/Secure_Hash_Algorithms)-256
- Symmetric encryption/decryption: [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)-256-[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

The encrypted message consists of the following items concatenated:

- Kyber encapsulated key
- Kyber nonce
- RSA encapsulated key
- RSA nonce
- Message

For now, I'm using the pure-Rust implementations of the RustCrypto library's `ml_kem` crate (specifically ML-KEM-1024) for the post-quantum key exchange and their `rsa` crate for the classical key exchange (with a key size of 512 bytes), `aes-gcm` (specifically AES-256-GCM) for symmetric encryption, and `sha2` (specifically SHA-256) as a hash function for generating the symmetric key. At some point, I may switch to using the reference implementation of ML-KEM, which is written in C, or the `liboqs` version (also in C), based on that.

Similarly, I may look for a safer implementation of RSA. Besides the issue mentioned above, RustCrypto describe their `rsa` crate as under construction and caution that it hasn't been independently audited yet. Even better, I could switch to an elliptic curve algorithm, given the many [ways to use RSA insecurely](https://paragonie.com/blog/2018/04/protecting-rsa-based-protocols-against-adaptive-chosen-ciphertext-attacks).

## Possible further developments

### Basic features

- Add option to sign and verify messages.

### Better key-handling

- Switch to SQLite storage: one table for public keys and one for private.
- Allow keys to be imported and deleted.
- Switch to accept `stdin` inputs.
- Encrypt database.

### Better security

- Switch to more reliable dependencies for the cryptographic algorithms.
- Check anywhere the stack needs to be explicitly cleaned with `zeroize`, including especially bytes from private keys. Some dependencies use `zeroize` when certain types are dropped, but I need to make sure I'm cleaning up anything else that requires it.
- Review security of the system. Look more closely into how Apple, Signal, Chrome, Cloudflare etc. are doing it.
- Consider Elliptic-Curve Diffie-Hellman for the classical key exchange.

### UI

- Rustle up some proper UI to replace the terminal interface.

### Messaging

- Build a messaging system on top of it.

### Tests

- Make integration tests for each of the options to replace the current single integration test (and maybe repurpose some bits of the latter as unit tests), then all modules declared in `lib.rs`, except for `options`, can be made private.
- Add unit tests. Test success and failure responses to each operation. Although the current integration test verifies that the core system successfully encrypts and decrypts, and hence that its components work, it could be useful to add finer grained tests before making radical changes to any of those parts, such as replacing dependencies with other implementations of the cryptographic algorithms, or indeed switching to other algorithms.
- Look into ways to test the actual security of the system.

[^1]: [Marvin Attack: potential key recovery through timing sidechannels #1](https://github.com/pjtunstall/holocron/security/dependabot/1)
[^2]: Even if supported, post-quantum cryptography may not be the default. For example, as of February 2025, Chrome and Firefox both use the hybrid algorithm X25519MLKEM768, but in Chrome it needs to be explicitly enabled with two flags, `chrome://flags/#enable-tls13-kyber` and `chrome://flags/#use-ml-kem`. In Firefox, enter `about:config` into the search bar, then select `security.tls.enable_kyber` and `network.http.http3.enable_kyber`; you can use Bas Westerbaan's [PQSpy](https://addons.mozilla.org/en-GB/firefox/addon/pqspy/) add-on to verify that post-quantum encryption is enabled.
