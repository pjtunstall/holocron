#![allow(dead_code)]

use aes_gcm::{
    aead::{Aead, KeyInit},
    {Aes256Gcm, Nonce},
};
use base64ct::{Base64, Encoding};
use generic_array::GenericArray;
use hkdf::Hkdf;
use hybrid_array::Array;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use rand_core::{OsRng, RngCore};
use rsa::{
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::env;
use std::fs;
use std::fs::{create_dir, read_to_string, File};
use std::io;
use std::io::{Read, Write};
use std::path::Path;

// ----- Encryption side errors -----

#[derive(Debug)]
enum EncryptionError {
    KyberError(String),
    AesError(String),
    KeyDerivationError(String),
    RsaError(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::KyberError(e) => write!(f, "Kyber operation failed: {}", e),
            EncryptionError::AesError(e) => write!(f, "AES encryption failed: {}", e),
            EncryptionError::KeyDerivationError(e) => write!(f, "Key derivation failed: {}", e),
            EncryptionError::RsaError(e) => write!(f, "RSA operation failed: {}", e),
        }
    }
}

impl std::error::Error for EncryptionError {}

// ----- Decryption side errors -----

#[derive(Debug)]
enum DecryptionError {
    Base64Error(base64ct::Error),
    InvalidFormat,
    Utf8Error(std::string::FromUtf8Error),
    AesError(String),
    KyberError(String),
    RsaError(String),
    KeyDerivationError(String),
}

impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptionError::Base64Error(e) => write!(f, "Base64 decoding error: {}", e),
            DecryptionError::InvalidFormat => write!(f, "Invalid message format"),
            DecryptionError::Utf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
            DecryptionError::AesError(e) => write!(f, "Decryption error: {}", e),
            DecryptionError::KyberError(e) => write!(f, "Kyber operation failed: {}", e),
            DecryptionError::RsaError(e) => write!(f, "rsa operation failed: {}", e),
            DecryptionError::KeyDerivationError(e) => write!(f, "Key derivation failed: {}", e),
        }
    }
}

impl std::error::Error for DecryptionError {}

impl From<EncryptionError> for DecryptionError {
    fn from(err: EncryptionError) -> Self {
        DecryptionError::KeyDerivationError(err.to_string())
    }
}

impl From<base64ct::Error> for DecryptionError {
    fn from(err: base64ct::Error) -> Self {
        DecryptionError::Base64Error(err)
    }
}

impl From<std::string::FromUtf8Error> for DecryptionError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        DecryptionError::Utf8Error(err)
    }
}

impl From<&'static str> for DecryptionError {
    fn from(error: &'static str) -> Self {
        DecryptionError::RsaError(error.to_string())
    }
}

// ----- Key generation -----

fn generate_kyber_keys() -> (
    DecapsulationKey<MlKem1024Params>,
    EncapsulationKey<MlKem1024Params>,
) {
    MlKem1024::generate(&mut OsRng)
}

fn generate_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let secret_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&secret_key);
    (secret_key, public_key)
}

// ----- Encryption functions -----

fn kyber_encapsulate_key(
    kyber_ek: &EncapsulationKey<MlKem1024Params>,
) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    kyber_ek
        .encapsulate(&mut OsRng)
        .map(|(secret, shared)| (secret.to_vec(), shared.to_vec()))
        .map_err(|e| EncryptionError::KyberError(format!("{:?}", e)))
}

fn rsa_encapsulate_key(rsa_ek: &RsaPublicKey) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    let mut aes_key: [u8; 32] = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut aes_key);
    let encrypted_aes_key = rsa_ek
        .encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key)
        .map_err(|e| EncryptionError::RsaError(e.to_string()))?;
    Ok((encrypted_aes_key, aes_key.to_vec()))
}

fn derive_aes_key(shared_secret: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"aes256gcm key", &mut okm)
        .map_err(|e| EncryptionError::KeyDerivationError(e.to_string()))?;
    Ok(okm.to_vec())
}

fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    let mut rng = OsRng;
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| EncryptionError::AesError(e.to_string()))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

fn format_wire_message(
    kyber_encapsulated_secret: &[u8],
    kyber_nonce: &[u8],
    rsa_encapsulated_secret: &[u8],
    rsa_nonce: &[u8],
    ciphertext: &[u8],
) -> String {
    let mut combined = Vec::new();
    combined.extend_from_slice(kyber_encapsulated_secret);
    combined.extend_from_slice(kyber_nonce);
    combined.extend_from_slice(rsa_encapsulated_secret);
    combined.extend_from_slice(rsa_nonce);
    combined.extend_from_slice(ciphertext);
    Base64::encode_string(&combined)
}

fn encrypt(
    plaintext: &[u8],
    kyber_ek: &EncapsulationKey<MlKem1024Params>,
    rsa_ek: &RsaPublicKey,
) -> Result<String, EncryptionError> {
    let (kyber_encapsulated_secret, kyber_shared_secret) = kyber_encapsulate_key(kyber_ek)?;
    let kyber_aes_encryption_key = derive_aes_key(&kyber_shared_secret)?;
    let (kyber_nonce, kyber_ciphertext) = aes_encrypt(&kyber_aes_encryption_key, plaintext)?;

    let (rsa_encapsulated_secret, rsa_shared_secret) = rsa_encapsulate_key(rsa_ek)?;
    let rsa_aes_encryption_key = derive_aes_key(&rsa_shared_secret)?;
    let (rsa_nonce, ciphertext) = aes_encrypt(&rsa_aes_encryption_key, &kyber_ciphertext)?;

    Ok(format_wire_message(
        &kyber_encapsulated_secret,
        &kyber_nonce,
        &rsa_encapsulated_secret,
        &rsa_nonce,
        &ciphertext,
    ))
}

// ----- Decryption functions -----

struct WireMessage {
    kyber_encapsulated_secret: Vec<u8>,
    kyber_nonce: Vec<u8>,
    rsa_encapsulated_secret: Vec<u8>,
    rsa_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn parse_wire_message(wire_message: &str) -> Result<WireMessage, DecryptionError> {
    let kyber_key_length: usize = 1568;
    let aes_nonce_length: usize = 12;
    let rsa_key_length: usize = 256;

    let kyber_key_plus_nonce_length: usize = kyber_key_length + aes_nonce_length;
    let rsa_key_plus_nonce_length: usize = rsa_key_length + aes_nonce_length;

    let bytes = Base64::decode_vec(wire_message)?;
    if bytes.len() < 1568 + 24 + 256 {
        return Err(DecryptionError::InvalidFormat);
    }

    let kyber_encapsulated_secret = bytes[0..kyber_key_length].to_vec();
    let kyber_nonce = bytes[kyber_key_length..kyber_key_plus_nonce_length].to_vec();

    let rsa_encapsulated_secret =
        bytes[kyber_key_plus_nonce_length..kyber_key_plus_nonce_length + rsa_key_length].to_vec();
    let rsa_nonce = bytes[kyber_key_plus_nonce_length + rsa_key_length
        ..kyber_key_plus_nonce_length + rsa_key_plus_nonce_length]
        .to_vec();
    let ciphertext =
        bytes[kyber_key_plus_nonce_length + rsa_key_length + aes_nonce_length..].to_vec();

    Ok(WireMessage {
        kyber_encapsulated_secret,
        kyber_nonce,
        rsa_encapsulated_secret,
        rsa_nonce,
        ciphertext,
    })
}

fn prepare_kyber_secret(bytes: &[u8]) -> Array<u8, <MlKem1024 as ml_kem::KemCore>::CiphertextSize> {
    let mut array = Array::default();
    array.copy_from_slice(bytes);
    array
}

fn kyber_decapsulate_key(
    kyber_dk: &DecapsulationKey<MlKem1024Params>,
    encapsulated_secret: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    let kyber_secret = prepare_kyber_secret(encapsulated_secret);
    kyber_dk
        .decapsulate(&kyber_secret)
        .map(|secret| secret.to_vec())
        .map_err(|e| DecryptionError::KyberError(format!("{:?}", e)))
}

fn rsa_decapsulate_key(
    rsa_dk: &RsaPrivateKey,
    encapsulated_secret: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    let decrypted_aes_key = rsa_dk
        .decrypt(Pkcs1v15Encrypt, &encapsulated_secret)
        .map_err(|e| DecryptionError::RsaError(e.to_string()))?;
    Ok(decrypted_aes_key)
}

fn aes_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    cipher.decrypt(nonce, ciphertext.as_ref())
}

fn decrypt(
    wire_message: &str,
    kyber_dk: &DecapsulationKey<MlKem1024Params>,
    rsa_dk: &RsaPrivateKey,
) -> Result<String, DecryptionError> {
    let message = parse_wire_message(wire_message)?;

    let rsa_shared_secret: Vec<u8> = rsa_decapsulate_key(rsa_dk, &message.rsa_encapsulated_secret)
        .map_err(|e| DecryptionError::RsaError(e.to_string()))?;
    let rsa_aes_decryption_key = derive_aes_key(&rsa_shared_secret)?;

    let rsa_plaintext = aes_decrypt(
        &rsa_aes_decryption_key,
        &message.rsa_nonce,
        &message.ciphertext,
    )
    .map_err(|e| DecryptionError::AesError(e.to_string()))?;

    let kyber_shared_secret = kyber_decapsulate_key(kyber_dk, &message.kyber_encapsulated_secret)?;
    let kyber_aes_decryption_key = derive_aes_key(&kyber_shared_secret)?;

    let plaintext = aes_decrypt(
        &kyber_aes_decryption_key,
        &message.kyber_nonce,
        &rsa_plaintext,
    )
    .map_err(|e| DecryptionError::AesError(e.to_string()))?;

    String::from_utf8(plaintext).map_err(DecryptionError::Utf8Error)
}

fn generate_keys(
    username: &str,
) -> Result<
    (
        EncapsulationKey<MlKem1024Params>,
        DecapsulationKey<MlKem1024Params>,
        RsaPublicKey,
        RsaPrivateKey,
    ),
    std::io::Error,
> {
    let (kyber_dk, kyber_ek) = generate_kyber_keys();
    let (rsa_dk, rsa_ek) = generate_rsa_keys();

    save_keys(username, &kyber_dk, &kyber_ek, &rsa_dk, &rsa_ek)?;

    Ok((kyber_ek, kyber_dk, rsa_ek, rsa_dk))
}

fn save_keys(
    username: &str,
    kyber_dk: &DecapsulationKey<MlKem1024Params>,
    kyber_ek: &EncapsulationKey<MlKem1024Params>,
    rsa_dk: &RsaPrivateKey,
    rsa_ek: &RsaPublicKey,
) -> io::Result<()> {
    if !Path::new("keys").is_dir() {
        create_dir("keys")?;
    }

    let kyber_dk_bytes: &[u8] = &kyber_dk.as_bytes().to_vec();
    let kyber_ek_bytes: &[u8] = &kyber_ek.as_bytes().to_vec();

    let binding = rsa_dk.to_pkcs8_der().unwrap();
    let rsa_dk_bytes = binding.as_bytes();
    let binding = rsa_ek.to_public_key_der().unwrap();
    let rsa_ek_bytes = binding.as_bytes();

    assert_eq!(kyber_dk_bytes.len(), 3168, "kyber_dk length != 3168");
    assert_eq!(kyber_ek_bytes.len(), 1568, "kyber_ek length != 1568");

    let mut secret_key = Vec::new();
    secret_key.extend_from_slice(kyber_dk_bytes);
    secret_key.extend_from_slice(rsa_dk_bytes);

    let mut public_key = Vec::new();
    public_key.extend_from_slice(kyber_ek_bytes);
    public_key.extend_from_slice(rsa_ek_bytes);

    let mut s = String::new();
    s.push_str("-----BEGIN HOLOCRON SECRET KEY-----\n\n");
    s.push_str(&Base64::encode_string(&secret_key));
    s.push_str("\n\n-----END HOLOCRON PRIVATE KEY-----");
    let mut file = File::create(format!("keys/{}_secret_key.asc", username))?;
    file.write_all(s.as_bytes())?;

    s.clear();
    s.push_str("-----BEGIN HOLOCRON PUBLIC KEY-----\n\n");
    s.push_str(&Base64::encode_string(&public_key));
    s.push_str("\n\n-----END HOLOCRON PUBLIC KEY-----");
    file = File::create(format!("keys/{}_public_key.asc", username))?;
    file.write_all(s.as_bytes())?;

    Ok(())
}

fn parse_public_key(
    path: &str,
) -> Result<(EncapsulationKey<MlKem1024Params>, RsaPublicKey), std::io::Error> {
    let mut file = File::open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let trimmed = contents
        .strip_prefix("-----BEGIN HOLOCRON PUBLIC KEY-----\n\n")
        .unwrap()
        .strip_suffix("\n\n-----END HOLOCRON PUBLIC KEY-----")
        .unwrap();

    let bytes = Base64::decode_vec(&trimmed).unwrap();
    let kyber_bytes = bytes[..1568].to_vec();
    let rsa_bytes = bytes[1568..].to_vec();

    let kyber_array: [u8; 1568] = kyber_bytes[..].try_into().expect("Wrong length");
    let encoded = Encoded::<EncapsulationKey<MlKem1024Params>>::from(kyber_array);
    let kyber_ek = EncapsulationKey::<MlKem1024Params>::from_bytes(&encoded);

    let rsa_ek =
        RsaPublicKey::from_public_key_der(&rsa_bytes).expect("Failed to decode RSA public key");

    Ok((kyber_ek, rsa_ek))
}

fn confirm_deletion() -> bool {
    let current_dir = env::current_dir().unwrap();
    let dir_name = current_dir.file_name().unwrap_or_default();

    let mut input = String::new();
    print!(
        "Are you sure you want to delete all keys in {}? (Y/N): ",
        dir_name.to_str().unwrap_or("unknown")
    );
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();

    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => true,
        _ => false,
    }
}

fn delete_keys_folder() -> Result<(), std::io::Error> {
    let current_dir = env::current_dir()?;
    println!("Current working directory: {}", current_dir.display());

    let folder_path = current_dir.join("keys");
    println!("Checking path: {}", folder_path.display());

    if folder_path.exists() {
        fs::remove_dir_all(&folder_path)?;
        println!("Keys folder deleted successfully.");
    } else {
        println!("Keys folder does not exist at: {}", folder_path.display());
    }
    Ok(())
}

fn main() {
    let usage = "\nUsage:

    \x1b[1m./holocron -g alice\x1b[0m
    ... to generate keys for Alice and save them as `alice_secret.asc` and `alice_public.asc` in the folder `keys`, creating the folder `keys` if it doesn't exist.

    \x1b[1m./holocron -e \"We're in a spot of bother.\" bob\x1b[0m
    ... to encrypt a message for Bob with the publi key `bob_public.asc`, located in the folder `keys`, and print the resulting ciphertext.

    \x1b[1m./holocron -ef plaintext.txt bob\x1b[0m
    ... to encrypt the message in `plaintext.txt` with the public key `bob_public.asc`, located in the folder `keys`, and save it to `ciphertext.asc`.

    \x1b[1m./holocron -df ciphertext bob\x1b[0m
    ... to decrypt the message in `ciphertext.asc` with the secret key `bob_secret.asc`, located in the folder `keys`, and save it to `plaintext.txt`.

    \x1b[1m./holocron -c\x1b[0m to clear all keys, i.e. delete the `keys` folder in the current directory.
    
    Note that if you compile in debug mode and run at the same time with `cargo run`, you'll need to prefix any arguments with `--`, thus: \x1b[1m./holocron -- -g alice\x1b[0m.\n";

    if env::args().len() < 2 {
        println!("\nInsufficient arguments.\n{}", usage);
        return;
    }

    let args: Vec<String> = env::args().collect();
    match args[1].as_str() {
        "-c" => {
            if confirm_deletion() {
                delete_keys_folder().expect("Failed to delete keys folder");
            } else {
                println!("Exiting without deleting keys.");
            }
        }
        "-g" => {
            let username = &args[2];
            generate_keys(username).expect("Failed to generate keys");
        }
        "-e" => {
            if args.len() < 3 {
                println!("This command requires three arguments.\n{}", &usage);
                return;
            }
            let plaintext = &args[2];
            let username = &args[3];

            let file_path = std::env::current_dir()
                .unwrap()
                .join("keys")
                .join(format!("{}_public_key.asc", username));
            let (kyber_ek, rsa_ek) = parse_public_key(&file_path.to_string_lossy()).unwrap();

            let encrypted =
                &encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek).expect("Failed to encrypt");

            let ciphertext = format!(
                "{}\n\n{}\n\n{}",
                "------BEGIN HOLOCRON MESSAGE-----".to_string(),
                encrypted,
                "------END HOLOCRON MESSAGE-----".to_string()
            );

            println!("{}", ciphertext);
        }
        "-ef" => {
            if args.len() < 3 {
                println!("This command requires three arguments.\n{}", &usage);
                return;
            }
            let plaintext_file = &args[2];
            let username = &args[3];

            let file_path = std::env::current_dir()
                .unwrap()
                .join("keys")
                .join(format!("{}_public_key.asc", username));

            if !file_path.exists() {
                println!("Public key file not found at: {}", file_path.display());
                return;
            }

            let plaintext = read_to_string(plaintext_file).expect("Failed to read plaintext file");

            let file_path = std::env::current_dir()
                .unwrap()
                .join("keys")
                .join(format!("{}_public_key.asc", username));

            let (kyber_ek, rsa_ek) =
                parse_public_key(&file_path.to_string_lossy()).expect("Failed to parse public key");

            let encrypted =
                encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek).expect("Failed to encrypt");

            let ciphertext_file = "ciphertext.asc";
            let ciphertext = format!(
                "{}\n\n{}\n\n{}",
                "------BEGIN HOLOCRON MESSAGE-----".to_string(),
                encrypted,
                "------END HOLOCRON MESSAGE-----".to_string()
            );

            let mut file = File::create(ciphertext_file).expect("Failed to create ciphertext file");
            use std::io::Write;
            file.write_all(ciphertext.as_bytes())
                .expect("Failed to write ciphertext");

            println!("Ciphertext saved to `ciphertext.asc`.");
        }
        _ => panic!("Command not found.\n{}", usage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keys_without_saving_then_encrypts_and_decrypt() {
        let alice_plaintext = "We're in a spot of bother.";

        let (bob_kyber_dk, bob_kyber_ek) = generate_kyber_keys();
        let (bob_rsa_dk, bob_rsa_ek) = generate_rsa_keys();

        match encrypt(alice_plaintext.as_bytes(), &bob_kyber_ek, &bob_rsa_ek) {
            Ok(wire_message) => match decrypt(&wire_message, &bob_kyber_dk, &bob_rsa_dk) {
                Ok(bob_plaintext) => {
                    assert_eq!(
                        alice_plaintext, &bob_plaintext,
                        "Message mismatch.\nAlice: `{}`\nBob: `{}`",
                        alice_plaintext, bob_plaintext
                    );
                }
                Err(e) => panic!("{}", e),
            },
            Err(e) => panic!("{}", e),
        }
    }

    #[test]
    fn generate_keys_and_save_then_encrypt_and_decrypt() {
        let username = "bob";
        let (kyber_ek, kyber_dk, rsa_ek, rsa_dk) = generate_keys(username).unwrap();
        let public_key_path = format!("keys/{}_public_key.asc", username);
        let (loaded_kyber_ek, loaded_rsa_ek) = parse_public_key(&public_key_path).unwrap();
        assert_eq!(kyber_ek, loaded_kyber_ek, "Public key mismatch: Kyber");
        assert_eq!(rsa_ek, loaded_rsa_ek, "Public key mismatch: RSA");

        let alice_plaintext = "We're in a spot of bother.";

        match encrypt(alice_plaintext.as_bytes(), &loaded_kyber_ek, &loaded_rsa_ek) {
            Ok(wire_message) => match decrypt(&wire_message, &kyber_dk, &rsa_dk) {
                Ok(bob_plaintext) => {
                    assert_eq!(
                        alice_plaintext, &bob_plaintext,
                        "Message mismatch.\nAlice: `{}`\nBob: `{}`",
                        alice_plaintext, bob_plaintext
                    );
                }
                Err(e) => panic!("{}", e),
            },
            Err(e) => panic!("{}", e),
        }
    }
}
