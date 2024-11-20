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
    KemCore, MlKem1024, MlKem1024Params,
};
use rand_core::{OsRng, RngCore};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

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
    let bits = 2048;
    let secret_key = RsaPrivateKey::new(&mut OsRng, bits).expect("failed to generate a key");
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

fn main() {
    let alice_plaintext = "We're in a spot of bother.";

    let (bob_kyber_dk, bob_kyber_ek) = generate_kyber_keys();
    let (bob_rsa_dk, bob_rsa_ek) = generate_rsa_keys();

    match encrypt(alice_plaintext.as_bytes(), &bob_kyber_ek, &bob_rsa_ek) {
        Ok(wire_message) => {
            println!("{}", wire_message);
            match decrypt(&wire_message, &bob_kyber_dk, &bob_rsa_dk) {
                Ok(bob_plaintext) => {
                    assert_eq!(
                        alice_plaintext, &bob_plaintext,
                        "Message mismatch.\nAlice: `{}`\nBob: `{}`",
                        alice_plaintext, bob_plaintext
                    );
                    println!("{}", bob_plaintext)
                }
                Err(e) => panic!("{}", e),
            }
        }
        Err(e) => panic!("{}", e),
    }
}
