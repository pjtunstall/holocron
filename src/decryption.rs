use aes_gcm::{
    aead::{Aead, KeyInit},
    {Aes256Gcm, Nonce},
};
use base64ct::{Base64, Encoding};
use generic_array::GenericArray;
use hybrid_array::Array;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey},
    MlKem1024, MlKem1024Params,
};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::keys::{self, KeyError};

// ----- Decryption side errors -----

#[derive(Debug)]
pub enum DecryptionError {
    Base64Error(base64ct::Error),
    InvalidFormat,
    Utf8Error(std::string::FromUtf8Error),
    AesError(String),
    KyberError(String),
    RsaError(String),
    KeyDerivationError(String),
    KeyGenerationError(String),
}

impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptionError::Base64Error(e) => write!(f, "Base64 decoding error:\n{}", e),
            DecryptionError::InvalidFormat => write!(f, "Invalid message format"),
            DecryptionError::Utf8Error(e) => write!(f, "UTF-8 conversion error:\n{}", e),
            DecryptionError::AesError(e) => write!(f, "Decryption error:\n{}", e),
            DecryptionError::KyberError(e) => write!(f, "Kyber operation failed:\n{}", e),
            DecryptionError::RsaError(e) => write!(f, "rsa operation failed:\n{}", e),
            DecryptionError::KeyDerivationError(e) => write!(f, "Key derivation failed:\n{}", e),
            DecryptionError::KeyGenerationError(e) => write!(f, "Key generation failed:\n{}", e),
        }
    }
}

impl std::error::Error for DecryptionError {}

impl From<KeyError> for DecryptionError {
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::DerivationFailed(err) => DecryptionError::KeyDerivationError(err),
            KeyError::GenerationFailed(err) => DecryptionError::KeyGenerationError(err),
        }
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

    let content = if wire_message.contains("-----BEGIN HOLOCRON MESSAGE-----") {
        wire_message
            .lines()
            .filter(|line| !line.starts_with("-----") && !line.is_empty())
            .collect::<Vec<&str>>()
            .join("")
    } else {
        wire_message.to_string()
    };

    let bytes = Base64::decode_vec(&content)?;
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

pub fn decrypt(
    wire_message: &str,
    kyber_dk: &DecapsulationKey<MlKem1024Params>,
    rsa_dk: &RsaPrivateKey,
) -> Result<String, DecryptionError> {
    let message = parse_wire_message(wire_message)?;

    let rsa_shared_secret: Vec<u8> = rsa_decapsulate_key(rsa_dk, &message.rsa_encapsulated_secret)
        .map_err(|e| DecryptionError::RsaError(e.to_string()))?;
    let rsa_aes_decryption_key = keys::derive_aes_key(&rsa_shared_secret)?;

    let rsa_plaintext = aes_decrypt(
        &rsa_aes_decryption_key,
        &message.rsa_nonce,
        &message.ciphertext,
    )
    .map_err(|e| DecryptionError::AesError(e.to_string()))?;

    let kyber_shared_secret = kyber_decapsulate_key(kyber_dk, &message.kyber_encapsulated_secret)?;
    let kyber_aes_decryption_key = keys::derive_aes_key(&kyber_shared_secret)?;

    let plaintext = aes_decrypt(
        &kyber_aes_decryption_key,
        &message.kyber_nonce,
        &rsa_plaintext,
    )
    .map_err(|e| DecryptionError::AesError(e.to_string()))?;

    String::from_utf8(plaintext).map_err(DecryptionError::Utf8Error)
}
