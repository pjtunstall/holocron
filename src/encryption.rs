use aes_gcm::{
    aead::{Aead, KeyInit},
    {Aes256Gcm, Nonce},
};
use base64ct::{Base64, Encoding};
use generic_array::GenericArray;
use ml_kem::{
    kem::{Encapsulate, EncapsulationKey},
    MlKem1024Params,
};
use rand_core::{OsRng, RngCore};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

use crate::keys::{self, KeyError};

// ----- Encryption side errors -----

#[derive(Debug)]
pub enum EncryptionError {
    KyberError(String),
    AesError(String),
    KeyDerivationError(String),
    KeyGenerationError(String),
    RsaError(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::KyberError(e) => write!(f, "Kyber operation failed:\n{}", e),
            EncryptionError::AesError(e) => write!(f, "AES encryption failed:\n{}", e),
            EncryptionError::KeyDerivationError(e) => write!(f, "Key derivation failed:\n{}", e),
            EncryptionError::KeyGenerationError(e) => write!(f, "Key generation failed:\n{}", e),
            EncryptionError::RsaError(e) => write!(f, "RSA operation failed:\n{}", e),
        }
    }
}

impl std::error::Error for EncryptionError {}

impl From<KeyError> for EncryptionError {
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::DerivationFailed(err) => EncryptionError::KeyDerivationError(err),
            KeyError::GenerationFailed(err) => EncryptionError::KeyGenerationError(err),
        }
    }
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

pub fn encrypt(
    plaintext: &[u8],
    kyber_ek: &EncapsulationKey<MlKem1024Params>,
    rsa_ek: &RsaPublicKey,
) -> Result<String, EncryptionError> {
    let (kyber_encapsulated_secret, kyber_shared_secret) = kyber_encapsulate_key(kyber_ek)?;
    let kyber_aes_encryption_key = keys::derive_aes_key(&kyber_shared_secret)?;
    let (kyber_nonce, kyber_ciphertext) = aes_encrypt(&kyber_aes_encryption_key, plaintext)?;

    let (rsa_encapsulated_secret, rsa_shared_secret) = rsa_encapsulate_key(rsa_ek)?;
    let rsa_aes_encryption_key = keys::derive_aes_key(&rsa_shared_secret)?;
    let (rsa_nonce, ciphertext) = aes_encrypt(&rsa_aes_encryption_key, &kyber_ciphertext)?;

    Ok(format_wire_message(
        &kyber_encapsulated_secret,
        &kyber_nonce,
        &rsa_encapsulated_secret,
        &rsa_nonce,
        &ciphertext,
    ))
}
