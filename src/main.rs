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
use rand::{thread_rng, RngCore};
use sha2::Sha256;

// ----- Encryption side errors -----

#[derive(Debug)]
enum EncryptionError {
    KyberError(String),
    AesError(String),
    KeyDerivationError(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::KyberError(e) => write!(f, "Kyber operation failed: {}", e),
            EncryptionError::AesError(e) => write!(f, "AES encryption failed: {}", e),
            EncryptionError::KeyDerivationError(e) => write!(f, "Key derivation failed: {}", e),
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

// ----- Key generation -----

fn generate_kyber_keys() -> (
    DecapsulationKey<MlKem1024Params>,
    EncapsulationKey<MlKem1024Params>,
) {
    let mut rng = thread_rng();
    MlKem1024::generate(&mut rng)
}

// ----- Encryption functions -----

fn encapsulate_key(
    kyber_ek: &EncapsulationKey<MlKem1024Params>,
) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    let mut rng = thread_rng();
    kyber_ek
        .encapsulate(&mut rng)
        .map(|(secret, shared)| (secret.to_vec(), shared.to_vec()))
        .map_err(|e| EncryptionError::KyberError(format!("{:?}", e)))
}

fn derive_encryption_key(shared_secret: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"aes256gcm key", &mut okm)
        .map_err(|e| EncryptionError::KeyDerivationError(e.to_string()))?;
    Ok(okm.to_vec())
}

fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    let mut rng = thread_rng();
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

fn format_wire_message(encapsulated_secret: &[u8], nonce: &[u8], ciphertext: &[u8]) -> String {
    let encapsulated_secret_b64 = Base64::encode_string(encapsulated_secret);
    let nonce_b64 = Base64::encode_string(nonce);
    let ciphertext_b64 = Base64::encode_string(ciphertext);

    format!(
        "{}:{}:{}",
        encapsulated_secret_b64, nonce_b64, ciphertext_b64
    )
}

fn encrypt(
    plaintext: &[u8],
    kyber_ek: &EncapsulationKey<MlKem1024Params>,
) -> Result<String, EncryptionError> {
    let (encapsulated_secret, shared_secret) = encapsulate_key(kyber_ek)?;
    let encryption_key = derive_encryption_key(&shared_secret)?;
    let (nonce, ciphertext) = aes_encrypt(&encryption_key, plaintext)?;
    Ok(format_wire_message(
        &encapsulated_secret,
        &nonce,
        &ciphertext,
    ))
}

// ----- Decryption functions -----

struct WireMessage {
    encapsulated_secret: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn parse_wire_message(wire_message: &str) -> Result<WireMessage, DecryptionError> {
    let parts: Vec<&str> = wire_message.split(':').collect();
    if parts.len() != 3 {
        return Err(DecryptionError::InvalidFormat);
    }

    Ok(WireMessage {
        encapsulated_secret: Base64::decode_vec(parts[0])?,
        nonce: Base64::decode_vec(parts[1])?,
        ciphertext: Base64::decode_vec(parts[2])?,
    })
}

fn prepare_kyber_secret(bytes: &[u8]) -> Array<u8, <MlKem1024 as ml_kem::KemCore>::CiphertextSize> {
    let mut array = Array::default();
    array.copy_from_slice(bytes);
    array
}

fn decapsulate_key(
    kyber_dk: &DecapsulationKey<MlKem1024Params>,
    encapsulated_secret: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    let kyber_secret = prepare_kyber_secret(encapsulated_secret);
    kyber_dk
        .decapsulate(&kyber_secret)
        .map(|secret| secret.to_vec())
        .map_err(|e| DecryptionError::KyberError(format!("{:?}", e)))
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
) -> Result<String, DecryptionError> {
    let message = parse_wire_message(wire_message)?;

    let shared_secret = decapsulate_key(kyber_dk, &message.encapsulated_secret)?;
    let decryption_key = derive_encryption_key(&shared_secret)?;

    let plaintext = aes_decrypt(&decryption_key, &message.nonce, &message.ciphertext)
        .map_err(|e| DecryptionError::AesError(e.to_string()))?;

    String::from_utf8(plaintext).map_err(DecryptionError::Utf8Error)
}

fn main() {
    // Alice's message.
    let alice_plaintext = "We're in a spot of bother.";

    // Generate Kyber keys for Bob.
    let (bob_kyber_dk, bob_kyber_ek) = generate_kyber_keys();

    // Alice encrypts her message for Bob.
    match encrypt(alice_plaintext.as_bytes(), &bob_kyber_ek) {
        Ok(wire_message) => {
            // Bob decrypts the message.
            match decrypt(&wire_message, &bob_kyber_dk) {
                Ok(bob_plaintext) => assert_eq!(
                    alice_plaintext, &bob_plaintext,
                    "Message mismatch. Alice: `{}`, Bob: `{}`.",
                    alice_plaintext, bob_plaintext
                ),
                Err(e) => panic!("{}", e),
            }
        }
        Err(e) => panic!("{}", e),
    }
}
