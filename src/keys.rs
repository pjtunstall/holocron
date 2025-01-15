use std::{
    env,
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

use base64ct::{Base64, Encoding};
use hkdf::Hkdf;
use ml_kem::{
    kem::{DecapsulationKey, EncapsulationKey},
    Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use rand::rngs::OsRng;
use rand_core::RngCore;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

pub const RSA_KEY_BIT_SIZE: usize = 4096;

// ----- Key errors -----

#[derive(Debug)]
pub enum KeyError {
    DerivationFailed(String),
    GenerationFailed(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::DerivationFailed(err) => write!(f, "Key derivation failed:\n{}", err),
            KeyError::GenerationFailed(err) => write!(f, "Key generation failed:\n{}", err),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<io::Error> for KeyError {
    fn from(err: io::Error) -> Self {
        KeyError::GenerationFailed(err.to_string())
    }
}

// ----- Key generation -----

pub fn generate_keys(
    username: &str,
) -> Result<
    (
        EncapsulationKey<MlKem1024Params>,
        DecapsulationKey<MlKem1024Params>,
        RsaPublicKey,
        RsaPrivateKey,
    ),
    KeyError,
> {
    let (kyber_dk, kyber_ek) = generate_kyber_keys();
    let (rsa_dk, rsa_ek) =
        generate_rsa_keys().map_err(|e| KeyError::GenerationFailed(e.to_string()))?;

    save_keys(username, &kyber_dk, &kyber_ek, &rsa_dk, &rsa_ek)?;

    Ok((kyber_ek, kyber_dk, rsa_ek, rsa_dk))
}

fn generate_kyber_keys() -> (
    DecapsulationKey<MlKem1024Params>,
    EncapsulationKey<MlKem1024Params>,
) {
    MlKem1024::generate(&mut OsRng)
}

fn generate_rsa_keys() -> Result<(RsaPrivateKey, RsaPublicKey), Box<dyn Error>> {
    let secret_key = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BIT_SIZE)
        .map_err(|e| format!("Failed to generate RSA private key:\n{}", e))?;
    let public_key = RsaPublicKey::from(&secret_key);
    Ok((secret_key, public_key))
}

fn check_if_file_already_exists(file_path: &str) -> io::Result<()> {
    if Path::new(&file_path).exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("File `{}` already exists.", file_path),
        ));
    }
    Ok(())
}

fn save_keys(
    username: &str,
    kyber_dk: &DecapsulationKey<MlKem1024Params>,
    kyber_ek: &EncapsulationKey<MlKem1024Params>,
    rsa_dk: &RsaPrivateKey,
    rsa_ek: &RsaPublicKey,
) -> io::Result<()> {
    let file_path_for_secret_key = format!("keys/{}_secret_key.asc", username);
    check_if_file_already_exists(&file_path_for_secret_key)?;

    let file_path_for_public_key = format!("keys/{}_public_key.asc", username);
    check_if_file_already_exists(&file_path_for_public_key)?;

    if !Path::new("keys").is_dir() {
        fs::create_dir("keys")?;
    }

    let kyber_dk_bytes = kyber_dk.as_bytes().to_vec();
    let kyber_ek_bytes = kyber_ek.as_bytes().to_vec();

    let rsa_dk_bytes = rsa_dk
        .to_pkcs8_der()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to serialize RSA private key:\n{}", e),
            )
        })?
        .as_bytes()
        .to_vec();
    let rsa_ek_bytes = rsa_ek
        .to_public_key_der()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to serialize RSA public key:\n{}", e),
            )
        })?
        .as_bytes()
        .to_vec();

    if kyber_dk_bytes.len() != 3168 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kyber_dk length != 3168",
        ));
    }
    if kyber_ek_bytes.len() != 1568 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kyber_ek length != 1568",
        ));
    }

    write_key(
        "SECRET",
        &kyber_dk_bytes,
        &rsa_dk_bytes,
        &file_path_for_secret_key,
    )?;
    write_key(
        "PUBLIC",
        &kyber_ek_bytes,
        &rsa_ek_bytes,
        &file_path_for_public_key,
    )?;

    Ok(())
}

fn write_key(kind: &str, kyber_bytes: &[u8], rsa_bytes: &[u8], path: &str) -> io::Result<()> {
    let mut key = Vec::new();
    key.extend_from_slice(&kyber_bytes);
    key.extend_from_slice(&rsa_bytes);

    let mut key_string = String::new();
    let header = format!("-----BEGIN HOLOCRON {} KEY-----\n\n", kind);
    let footer = format!("\n\n-----END HOLOCRON {} KEY-----", kind);
    key_string.push_str(&header);
    key_string.push_str(&Base64::encode_string(&key));
    key_string.push_str(&footer);

    let mut file = File::create(path)?;
    file.write_all(key_string.as_bytes())?;

    Ok(())
}

pub fn parse_public_key(
    path: &str,
) -> Result<(EncapsulationKey<MlKem1024Params>, RsaPublicKey), io::Error> {
    let mut file = File::open(&path).map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let trimmed = contents
        .strip_prefix("-----BEGIN HOLOCRON PUBLIC KEY-----\n\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid public key format"))?
        .strip_suffix("\n\n-----END HOLOCRON PUBLIC KEY-----")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid public key format"))?;

    let bytes = Base64::decode_vec(&trimmed).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Base64 decode error:\n{}", e),
        )
    })?;

    let kyber_bytes = bytes[..1568].to_vec();
    let rsa_bytes = bytes[1568..].to_vec();

    let kyber_array: [u8; 1568] = kyber_bytes[..]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Wrong length for kyber bytes"))?;
    let encoded = Encoded::<EncapsulationKey<MlKem1024Params>>::from(kyber_array);
    let kyber_ek = EncapsulationKey::<MlKem1024Params>::from_bytes(&encoded);

    let rsa_ek = RsaPublicKey::from_public_key_der(&rsa_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to decode RSA public key",
        )
    })?;

    Ok((kyber_ek, rsa_ek))
}

pub fn parse_secret_key(
    path: &str,
) -> Result<(DecapsulationKey<MlKem1024Params>, RsaPrivateKey), io::Error> {
    let mut file = File::open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Get content between headers, more flexibly
    let content = contents
        .lines()
        .filter(|line| !line.starts_with("-----") && !line.is_empty())
        .collect::<Vec<&str>>()
        .join("");

    let bytes = Base64::decode_vec(&content).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to decode base64 content",
        )
    })?;

    if bytes.len() < 3168 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "File too short",
        ));
    }

    let kyber_bytes = &bytes[..3168];
    let rsa_bytes = &bytes[3168..];

    let kyber_array: [u8; 3168] = kyber_bytes.try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid Kyber key length")
    })?;

    let decoded = Encoded::<DecapsulationKey<MlKem1024Params>>::from(kyber_array);
    let kyber_dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&decoded);

    let rsa_dk = RsaPrivateKey::from_pkcs8_der(rsa_bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to decode RSA key")
    })?;

    Ok((kyber_dk, rsa_dk))
}

pub fn confirm_deletion() -> bool {
    let current_dir = match env::current_dir() {
        Ok(dir) => dir,
        Err(_) => {
            eprintln!("Error: Unable to determine the current directory.");
            return false;
        }
    };

    let dir_name = current_dir.file_name().unwrap_or_default();
    let dir_name_str = dir_name.to_str().unwrap_or("the current directory");

    let full_path_str = current_dir.to_str().unwrap_or("an unnamable path");

    let mut input = String::new();
    println!(
        "Are you sure you want to delete all keys in {}?\n(Full path: `{}`)\n(Y/N): ",
        dir_name_str, full_path_str
    );

    if let Err(e) = io::stdout().flush() {
        eprintln!("Error: Unable to flush stdout:\n{}", e);
        return false;
    }

    if let Err(e) = io::stdin().read_line(&mut input) {
        eprintln!("Error: Unable to read input:\n{}", e);
        return false;
    }

    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => true,
        _ => false,
    }
}

pub fn delete_keys_folder() -> Result<(), io::Error> {
    let current_dir = env::current_dir()?;
    let folder_path = current_dir.join("keys");

    if folder_path.exists() {
        fs::remove_dir_all(&folder_path)?;
        Ok(())
    } else {
        let err_msg = format!(
            "Keys folder does not exist at:\n`{}`",
            folder_path.display()
        );
        Err(io::Error::new(io::ErrorKind::NotFound, err_msg))
    }
}

pub fn derive_aes_key(shared_secret: &[u8]) -> Result<Vec<u8>, KeyError> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"aes256gcm key", &mut okm)
        .map_err(|e| KeyError::DerivationFailed(e.to_string()))?;
    Ok(okm.to_vec())
}
