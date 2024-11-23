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
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

fn main() {
    let usage = "\nUsage:

    \x1b[1m./holocron -g bob\x1b[0m
    ... to generate keys for Bob and save them as `bob_secret.asc` and `bob_public.asc` in the folder `keys`, creating the folder `keys` if it doesn't exist.

    \x1b[1m./holocron -eff hello.txt bob\x1b[0m
    ... to encrypt the message in `hello.txt` with the public key `bob_public.asc`, located in the folder `keys`, and save the resulting ciphertext to `hello.asc`.

    \x1b[1m./holocron -etf \"We're in a spot of bother.\" bob\x1b[0m
    ... to encrypt the given message for Bob with the public key `bob_public.asc`, located in the folder `keys`, and save the resulting ciphertext to `ciphertext.asc`.

    \x1b[1m./holocron -ett \"We're in a spot of bother.\" bob\x1b[0m
    ... to encrypt the given message for Bob with the public key `bob_public.asc`, located in the folder `keys`, and print the resulting ciphertext to the terminal.

    \x1b[1m./holocron -dff hello.asc bob\x1b[0m
    ... to decrypt the message in `hello.asc` with the secret key `bob_secret.asc`, located in the folder `keys`, and save the resulting plaintext to `hello.txt`.

    \x1b[1m./holocron -dft hello.asc bob\x1b[0m
    ... to decrypt the message in `hello.asc` with the secret key `bob_secret.asc`, located in the folder `keys`, and print the resulting plaintext to the terminal.

    \x1b[1m./holocron -c\x1b[0m to clear all keys, i.e. delete the `keys` folder in the current directory.
    
    Note that if you compile in debug mode and run at the same time with `cargo run`, you'll need to prefix any arguments with `--`, thus: \x1b[1m./holocron -- -g bob\x1b[0m.\n";

    if env::args().len() < 2 {
        println!("\nInsufficient arguments.\n{}", usage);
        return;
    }

    let args: Vec<String> = env::args().collect();
    match args[1].as_str() {
        "-c" => c_for_clear_all_keys(),
        "-g" => g_for_generate_keys(&args, &usage),
        "-eff" => eff_for_encrypt_from_file_to_file(&args, &usage),
        "-etf" => etf_for_encrypt_from_terminal_to_file(&args, &usage),
        "-ett" => ett_for_encrypt_from_terminal_to_terminal(&args, &usage),
        "-dff" => dff_for_decrypt_from_file_to_file(&args, &usage),
        "-dft" => dft_for_decrypt_from_file_to_terminal(&args, &usage),
        _ => println!("Command not found.\n{}", usage),
    }
}

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
            EncryptionError::KyberError(e) => write!(f, "Kyber operation failed:\n{}", e),
            EncryptionError::AesError(e) => write!(f, "AES encryption failed:\n{}", e),
            EncryptionError::KeyDerivationError(e) => write!(f, "Key derivation failed:\n{}", e),
            EncryptionError::RsaError(e) => write!(f, "RSA operation failed:\n{}", e),
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
            DecryptionError::Base64Error(e) => write!(f, "Base64 decoding error:\n{}", e),
            DecryptionError::InvalidFormat => write!(f, "Invalid message format"),
            DecryptionError::Utf8Error(e) => write!(f, "UTF-8 conversion error:\n{}", e),
            DecryptionError::AesError(e) => write!(f, "Decryption error:\n{}", e),
            DecryptionError::KyberError(e) => write!(f, "Kyber operation failed:\n{}", e),
            DecryptionError::RsaError(e) => write!(f, "rsa operation failed:\n{}", e),
            DecryptionError::KeyDerivationError(e) => write!(f, "Key derivation failed:\n{}", e),
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

fn generate_rsa_keys() -> Result<(RsaPrivateKey, RsaPublicKey), Box<dyn Error>> {
    let secret_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|e| format!("Failed to generate RSA private key:\n{}", e))?;
    let public_key = RsaPublicKey::from(&secret_key);
    Ok((secret_key, public_key))
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
    let (rsa_dk, rsa_ek) = match generate_rsa_keys() {
        Ok((dk, ek)) => (dk, ek),
        Err(e) => {
            eprintln!("Error generating RSA keys:\n{}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    };

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
        fs::create_dir("keys")?;
    }

    let kyber_dk_bytes = kyber_dk.as_bytes().to_vec();
    let kyber_ek_bytes = kyber_ek.as_bytes().to_vec();

    let rsa_dk_bytes = rsa_dk
        .to_pkcs8_der()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to serialize RSA private key: {}", e),
            )
        })?
        .as_bytes()
        .to_vec();
    let rsa_ek_bytes = rsa_ek
        .to_public_key_der()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to serialize RSA public key: {}", e),
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

    let mut secret_key = Vec::new();
    secret_key.extend_from_slice(&kyber_dk_bytes);
    secret_key.extend_from_slice(&rsa_dk_bytes);

    let mut public_key = Vec::new();
    public_key.extend_from_slice(&kyber_ek_bytes);
    public_key.extend_from_slice(&rsa_ek_bytes);

    let mut secret_key_str = String::new();
    secret_key_str.push_str("-----BEGIN HOLOCRON SECRET KEY-----\n\n");
    secret_key_str.push_str(&Base64::encode_string(&secret_key));
    secret_key_str.push_str("\n\n-----END HOLOCRON PRIVATE KEY-----");

    let mut file = File::create(format!("keys/{}_secret_key.asc", username))?;
    file.write_all(secret_key_str.as_bytes())?;

    let mut public_key_str = String::new();
    public_key_str.push_str("-----BEGIN HOLOCRON PUBLIC KEY-----\n\n");
    public_key_str.push_str(&Base64::encode_string(&public_key));
    public_key_str.push_str("\n\n-----END HOLOCRON PUBLIC KEY-----");

    let mut file = File::create(format!("keys/{}_public_key.asc", username))?;
    file.write_all(public_key_str.as_bytes())?;

    Ok(())
}

fn parse_public_key(
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

fn parse_secret_key(
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

fn confirm_deletion() -> bool {
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
        "Are you sure you want to delete all keys in {}?\n(Full path: {})\n(Y/N): ",
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

fn delete_keys_folder() -> Result<(), io::Error> {
    let current_dir = env::current_dir()?;
    let folder_path = current_dir.join("keys");

    if folder_path.exists() {
        fs::remove_dir_all(&folder_path)?;
        Ok(())
    } else {
        let err_msg = format!("Keys folder does not exist at:\n{}", folder_path.display());
        Err(io::Error::new(io::ErrorKind::NotFound, err_msg))
    }
}

fn c_for_clear_all_keys() {
    if confirm_deletion() {
        match delete_keys_folder() {
            Ok(_) => println!("Keys folder successfully deleted."),
            Err(e) => eprintln!("Failed to delete keys folder:\n{}", e),
        }
    } else {
        println!("Exiting without deleting keys.");
    }
}

fn g_for_generate_keys(args: &Vec<String>, usage: &str) {
    if args.len() < 3 {
        println!(
            "This command requires three arguments, including the program name.\n{}",
            &usage
        );
        return;
    }

    let username = &args[2];

    if let Err(e) = generate_keys(username) {
        eprintln!("Error: Failed to generate keys for `{}`:\n{}", username, e);
    } else {
        println!("Keys successfully generated for `{}`.", username);
    }
}

fn eff_for_encrypt_from_file_to_file(args: &Vec<String>, usage: &str) {
    if args.len() < 4 {
        println!(
            "This command requires four arguments, including the program name.\n{}",
            usage
        );
        return;
    }

    let plaintext_file = &args[2];
    let username = &args[3];

    let file_path = match std::env::current_dir() {
        Ok(current_dir) => current_dir
            .join("keys")
            .join(format!("{}_public_key.asc", username)),
        Err(e) => {
            println!("Failed to get current directory:\n{}", e);
            return;
        }
    };

    if !file_path.exists() {
        println!("Public key file not found at:\n{}", file_path.display());
        return;
    }

    let plaintext = match fs::read_to_string(plaintext_file) {
        Ok(content) => content,
        Err(e) => {
            println!("Failed to read plaintext file `{}`:\n{}", plaintext_file, e);
            return;
        }
    };

    let (kyber_ek, rsa_ek) = match parse_public_key(&file_path.to_string_lossy()) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse public key at: `{}`\n{}",
                file_path.display(),
                e
            );
            return;
        }
    };

    let encrypted = match encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Encryption failed:\n{}", e);
            return;
        }
    };

    let file_name = Path::new(plaintext_file)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(plaintext_file);

    let ciphertext_file = format!("{}.asc", file_name);
    let ciphertext = format!(
        "{}\n\n{}\n\n{}",
        "-----BEGIN HOLOCRON MESSAGE-----", encrypted, "-----END HOLOCRON MESSAGE-----"
    );

    let mut file = match File::create(&ciphertext_file) {
        Ok(f) => f,
        Err(e) => {
            println!(
                "Failed to create ciphertext file `{}`:\n{}",
                ciphertext_file, e
            );
            return;
        }
    };

    if let Err(e) = file.write_all(ciphertext.as_bytes()) {
        println!(
            "Failed to write ciphertext to file `{}`:\n{}",
            ciphertext_file, e
        );
        return;
    }

    println!("Ciphertext saved to `{}`.", ciphertext_file);
}

fn ett_for_encrypt_from_terminal_to_terminal(args: &Vec<String>, usage: &str) {
    if args.len() < 4 {
        println!(
            "This command requires four arguments, including the program name.\n{}",
            usage
        );
        return;
    }

    let plaintext = &args[2];
    let username = &args[3];

    let file_path = match std::env::current_dir() {
        Ok(current_dir) => current_dir
            .join("keys")
            .join(format!("{}_public_key.asc", username)),
        Err(e) => {
            println!("Failed to get current directory:\n{}", e);
            return;
        }
    };

    let key_file_path = file_path.to_string_lossy().to_string();
    let (kyber_ek, rsa_ek) = match parse_public_key(&key_file_path) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse public key file at: {}\n{}",
                key_file_path, e
            );
            return;
        }
    };

    let encrypted = match encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Encryption failed:\n{}", e);
            return;
        }
    };

    let ciphertext = format!(
        "{}\n\n{}\n\n{}",
        "-----BEGIN HOLOCRON MESSAGE-----", encrypted, "-----END HOLOCRON MESSAGE-----"
    );

    println!("{}", ciphertext);
}

fn etf_for_encrypt_from_terminal_to_file(args: &Vec<String>, usage: &str) {
    if args.len() < 4 {
        println!(
            "This command requires four arguments, including the program name.\n{}",
            usage
        );
        return;
    }

    let plaintext = &args[2];
    let username = &args[3];

    let file_path = match std::env::current_dir() {
        Ok(current_dir) => current_dir
            .join("keys")
            .join(format!("{}_public_key.asc", username)),
        Err(e) => {
            println!("Failed to get current directory:\n{}", e);
            return;
        }
    };

    let key_file_path = file_path.to_string_lossy().to_string();
    let (kyber_ek, rsa_ek) = match parse_public_key(&key_file_path) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse public key file at: {}\n{}",
                key_file_path, e
            );
            return;
        }
    };

    let encrypted = match encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Encryption failed:\n{}", e);
            return;
        }
    };

    let ciphertext = format!(
        "{}\n\n{}\n\n{}",
        "-----BEGIN HOLOCRON MESSAGE-----", encrypted, "-----END HOLOCRON MESSAGE-----"
    );

    let mut file = match File::create("ciphertext.asc") {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to create ciphertext file:\n{}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(ciphertext.as_bytes()) {
        println!("Failed to write ciphertext to file:\n{}", e);
        return;
    }

    println!("Ciphertext saved to `ciphertext.asc`.");
}

fn dff_for_decrypt_from_file_to_file(args: &Vec<String>, usage: &str) {
    if args.len() < 4 {
        println!(
            "This command requires four arguments, including the program name.\n{}",
            usage
        );
        return;
    }

    let ciphertext_file = &args[2];
    let username = &args[3];

    let file_path = match std::env::current_dir() {
        Ok(current_dir) => current_dir
            .join("keys")
            .join(format!("{}_secret_key.asc", username)),
        Err(e) => {
            println!("Failed to get current directory:\n{}", e);
            return;
        }
    };

    if !file_path.exists() {
        println!("Secret key file not found at:\n{}", file_path.display());
        return;
    }

    let ciphertext = match fs::read_to_string(ciphertext_file) {
        Ok(content) => content,
        Err(e) => {
            println!(
                "Failed to read ciphertext file `{}`:\n{}",
                ciphertext_file, e
            );
            return;
        }
    };

    let (kyber_dk, rsa_dk) = match parse_secret_key(&file_path.to_string_lossy()) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse secret key file `{}`:\n{}",
                file_path.display(),
                e
            );
            return;
        }
    };

    let decrypted = match decrypt(&ciphertext, &kyber_dk, &rsa_dk) {
        Ok(message) => message,
        Err(e) => {
            println!("Failed to decrypt the message:\n{}", e);
            return;
        }
    };

    let decrypted_file = match ciphertext_file.strip_suffix(".asc") {
        Some(base) => format!("{}.txt", base),
        None => format!("{}_decrypted.txt", ciphertext_file),
    };

    let mut file = match fs::File::create(&decrypted_file) {
        Ok(file) => file,
        Err(e) => {
            println!(
                "Failed to create plaintext file `{}`:\n{}",
                decrypted_file, e
            );
            return;
        }
    };

    if let Err(e) = file.write_all(decrypted.as_bytes()) {
        println!(
            "Failed to write to plaintext file `{}`:\n{}",
            decrypted_file, e
        );
        return;
    }

    println!("Plaintext saved to `{}`.", decrypted_file);
}

fn dft_for_decrypt_from_file_to_terminal(args: &Vec<String>, usage: &str) {
    if args.len() < 4 {
        println!(
            "This command requires four arguments, including the program name.\n{}",
            usage
        );
        return;
    }

    let ciphertext_file = &args[2];
    let username = &args[3];

    let file_path = match std::env::current_dir() {
        Ok(current_dir) => current_dir
            .join("keys")
            .join(format!("{}_secret_key.asc", username)),
        Err(e) => {
            println!("Failed to get current directory:\n{}", e);
            return;
        }
    };

    if !file_path.exists() {
        println!("Secret key file not found at:\n{}", file_path.display());
        return;
    }

    let ciphertext = match fs::read_to_string(ciphertext_file) {
        Ok(content) => content,
        Err(e) => {
            println!(
                "Failed to read ciphertext file `{}`:\n{}",
                ciphertext_file, e
            );
            return;
        }
    };

    let (kyber_dk, rsa_dk) = match parse_secret_key(&file_path.to_string_lossy()) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse secret key file `{}`:\n{}",
                file_path.display(),
                e
            );
            return;
        }
    };

    let decrypted = match decrypt(&ciphertext, &kyber_dk, &rsa_dk) {
        Ok(message) => message,
        Err(e) => {
            println!("Failed to decrypt the message:\n{}", e);
            return;
        }
    };

    println!("{}", decrypted);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keys_without_saving_then_encrypts_and_decrypt() {
        let alice_plaintext = "We're in a spot of bother.";

        let (bob_kyber_dk, bob_kyber_ek) = generate_kyber_keys();
        let (bob_rsa_dk, bob_rsa_ek) = generate_rsa_keys().expect("Failed to generate RSA keys");

        let wire_message = encrypt(alice_plaintext.as_bytes(), &bob_kyber_ek, &bob_rsa_ek)
            .expect("Failed to encrypt message");

        let bob_plaintext =
            decrypt(&wire_message, &bob_kyber_dk, &bob_rsa_dk).expect("Failed to decrypt message");

        assert_eq!(
            alice_plaintext, &bob_plaintext,
            "Message mismatch.\nAlice: `{}`\nBob: `{}`",
            alice_plaintext, bob_plaintext
        );
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
