use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64ct::{Base64, Encoding};
use generic_array::GenericArray;
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    *,
};
// use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand::thread_rng;
// use rand_core::OsRng;
use sha2::Sha256;
use std::fs::File;
use std::io::Write;

// TODO
// - Start separating code into functions.
// - Generate two quantum key pairs, one for Alice and one for Bob.
// - Add classical p256.
// - Accept command-line arguments and store public and private keys in text files.

fn main() {
    let mut rng = thread_rng();

    // Generate quantum (decapsulation key, encapsulation key) pair
    let (qdk, qek) = MlKem1024::generate(&mut rng);

    // Generate classical (decapsulation, encapsulatio) keypair.

    // Encode quantum private key as base 64 string.
    let qdk_string = Base64::encode_string(format!("{:?}", qdk).as_bytes());

    // Save quantum private key to file.
    let mut file = File::create("private_key.txt").unwrap();
    writeln!(file, "{}", qdk_string).unwrap();
    println!("Encrypted key saved.");

    // Encapsulate a shared key to the holder of the decapsulation key
    let (qct, k_send) = qek.encapsulate(&mut rng).unwrap();

    // Direqctly serialize the ciphertext bytes
    let qct_string = Base64::encode_string(qct.as_slice());
    println!("Shared key size: {:?}", qct_string.len());

    // Derive a 32-byte key using HKDF
    let hk = Hkdf::<Sha256>::new(None, &k_send);
    let mut okm = [0u8; 32];
    hk.expand(b"aes256gcm key", &mut okm)
        .expect("HKDF expand failed");

    let key = GenericArray::from_slice(&okm);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce"); // 12 bytes; must be unique
    let plaintext = b"We're in a spot of bother.";
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("encryption failure!");

    let encoded_message = Base64::encode_string(ciphertext.as_ref());
    let full_message = format!("{}:{}", qct_string, encoded_message);
    println!("Full message: {}", full_message);

    // Simulate message transmission by splitting the received message
    let parts: Vec<&str> = full_message.split(':').collect();
    let received_qct_string = parts[0];
    let received_ciphertext_string = parts[1];

    // Deserialize the ciphertext back into the correqct type
    let qct_bytes = Base64::decode_vec(received_qct_string).unwrap();

    // Clone the original ciphertext type using the decoded bytes
    let mut qct_clone = qct.clone();
    qct_clone.copy_from_slice(&qct_bytes);

    // Decapsulate the shared key using the deserialized ciphertext
    let k_recv = qdk.decapsulate(&qct_clone).unwrap();
    let hk = Hkdf::<Sha256>::new(None, &k_recv);
    let mut okm = [0u8; 32];
    hk.expand(b"aes256gcm key", &mut okm)
        .expect("HKDF expand failed");

    let key = GenericArray::from_slice(&okm);
    let cipher = Aes256Gcm::new(key);

    let received_ciphertext = Base64::decode_vec(received_ciphertext_string).unwrap();
    let decrypted_data = cipher
        .decrypt(nonce, received_ciphertext.as_ref())
        .expect("decryption failure!");

    let decoded = String::from_utf8(decrypted_data).unwrap();
    println!("Decrypted: {:?}", decoded);
}
