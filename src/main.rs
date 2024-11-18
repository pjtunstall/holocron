// #![allow(dead_code)]

// use aes_gcm::aead::{Aead, KeyInit};
// use aes_gcm::{Aes256Gcm, Nonce};
// use base64ct::{Base64, Encoding};
// use generic_array::GenericArray;
// use hkdf::Hkdf;
// use ml_kem::{
//     kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
//     KemCore, MlKem1024, MlKem1024Params,
// };
// // use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
// use rand::{rngs::ThreadRng, thread_rng, RngCore};
// // use rand_core::OsRng;
// use sha2::Sha256;
// use std::fs::File;
// use std::io::Write;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64ct::{Base64, Encoding};
use generic_array::GenericArray;
use hkdf::Hkdf;
use hybrid_array;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    KemCore, MlKem1024, MlKem1024Params,
};
use rand::{rngs::ThreadRng, thread_rng, RngCore};
use sha2::Sha256;

fn generate_kyber_keys(
    r: &mut ThreadRng,
) -> (
    DecapsulationKey<MlKem1024Params>,
    EncapsulationKey<MlKem1024Params>,
) {
    MlKem1024::generate(r)
}

fn encapsulate_kyber_key(
    rng: &mut ThreadRng,
    ek: &EncapsulationKey<MlKem1024Params>,
) -> (
    hybrid_array::Array<
        u8,
        typenum::uint::UInt<
            typenum::uint::UInt<
                typenum::uint::UInt<
                    typenum::uint::UInt<
                        typenum::uint::UInt<
                            typenum::uint::UInt<
                                typenum::uint::UInt<
                                    typenum::uint::UInt<
                                        typenum::uint::UInt<
                                            typenum::uint::UInt<
                                                typenum::uint::UInt<
                                                    typenum::uint::UTerm,
                                                    typenum::bit::B1,
                                                >,
                                                typenum::bit::B1,
                                            >,
                                            typenum::bit::B0,
                                        >,
                                        typenum::bit::B0,
                                    >,
                                    typenum::bit::B0,
                                >,
                                typenum::bit::B1,
                            >,
                            typenum::bit::B0,
                        >,
                        typenum::bit::B0,
                    >,
                    typenum::bit::B0,
                >,
                typenum::bit::B0,
            >,
            typenum::bit::B0,
        >,
    >,
    hybrid_array::Array<
        u8,
        typenum::uint::UInt<
            typenum::uint::UInt<
                typenum::uint::UInt<
                    typenum::uint::UInt<
                        typenum::uint::UInt<
                            typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>,
                            typenum::bit::B0,
                        >,
                        typenum::bit::B0,
                    >,
                    typenum::bit::B0,
                >,
                typenum::bit::B0,
            >,
            typenum::bit::B0,
        >,
    >,
) {
    ek.encapsulate(rng).unwrap()
}

fn main() {
    let mut rng = thread_rng();

    println!("Generating key pair for Bob...");
    let (bob_kyber_dk, bob_kyber_ek) = generate_kyber_keys(&mut rng);

    println!("Keys generated.");
    println!("\nAlice wants to send Bob a secret message...");

    // Alice uses Bob's encapsulation key (public key) to create a shared secret
    // let (kyber_encrypted_secret, alice_shared_secret) = bob_kyber_ek.encapsulate(&mut rng).unwrap();
    let (kyber_encrypted_secret, alice_shared_secret) =
        encapsulate_kyber_key(&mut rng, &bob_kyber_ek);

    // // Add this after the encapsulation:
    // println!(
    //     "Type of kyber_encrypted_secret: {}",
    //     std::any::type_name_of_val(&kyber_encrypted_secret)
    // );
    // println!(
    //     "Type of alice_shared_secret: {}",
    //     std::any::type_name_of_val(&alice_shared_secret)
    // );

    // Alice derives an encryption key from the shared secret
    let hk = Hkdf::<Sha256>::new(None, &alice_shared_secret); // HMAC-based Key derivation
    let mut okm = [0u8; 32]; // Output key material
    hk.expand(b"aes256gcm key", &mut okm) // First parameter hashed to make this okm distinct from others derived from the same secret but with a different purpose, such as authentication.
        .expect("HKDF expand failed");

    let key = GenericArray::from_slice(&okm);
    let cipher = Aes256Gcm::new(key);

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Alice's secret message to Bob
    let plaintext = b"We're in a spot of bother.";

    // Alice encrypts her message
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("encryption failure!");

    // Alice prepares the full message for transmission
    let kyber_encrypted_secret_string = Base64::encode_string(kyber_encrypted_secret.as_slice());
    let nonce_string = Base64::encode_string(&nonce_bytes);
    let encrypted_message = Base64::encode_string(ciphertext.as_ref());
    let full_message = format!(
        "{}:{}:{}",
        kyber_encrypted_secret_string, nonce_string, encrypted_message
    );

    println!("\nAlice's encrypted message: {}", full_message);
    println!("\nMessage is sent to Bob...");

    // --- Message transmission happens here ---

    println!("\nBob receives the message and decrypts it...");

    // Bob splits up the received message components
    let parts: Vec<&str> = full_message.split(':').collect();
    let received_kyber_encrypted_secret_string = parts[0];
    let received_nonce_string = parts[1];
    let received_ciphertext_string = parts[2];

    // Bob recovers the ML-KEM ciphertext
    let ct_bytes = Base64::decode_vec(received_kyber_encrypted_secret_string).unwrap();
    let mut received_kyber_encrypted_secret = kyber_encrypted_secret.clone();
    received_kyber_encrypted_secret.copy_from_slice(&ct_bytes);

    // Bob uses his decapsulation key (private key) to recover the shared secret
    let bob_shared_secret = bob_kyber_dk
        .decapsulate(&received_kyber_encrypted_secret)
        .unwrap();

    // Bob derives the same encryption key from the shared secret
    let hk = Hkdf::<Sha256>::new(None, &bob_shared_secret); // HMAC-based Key derivation
    let mut okm = [0u8; 32]; // Output key material
    hk.expand(b"aes256gcm key", &mut okm)
        .expect("HKDF expand failed");

    let key = GenericArray::from_slice(&okm);
    let cipher = Aes256Gcm::new(key);

    // Bob recovers the nonce and ciphertext
    let received_nonce_bytes = Base64::decode_vec(received_nonce_string).unwrap();
    let received_nonce = Nonce::from_slice(&received_nonce_bytes);
    let received_ciphertext = Base64::decode_vec(received_ciphertext_string).unwrap();

    // Bob decrypts the message
    let decrypted_data = cipher
        .decrypt(received_nonce, received_ciphertext.as_ref())
        .expect("decryption failure!");

    let decoded_message = String::from_utf8(decrypted_data).unwrap();
    println!(
        "\nBob successfully decrypted Alice's message: {:?}",
        decoded_message
    );
}
