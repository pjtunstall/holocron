use std::fs;

use base64ct::{Base64, Encoding};
use rand::rngs::OsRng;
use rand::RngCore;

use holocron::{decryption, encryption, keys};

struct ConditionalCleanup {
    activated: bool,
    username: String,
}

impl ConditionalCleanup {
    fn new(username: String) -> Self {
        Self {
            activated: false,
            username,
        }
    }
}

impl Drop for ConditionalCleanup {
    fn drop(&mut self) {
        // Delete any keys generated by the test.
        if self.activated {
            let public_path = format!("keys/{}_public_key.asc", &self.username);
            let secret_path = format!("keys/{}_secret_key.asc", &self.username);

            if let Err(e) = fs::remove_file(&public_path) {
                eprintln!("Error removing public key: {}", e);
            }
            if let Err(e) = fs::remove_file(&secret_path) {
                eprintln!("Error removing secret key: {}", e);
            }

            // Check if the `keys` directory exists and remove it if it's empty.
            if let Ok(entries) = fs::read_dir("keys") {
                if entries.count() == 0 {
                    if let Err(e) = fs::remove_dir("keys") {
                        eprintln!("Error removing `keys` directory: {}", e);
                    }
                }
            } else {
                eprintln!("Failed to read `keys` directory.");
            }
        }
    }
}

// Generate keys and save them, then load and parse public key, then encrypt and decrypt a message with it. Check that the decrypted message is the same as the original. Delete any keys generated by the test.
#[test]
fn test_holocron() {
    // Create a long random name to avoid clash with user-generated keys.
    let mut buffer = vec![0u8; 16];
    OsRng.fill_bytes(&mut buffer);
    let username = Base64::encode_string(&buffer);

    let mut cleanup = ConditionalCleanup::new(username);
    std::env::set_current_dir(std::env::current_dir().unwrap()).unwrap();
    let (kyber_ek, kyber_dk, rsa_ek, rsa_dk) = keys::generate_keys(&cleanup.username).unwrap();
    cleanup.activated = true; // Only allow keys to be deleted if they were generated by the test.

    let public_key_path = format!("keys/{}_public_key.asc", &cleanup.username);
    let (loaded_kyber_ek, loaded_rsa_ek) = keys::parse_public_key(&public_key_path).unwrap();

    assert_eq!(kyber_ek, loaded_kyber_ek, "Public key mismatch: Kyber");
    assert_eq!(rsa_ek, loaded_rsa_ek, "Public key mismatch: RSA");

    let alice_plaintext = "We're in a spot of bother.";

    match encryption::encrypt(alice_plaintext.as_bytes(), &loaded_kyber_ek, &loaded_rsa_ek) {
        Ok(wire_message) => match decryption::decrypt(&wire_message, &kyber_dk, &rsa_dk) {
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
