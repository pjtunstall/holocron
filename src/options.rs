use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

use crate::decryption;
use crate::encryption;
use crate::keys;

pub fn c_for_clear_all_keys() {
    if keys::confirm_deletion() {
        match keys::delete_keys_folder() {
            Ok(_) => println!("Keys folder successfully deleted."),
            Err(e) => eprintln!("Failed to delete keys folder:\n{}", e),
        }
    } else {
        println!("Exiting without deleting keys.");
    }
}

pub fn g_for_generate_keys(args: &Vec<String>, usage: &str) {
    if args.len() < 3 {
        println!(
            "This command requires three arguments, including the program name.\n{}",
            &usage
        );
        return;
    }

    let username = &args[2];

    if let Err(e) = keys::generate_keys(username) {
        eprintln!("Error: Failed to generate keys for `{}`:\n{}", username, e);
    } else {
        println!("Keys successfully generated for `{}`.", username);
    }
}

pub fn eff_for_encrypt_from_file_to_file(args: &Vec<String>, usage: &str) {
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

    let (kyber_ek, rsa_ek) = match keys::parse_public_key(&file_path.to_string_lossy()) {
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

    let encrypted = match encryption::encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
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

pub fn ett_for_encrypt_from_terminal_to_terminal(args: &Vec<String>, usage: &str) {
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
    let (kyber_ek, rsa_ek) = match keys::parse_public_key(&key_file_path) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse public key file at: `{}`\n{}",
                key_file_path, e
            );
            return;
        }
    };

    let encrypted = match encryption::encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
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

pub fn etf_for_encrypt_from_terminal_to_file(args: &Vec<String>, usage: &str) {
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
    let (kyber_ek, rsa_ek) = match keys::parse_public_key(&key_file_path) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse public key file at: `{}`\n{}",
                key_file_path, e
            );
            return;
        }
    };

    let encrypted = match encryption::encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
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

    let path = "message.asc";
    let mut file = match File::create(path) {
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

    println!("Ciphertext saved to `{}`.", path);
}

pub fn dff_for_decrypt_from_file_to_file(args: &Vec<String>, usage: &str) {
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

    let (kyber_dk, rsa_dk) = match keys::parse_secret_key(&file_path.to_string_lossy()) {
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

    let decrypted = match decryption::decrypt(&ciphertext, &kyber_dk, &rsa_dk) {
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

pub fn dft_for_decrypt_from_file_to_terminal(args: &Vec<String>, usage: &str) {
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

    let (kyber_dk, rsa_dk) = match keys::parse_secret_key(&file_path.to_string_lossy()) {
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

    let decrypted = match decryption::decrypt(&ciphertext, &kyber_dk, &rsa_dk) {
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

    struct ConditionalCleanup {
        cleanup: bool,
    }

    impl ConditionalCleanup {
        fn new() -> Self {
            Self { cleanup: false }
        }

        fn disarm(&mut self) {
            self.cleanup = true;
        }
    }

    impl Drop for ConditionalCleanup {
        fn drop(&mut self) {
            // Delete any keys generated in by the test.
            if self.cleanup {
                if let Err(e) = fs::remove_file("keys/bob_public_key.asc") {
                    eprintln!("Error removing public key: {}", e);
                }
                if let Err(e) = fs::remove_file("keys/bob_secret_key.asc") {
                    eprintln!("Error removing secret key:\n{}", e);
                }

                // Check if the "keys" directory exists and remove it if it's empty..
                if let Ok(entries) = fs::read_dir("keys") {
                    if entries.count() == 0 {
                        if let Err(e) = fs::remove_dir("keys") {
                            eprintln!("Error removing `keys` directory:\n{}", e);
                        }
                    }
                } else {
                    eprintln!("Failed to read `keys` directory.");
                }
            }
        }
    }

    // Generate keys and save them, then load and parse public key, then encrypt and decrypt a message with it. Check that the decrypted message is the same as the original. Delete any keys generated in by the test.
    // Note: this test assumed that keys for `bob` don't already exist in the `keys` folder. If they do, you can delete them or more them elsewhere while you run the test.
    #[test]
    fn test_holocron() {
        let username = "bob";

        let mut guard = ConditionalCleanup::new();
        std::env::set_current_dir(std::env::current_dir().unwrap()).unwrap();
        let (kyber_ek, kyber_dk, rsa_ek, rsa_dk) = keys::generate_keys(username).unwrap();
        guard.disarm(); // Only allow keys to be deleted if they were generated by the test.

        let public_key_path = format!("keys/{}_public_key.asc", username);
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
}
