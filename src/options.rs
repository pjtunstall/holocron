use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

use crate::{decryption, encryption, keys};

pub fn c_for_clear_all_keys() {
    if keys::confirm_deletion() {
        match keys::delete_keys_folder() {
            Ok(_) => println!("Keys folder successfully deleted."),
            Err(e) => eprintln!("Failed to delete keys folder: {}", e),
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
        eprintln!("Error: Failed to generate keys for `{}`: {}", username, e);
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
            println!("Failed to get current directory: {}", e);
            return;
        }
    };

    if !file_path.exists() {
        println!("Public key file not found at `{}`", file_path.display());
        return;
    }

    let plaintext = match fs::read_to_string(plaintext_file) {
        Ok(content) => content,
        Err(e) => {
            println!("Failed to read plaintext file `{}`: {}", plaintext_file, e);
            return;
        }
    };

    let (kyber_ek, rsa_ek) = match keys::parse_public_key(&file_path.to_string_lossy()) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse public key at `{}`: {}",
                file_path.display(),
                e
            );
            return;
        }
    };

    let encrypted = match encryption::encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Encryption failed: {}", e);
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
                "Failed to create ciphertext file `{}`: {}",
                ciphertext_file, e
            );
            return;
        }
    };

    if let Err(e) = file.write_all(ciphertext.as_bytes()) {
        println!(
            "Failed to write ciphertext to file `{}`: {}",
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
            println!("Failed to get current directory: {}", e);
            return;
        }
    };

    let key_file_path = file_path.to_string_lossy().to_string();
    let (kyber_ek, rsa_ek) = match keys::parse_public_key(&key_file_path) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse public key file at `{}`: {}",
                key_file_path, e
            );
            return;
        }
    };

    let encrypted = match encryption::encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Encryption failed: {}", e);
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
            println!("Failed to get current directory: {}", e);
            return;
        }
    };

    let key_file_path = file_path.to_string_lossy().to_string();
    let (kyber_ek, rsa_ek) = match keys::parse_public_key(&key_file_path) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse public key file at `{}`: {}",
                key_file_path, e
            );
            return;
        }
    };

    let encrypted = match encryption::encrypt(plaintext.as_bytes(), &kyber_ek, &rsa_ek) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Encryption failed: {}", e);
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
            println!("Failed to create ciphertext file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(ciphertext.as_bytes()) {
        println!("Failed to write ciphertext to file: {}", e);
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
            println!("Failed to get current directory: {}", e);
            return;
        }
    };

    if !file_path.exists() {
        println!("Secret key file not found at `{}`", file_path.display());
        return;
    }

    let ciphertext = match fs::read_to_string(ciphertext_file) {
        Ok(content) => content,
        Err(e) => {
            println!(
                "Failed to read ciphertext file `{}`: {}",
                ciphertext_file, e
            );
            return;
        }
    };

    let (kyber_dk, rsa_dk) = match keys::parse_secret_key(&file_path.to_string_lossy()) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse secret key file `{}`: {}",
                file_path.display(),
                e
            );
            return;
        }
    };

    let decrypted = match decryption::decrypt(&ciphertext, &kyber_dk, &rsa_dk) {
        Ok(message) => message,
        Err(e) => {
            println!("Failed to decrypt message: {}", e);
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
                "Failed to create plaintext file `{}`: {}",
                decrypted_file, e
            );
            return;
        }
    };

    if let Err(e) = file.write_all(decrypted.as_bytes()) {
        println!(
            "Failed to write to plaintext file `{}`: {}",
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
            println!("Failed to get current directory: {}", e);
            return;
        }
    };

    if !file_path.exists() {
        println!("Secret key file not found at `{}`", file_path.display());
        return;
    }

    let ciphertext = match fs::read_to_string(ciphertext_file) {
        Ok(content) => content,
        Err(e) => {
            println!(
                "Failed to read ciphertext file `{}`: {}",
                ciphertext_file, e
            );
            return;
        }
    };

    let (kyber_dk, rsa_dk) = match keys::parse_secret_key(&file_path.to_string_lossy()) {
        Ok(keys) => keys,
        Err(e) => {
            println!(
                "Failed to parse secret key file `{}`: {}",
                file_path.display(),
                e
            );
            return;
        }
    };

    let decrypted = match decryption::decrypt(&ciphertext, &kyber_dk, &rsa_dk) {
        Ok(message) => message,
        Err(e) => {
            println!("Failed to decrypt the message: {}", e);
            return;
        }
    };

    println!("{}", decrypted);
}
