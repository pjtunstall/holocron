mod decryption;
mod encryption;
mod keys;
mod options;

use std::env;

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
        "-c" => options::c_for_clear_all_keys(),
        "-g" => options::g_for_generate_keys(&args, &usage),
        "-eff" => options::eff_for_encrypt_from_file_to_file(&args, &usage),
        "-etf" => options::etf_for_encrypt_from_terminal_to_file(&args, &usage),
        "-ett" => options::ett_for_encrypt_from_terminal_to_terminal(&args, &usage),
        "-dff" => options::dff_for_decrypt_from_file_to_file(&args, &usage),
        "-dft" => options::dft_for_decrypt_from_file_to_terminal(&args, &usage),
        _ => println!("Command not found.\n{}", usage),
    }
}
