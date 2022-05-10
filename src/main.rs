use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};
use clap::{Parser, Subcommand};
use rand::prelude::*;
use std::io::{Read, Write};
use thiserror::Error;

/// Tool for encrypting and decrypting files utilizing ChaCha20
#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file
    En {
        /// File to decrypt
        #[clap(long, short)]
        file: String,

        /// Private key
        #[clap(long, short, group = "key_g")]
        key: Option<String>,

        /// Private key from a file
        #[clap(long, group = "key_g")]
        key_file: Option<String>,
    },

    /// Decrypt a file
    De {
        /// File to decrypt
        #[clap(long, short)]
        file: String,

        /// Private key
        #[clap(long, short, group = "key_g")]
        key: Option<String>,

        /// Private key from a file
        #[clap(long, group = "key_g")]
        key_file: Option<String>,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("Could not read file {0}")]
    FileReadError(String),

    #[error("Could not write file {0}")]
    FileWriteError(String),

    #[error("Key length is invalid (Actual: {0} Expected: {1})")]
    KeyLenError(usize, usize),

    #[error("Could not encrypt data")]
    EncryptionError,

    #[error("Could not decrypt data")]
    DecryptionError,
}

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

fn get_key(raw_key: Option<String>, key_file: Option<String>) -> Result<Key, CliError> {
    let key = if let Some(raw_key) = raw_key {
        raw_key.chars().map(|c| c as u8).collect()
    } else {
        read_bytes(&key_file.unwrap())?
    };

    match key.len() {
        KEY_LEN => Ok(*Key::from_slice(&key)),
        len => Err(CliError::KeyLenError(len, KEY_LEN)),
    }
}

fn new_rand_nonce() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..NONCE_LEN).map(|_| rng.gen()).collect()
}

fn read_bytes(file_name: &String) -> Result<Vec<u8>, CliError> {
    let file =
        std::fs::File::open(&file_name).map_err(|_| CliError::FileReadError(file_name.clone()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .map_err(|_| CliError::FileReadError(file_name.clone()))?;
    Ok(data)
}

fn write_bytes(file_name: &String, text: Vec<u8>) -> Result<(), CliError> {
    let mut crypt_file = std::fs::File::create(&file_name)
        .map_err(|_| CliError::FileWriteError(file_name.clone()))?;
    crypt_file
        .write(text.as_ref())
        .map_err(|_| CliError::FileWriteError(file_name.clone()))?;
    Ok(())
}

fn encrypt(
    file_name: String,
    raw_key: Option<String>,
    key_file: Option<String>,
) -> Result<(), CliError> {
    let cipher = ChaCha20Poly1305::new(&get_key(raw_key, key_file)?);
    let nonce = new_rand_nonce();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), read_bytes(&file_name)?.as_ref())
        .map_err(|_| CliError::EncryptionError)?;
    write_bytes(
        &format!("{}.crypt", &file_name),
        [nonce, ciphertext].concat(),
    )
}

fn decrypt(
    file_name: String,
    raw_key: Option<String>,
    key_file: Option<String>,
) -> Result<(), CliError> {
    let cipher = ChaCha20Poly1305::new(&get_key(raw_key, key_file)?);
    let data = read_bytes(&format!("{}.crypt", &file_name))?;
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let plaintext = cipher
        .decrypt(&nonce, &data[NONCE_LEN..])
        .map_err(|_| CliError::DecryptionError)?;
    write_bytes(&file_name, plaintext)
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::En {
            file,
            key,
            key_file,
        } => encrypt(file, key, key_file),
        Command::De {
            file,
            key,
            key_file,
        } => decrypt(file, key, key_file),
    };

    match result {
        Ok(_) => println!("SUCCESS"),
        Err(error) => println!("ERROR: {}", error),
    }
}
