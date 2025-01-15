use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, generic_array::typenum::U12};
use rand::RngCore;
use hmac::Hmac; // Add this for Hmac usage with pbkdf2
use pbkdf2::pbkdf2;
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use std::io::{self, Write};
use base64;
use rand::Rng; // Add this for the gen_range method

#[derive(Serialize, Deserialize)]
struct PasswordEntry {
    website: String,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedEntry {
    ciphertext: String,
    nonce: String,
    salt: String,
}

fn derive_key(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut key = [0u8; 32]; // 256-bit key for AES-256
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 100_000, &mut key);
    *Key::<Aes256Gcm>::from_slice(&key) // Specify the key size explicitly
}

fn encrypt_data(plaintext: &str, key: &Key<Aes256Gcm>, nonce: &Nonce<U12>) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    cipher.encrypt(nonce, plaintext.as_bytes()).expect("encryption failure!")
}

fn decrypt_data(ciphertext: &[u8], key: &Key<Aes256Gcm>, nonce: &Nonce<U12>) -> String {
    let cipher = Aes256Gcm::new(key);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext).expect("decryption failure!");
    String::from_utf8(decrypted_bytes).expect("invalid UTF-8")
}

fn generate_password(length: usize, include_symbols: bool) -> String {
    let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let digits = "0123456789";
    let symbols = "!@#$%^&*()_-+=<>?";

    let mut all_chars = String::from(letters) + digits;
    if include_symbols {
        all_chars += symbols;
    }

    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..all_chars.len()); // Fix missing gen_range method
            all_chars.chars().nth(idx).unwrap()
        })
        .collect()
}

fn load_entries(master_password: &str) -> Vec<PasswordEntry> {
    if !std::path::Path::new("passwords.json").exists() {
        return Vec::new();
    }

    let contents = std::fs::read_to_string("passwords.json").expect("Unable to read file");
    let encrypted_entry: EncryptedEntry = serde_json::from_str(&contents).unwrap();

    let ciphertext = base64::decode(&encrypted_entry.ciphertext).unwrap();
    let nonce_bytes = base64::decode(&encrypted_entry.nonce).unwrap();
    let salt = base64::decode(&encrypted_entry.salt).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = derive_key(master_password, &salt);
    let decrypted_data = decrypt_data(&ciphertext, &key, &nonce);
    serde_json::from_str(&decrypted_data).unwrap_or_else(|_| Vec::new())
}

fn save_entries(entries: &Vec<PasswordEntry>, master_password: &str) {
    let serialized_entries = serde_json::to_string(entries).unwrap();

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(master_password, &salt);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = encrypt_data(&serialized_entries, &key, &nonce);

    let encrypted_entry = EncryptedEntry {
        ciphertext: base64::encode(&ciphertext),
        nonce: base64::encode(&nonce_bytes),
        salt: base64::encode(&salt),
    };

    let serialized = serde_json::to_string(&encrypted_entry).unwrap();
    std::fs::write("passwords.json", serialized).expect("Unable to write file");
}

fn add_entry(entries: &mut Vec<PasswordEntry>) {
    let mut website = String::new();
    let mut username = String::new();
    let mut password = String::new();

    print!("Enter website: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut website).unwrap();

    print!("Enter username: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut username).unwrap();

    print!("Enter password (leave blank to generate one): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim();

    let password = if password.is_empty() {
        generate_password(12, true)
    } else {
        password.to_string()
    };

    entries.push(PasswordEntry {
        website: website.trim().to_string(),
        username: username.trim().to_string(),
        password,
    });

    println!("Entry added successfully!");
}

fn view_entries(entries: &Vec<PasswordEntry>) {
    for (i, entry) in entries.iter().enumerate() {
        println!("Entry {}:", i + 1);
        println!("Website: {}", entry.website);
        println!("Username: {}", entry.username);
        println!("Password: {}", entry.password);
        println!("------------------------");
    }
}

fn delete_entry(entries: &mut Vec<PasswordEntry>) {
    print!("Enter the number of the entry to delete: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    if let Ok(index) = input.trim().parse::<usize>() {
        if index > 0 && index <= entries.len() {
            entries.remove(index - 1);
            println!("Entry deleted.");
        } else {
            println!("Invalid entry number.");
        }
    } else {
        println!("Invalid input.");
    }
}

fn main() {
    print!("Enter master password: ");
    io::stdout().flush().unwrap();
    let mut master_password = String::new();
    io::stdin().read_line(&mut master_password).unwrap();
    let master_password = master_password.trim();

    let mut entries = load_entries(master_password);

    loop {
        println!("Password Manager Options:");
        println!("1. Add Entry");
        println!("2. View Entries");
        println!("3. Delete Entry");
        println!("4. Exit");

        print!("Select an option: ");
        io::stdout().flush().unwrap();

        let mut option = String::new();
        io::stdin().read_line(&mut option).unwrap();

        match option.trim() {
            "1" => add_entry(&mut entries),
            "2" => view_entries(&entries),
            "3" => delete_entry(&mut entries),
            "4" => {
                save_entries(&entries, master_password);
                break;
            }
            _ => println!("Invalid option."),
        }
    }
}
