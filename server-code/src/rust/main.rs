use clap::{App, Arg, SubCommand};
use serde_json;
use std::io::{self, Write};

mod crypto;
mod error;
mod message;
mod utils;

use crypto::CryptoSystem;
use message::{Message, EncryptionType, SignatureType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("Crypto API")
        .version("1.0")
        .about("Advanced Hybrid Encryption System")
        .subcommand(
            SubCommand::with_name("encrypt")
                .about("Encrypt a message")
                .arg(
                    Arg::with_name("message")
                        .short("m")
                        .long("message")
                        .value_name("MESSAGE")
                        .help("Message to encrypt")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("public-key")
                        .short("k")
                        .long("public-key")
                        .value_name("PUBLIC_KEY")
                        .help("Recipient's public key")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("method")
                        .short("e")
                        .long("encryption-method")
                        .value_name("METHOD")
                        .help("Encryption method (rust_aes, rust_rsa, hybrid)")
                        .takes_value(true)
                        .default_value("hybrid"),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .about("Decrypt a message")
                .arg(
                    Arg::with_name("encrypted-content")
                        .short("c")
                        .long("encrypted-content")
                        .value_name("CONTENT")
                        .help("Encrypted message content")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("encrypted-key")
                        .short("k")
                        .long("encrypted-key")
                        .value_name("KEY")
                        .help("Encrypted AES key")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("iv")
                        .short("i")
                        .long("iv")
                        .value_name("IV")
                        .help("Initialization vector")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("private-key")
                        .short("p")
                        .long("private-key")
                        .value_name("PRIVATE_KEY")
                        .help("Your private key")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("w")
                        .long("password")
                        .value_name("PASSWORD")
                        .help("Password for private key")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("sign")
                .about("Sign a message")
                .arg(
                    Arg::with_name("message")
                        .short("m")
                        .long("message")
                        .value_name("MESSAGE")
                        .help("Message to sign")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("private-key")
                        .short("k")
                        .long("private-key")
                        .value_name("PRIVATE_KEY")
                        .help("Your private key")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("w")
                        .long("password")
                        .help("Password for private key")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("verify")
                .about("Verify a message signature")
                .arg(
                    Arg::with_name("message")
                        .short("m")
                        .long("message")
                        .value_name("MESSAGE")
                        .help("Original message")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("signature")
                        .short("s")
                        .long("signature")
                        .value_name("SIGNATURE")
                        .help("Message signature")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("public-key")
                        .short("k")
                        .long("public-key")
                        .value_name("PUBLIC_KEY")
                        .help("Sender's public key")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("generate-keys")
                .about("Generate RSA key pair")
                .arg(
                    Arg::with_name("output-dir")
                        .short("o")
                        .long("output-dir")
                        .value_name("DIRECTORY")
                        .help("Output directory for keys")
                        .takes_value(true)
                        .default_value("keys"),
                ),
        )
        .subcommand(
            SubCommand::with_name("info")
                .about("Show system information"),
        )
        .get_matches();

    match matches.subcommand() {
        ("encrypt", Some(encrypt_matches)) => {
            let message_content = encrypt_matches.value_of("message").unwrap();
            let public_key = encrypt_matches.value_of("public-key").unwrap();
            let method = encrypt_matches.value_of("method").unwrap();

            let encryption_type = match method {
                "rust_aes" => EncryptionType::RustAES,
                "rust_rsa" => EncryptionType::RustRSA,
                "hybrid" => EncryptionType::Hybrid,
                _ => EncryptionType::Hybrid,
            };

            let crypto = CryptoSystem::new(
                encryption_type,
                SignatureType::RustSHA512,
                1024,
            );

            let message = Message::new(
                "sender".to_string(),
                "recipient".to_string(),
                message_content.to_string(),
            );

            match crypto.encrypt_message(&message, public_key, false) {
                Ok(encrypted) => {
                    let json = serde_json::to_string_pretty(&encrypted)?;
                    println!("{}", json);
                }
                Err(e) => {
                    eprintln!("Encryption failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        ("decrypt", Some(decrypt_matches)) => {
            let encrypted_content = decrypt_matches.value_of("encrypted-content").unwrap();
            let encrypted_key = decrypt_matches.value_of("encrypted-key").unwrap();
            let iv = decrypt_matches.value_of("iv").unwrap();
            let private_key = decrypt_matches.value_of("private-key").unwrap();
            let password = decrypt_matches.value_of("password").unwrap();

            let crypto = CryptoSystem::default();

            // Create encrypted message structure
            let encrypted_message = message::EncryptedMessage {
                encrypted_content: encrypted_content.to_string(),
                encrypted_key: encrypted_key.to_string(),
                iv: iv.to_string(),
                tag: "".to_string(),
                timestamp: utils::get_current_timestamp(),
                encryption_type: EncryptionType::RustAES,
                algorithm: "AES-256-GCM".to_string(),
            };

            match crypto.decrypt_message(&encrypted_message, private_key, password) {
                Ok(decrypted) => {
                    let result = serde_json::json!({
                        "success": true,
                        "decrypted_content": decrypted
                    });
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                Err(e) => {
                    let result = serde_json::json!({
                        "success": false,
                        "error": e.to_string()
                    });
                    eprintln!("{}", serde_json::to_string_pretty(&result)?);
                    std::process::exit(1);
                }
            }
        }

        ("sign", Some(sign_matches)) => {
            let message_content = sign_matches.value_of("message").unwrap();
            let private_key = sign_matches.value_of("private-key").unwrap();
            let password = sign_matches.value_of("password").unwrap();

            let crypto = CryptoSystem::default();

            match crypto.sign_message(message_content, private_key, password) {
                Ok(signed) => {
                    let json = serde_json::to_string_pretty(&signed)?;
                    println!("{}", json);
                }
                Err(e) => {
                    eprintln!("Signing failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        ("verify", Some(verify_matches)) => {
            let message_content = verify_matches.value_of("message").unwrap();
            let signature = verify_matches.value_of("signature").unwrap();
            let public_key = verify_matches.value_of("public-key").unwrap();

            let crypto = CryptoSystem::default();

            let signed_message = message::SignedMessage {
                message: message_content.to_string(),
                signature: signature.to_string(),
                timestamp: utils::get_current_timestamp(),
                signature_type: SignatureType::RustSHA512,
            };

            match crypto.verify_signature(&signed_message, public_key) {
                Ok(is_valid) => {
                    let result = serde_json::json!({
                        "success": true,
                        "is_valid": is_valid
                    });
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                Err(e) => {
                    let result = serde_json::json!({
                        "success": false,
                        "error": e.to_string()
                    });
                    eprintln!("{}", serde_json::to_string_pretty(&result)?);
                    std::process::exit(1);
                }
            }
        }

        ("generate-keys", Some(key_matches)) => {
            let output_dir = key_matches.value_of("output-dir").unwrap();
            
            println!("Generating RSA-4096 key pair...");
            println!("Output directory: {}", output_dir);
            
            // This would implement key generation
            // For now, just show a message
            println!("Key generation not yet implemented");
        }

        ("info", Some(_)) => {
            let crypto = CryptoSystem::default();
            let info = crypto.get_system_info();
            
            println!("🔐 Crypto API System Information");
            println!("=================================");
            println!("Preferred Encryption: {:?}", info.preferred_encryption);
            println!("Preferred Signature: {:?}", info.preferred_signature);
            println!("Performance Threshold: {} bytes", info.performance_threshold);
            println!("\nSupported Algorithms:");
            for algorithm in &info.supported_algorithms {
                println!("  • {}", algorithm);
            }
        }

        _ => {
            println!("Crypto API - Advanced Hybrid Encryption System");
            println!("Version 1.0.0");
            println!("\nUse --help for more information");
            println!("\nAvailable commands:");
            println!("  encrypt    - Encrypt a message");
            println!("  decrypt    - Decrypt a message");
            println!("  sign       - Sign a message");
            println!("  verify     - Verify a signature");
            println!("  generate-keys - Generate RSA key pair");
            println!("  info       - Show system information");
        }
    }

    Ok(())
}
