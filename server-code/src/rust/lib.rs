//! # Crypto API - Advanced Encryption System
//! 
//! This library provides a comprehensive encryption system with:
//! - RSA-4096 asymmetric encryption
//! - AES-256-GCM symmetric encryption  
//! - SHA-512 digital signatures
//! - PBKDF2 key derivation
//! - Secure key management

pub mod crypto;
pub mod key_management;
pub mod message;
pub mod user;
pub mod error;
pub mod utils;

pub use crypto::CryptoSystem;
pub use key_management::KeyManager;
pub use message::{Message, EncryptedMessage, SignedMessage};
pub use user::User;
pub use error::{CryptoError, Result};

// Re-export commonly used types
pub use rsa::{RsaPrivateKey, RsaPublicKey};
pub use aes_gcm::{Aes256Gcm, Key, Nonce};
pub use sha2::{Sha512, Digest};
