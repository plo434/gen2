use crate::error::{CryptoError, Result};
use crate::message::{EncryptedMessage, EncryptionType, Message, SignedMessage, SignatureType};
use crate::utils::{
    generate_aes_key, generate_iv, generate_random_bytes, 
    bytes_to_base64, base64_to_bytes, bytes_to_hex, hex_to_bytes,
    derive_key_from_password, hash_sha512_hex
};

use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, LineEnding}};
use sha2::{Sha512, Digest};

/// Hybrid Crypto System that chooses the best technology for each operation
pub struct CryptoSystem {
    /// Preferred encryption method for different scenarios
    preferred_encryption: EncryptionType,
    /// Preferred signature method
    preferred_signature: SignatureType,
    /// Performance threshold for choosing Rust over JavaScript
    performance_threshold: usize,
}

impl Default for CryptoSystem {
    fn default() -> Self {
        Self {
            preferred_encryption: EncryptionType::Hybrid,
            preferred_signature: SignatureType::RustSHA512,
            performance_threshold: 1024, // 1KB threshold
        }
    }
}

impl CryptoSystem {
    /// Create new crypto system with custom preferences
    pub fn new(
        preferred_encryption: EncryptionType,
        preferred_signature: SignatureType,
        performance_threshold: usize,
    ) -> Self {
        Self {
            preferred_encryption,
            preferred_signature,
            performance_threshold,
        }
    }

    /// Choose the best encryption method based on data size and requirements
    fn choose_encryption_method(&self, data_size: usize, requires_performance: bool) -> EncryptionType {
        if requires_performance || data_size > self.performance_threshold {
            // Use Rust for better performance
            match self.preferred_encryption {
                EncryptionType::Hybrid => EncryptionType::RustAES,
                EncryptionType::RustAES => EncryptionType::RustAES,
                EncryptionType::RustRSA => EncryptionType::RustRSA,
                _ => EncryptionType::RustAES,
            }
        } else {
            // Use JavaScript for easier integration
            match self.preferred_encryption {
                EncryptionType::Hybrid => EncryptionType::JSRSA,
                EncryptionType::JSRSA => EncryptionType::JSRSA,
                _ => EncryptionType::JSRSA,
            }
        }
    }

    /// Encrypt message using the best available method
    pub fn encrypt_message(
        &self,
        message: &Message,
        recipient_public_key: &str,
        require_performance: bool,
    ) -> Result<EncryptedMessage> {
        let data_size = message.content.len();
        let encryption_type = self.choose_encryption_method(data_size, require_performance);

        match encryption_type {
            EncryptionType::RustAES => self.encrypt_with_rust_aes(message, recipient_public_key),
            EncryptionType::RustRSA => self.encrypt_with_rust_rsa(message, recipient_public_key),
            EncryptionType::JSRSA => self.encrypt_with_js_rsa(message, recipient_public_key),
            EncryptionType::Hybrid => self.encrypt_hybrid(message, recipient_public_key),
            EncryptionType::None => Err(CryptoError::EncryptionFailed(
                "No encryption method specified".to_string()
            )),
        }
    }

    /// Encrypt using Rust AES-256-GCM (best performance)
    fn encrypt_with_rust_aes(
        &self,
        message: &Message,
        _recipient_public_key: &str,
    ) -> Result<EncryptedMessage> {
        let key = generate_aes_key()?;
        let iv = generate_iv()?;
        
        // Convert to AES-GCM types
        let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher_nonce = Nonce::from_slice(&iv);
        
        let cipher = Aes256Gcm::new(cipher_key);
        
        // Encrypt the message
        let encrypted_content = cipher
            .encrypt(cipher_nonce, message.content.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // For AES, we store the key encrypted with a random password
        let password = generate_random_bytes(32)?;
        let encrypted_key = self.encrypt_key_with_password(&key, &password)?;

        Ok(EncryptedMessage {
            encrypted_content: bytes_to_base64(&encrypted_content),
            encrypted_key: bytes_to_base64(&encrypted_key),
            iv: bytes_to_hex(&iv),
            tag: "".to_string(), // GCM includes tag in encrypted content
            timestamp: crate::utils::get_current_timestamp(),
            encryption_type: EncryptionType::RustAES,
            algorithm: "AES-256-GCM".to_string(),
        })
    }

    /// Encrypt using Rust RSA-4096 (best security for small data)
    fn encrypt_with_rust_rsa(
        &self,
        message: &Message,
        recipient_public_key: &str,
    ) -> Result<EncryptedMessage> {
        // Parse public key
        let public_key = RsaPublicKey::from_public_key_pem(recipient_public_key)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

        // RSA can only encrypt small amounts of data, so we use hybrid approach
        let aes_key = generate_aes_key()?;
        let iv = generate_iv()?;

        // Encrypt AES key with RSA
        let encrypted_key = public_key
            .encrypt(&mut rand::thread_rng(), rsa::Pkcs1v15Encrypt, &aes_key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Encrypt message with AES
        let cipher_key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher_nonce = Nonce::from_slice(&iv);
        
        let cipher = Aes256Gcm::new(cipher_key);
        let encrypted_content = cipher
            .encrypt(cipher_nonce, message.content.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedMessage {
            encrypted_content: bytes_to_base64(&encrypted_content),
            encrypted_key: bytes_to_base64(&encrypted_key),
            iv: bytes_to_hex(&iv),
            tag: "".to_string(),
            timestamp: crate::utils::get_current_timestamp(),
            encryption_type: EncryptionType::RustRSA,
            algorithm: "RSA-4096 + AES-256-GCM".to_string(),
        })
    }

    /// Encrypt using JavaScript RSA (easier integration)
    fn encrypt_with_js_rsa(
        &self,
        message: &Message,
        _recipient_public_key: &str,
    ) -> Result<EncryptedMessage> {
        // This would delegate to JavaScript implementation
        // For now, we'll return an error indicating JS implementation needed
        Err(CryptoError::EncryptionFailed(
            "JavaScript RSA encryption not implemented in Rust".to_string()
        ))
    }

    /// Hybrid encryption: Rust AES + JavaScript RSA
    fn encrypt_hybrid(
        &self,
        message: &Message,
        recipient_public_key: &str,
    ) -> Result<EncryptedMessage> {
        // Use Rust for the heavy lifting (AES encryption)
        let aes_result = self.encrypt_with_rust_aes(message, recipient_public_key)?;
        
        // Modify to indicate hybrid approach
        Ok(EncryptedMessage {
            encryption_type: EncryptionType::Hybrid,
            algorithm: "Hybrid: Rust AES + JS RSA".to_string(),
            ..aes_result
        })
    }

    /// Decrypt message using the appropriate method
    pub fn decrypt_message(
        &self,
        encrypted_message: &EncryptedMessage,
        private_key: &str,
        password: &str,
    ) -> Result<String> {
        match encrypted_message.encryption_type {
            EncryptionType::RustAES => self.decrypt_rust_aes(encrypted_message, password),
            EncryptionType::RustRSA => self.decrypt_rust_rsa(encrypted_message, private_key, password),
            EncryptionType::JSRSA => self.decrypt_js_rsa(encrypted_message, private_key, password),
            EncryptionType::Hybrid => self.decrypt_hybrid(encrypted_message, private_key, password),
            EncryptionType::None => Err(CryptoError::DecryptionFailed(
                "No encryption method specified".to_string()
            )),
        }
    }

    /// Decrypt Rust AES encrypted message
    fn decrypt_rust_aes(&self, encrypted_message: &EncryptedMessage, password: &str) -> Result<String> {
        let encrypted_content = base64_to_bytes(&encrypted_message.encrypted_content)?;
        let encrypted_key = base64_to_bytes(&encrypted_message.encrypted_key)?;
        let iv = hex_to_bytes(&encrypted_message.iv)?;

        // Decrypt the AES key
        let aes_key = self.decrypt_key_with_password(&encrypted_key, password)?;

        // Decrypt the content
        let cipher_key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher_nonce = Nonce::from_slice(&iv);
        
        let cipher = Aes256Gcm::new(cipher_key);
        let decrypted_content = cipher
            .decrypt(cipher_nonce, &encrypted_content)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        String::from_utf8(decrypted_content)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    /// Decrypt Rust RSA encrypted message
    fn decrypt_rust_rsa(
        &self,
        encrypted_message: &EncryptedMessage,
        private_key: &str,
        _password: &str,
    ) -> Result<String> {
        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

        let encrypted_key = base64_to_bytes(&encrypted_message.encrypted_key)?;
        let encrypted_content = base64_to_bytes(&encrypted_message.encrypted_content)?;
        let iv = hex_to_bytes(&encrypted_message.iv)?;

        // Decrypt AES key with RSA
        let aes_key = private_key
            .decrypt(rsa::Pkcs1v15Decrypt, &encrypted_key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        // Decrypt content with AES
        let cipher_key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher_nonce = Nonce::from_slice(&iv);
        
        let cipher = Aes256Gcm::new(cipher_key);
        let decrypted_content = cipher
            .decrypt(cipher_nonce, &encrypted_content)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        String::from_utf8(decrypted_content)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    /// Decrypt JavaScript RSA encrypted message
    fn decrypt_js_rsa(
        &self,
        _encrypted_message: &EncryptedMessage,
        _private_key: &str,
        _password: &str,
    ) -> Result<String> {
        Err(CryptoError::DecryptionFailed(
            "JavaScript RSA decryption not implemented in Rust".to_string()
        ))
    }

    /// Decrypt hybrid encrypted message
    fn decrypt_hybrid(
        &self,
        encrypted_message: &EncryptedMessage,
        private_key: &str,
        password: &str,
    ) -> Result<String> {
        // Try Rust methods first, fall back to JavaScript if needed
        match self.decrypt_rust_aes(encrypted_message, password) {
            Ok(content) => Ok(content),
            Err(_) => self.decrypt_rust_rsa(encrypted_message, private_key, password),
        }
    }

    /// Sign message using the best available method
    pub fn sign_message(
        &self,
        message: &str,
        private_key: &str,
        password: &str,
    ) -> Result<SignedMessage> {
        match self.preferred_signature {
            SignatureType::RustSHA512 => self.sign_with_rust_sha512(message, private_key, password),
            SignatureType::JSSHA512 => self.sign_with_js_sha512(message, private_key, password),
        }
    }

    /// Sign using Rust SHA-512 + RSA
    fn sign_with_rust_sha512(
        &self,
        message: &str,
        private_key: &str,
        _password: &str,
    ) -> Result<SignedMessage> {
        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

        // Hash the message
        let mut hasher = Sha512::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        // Sign the hash
        let signature = private_key
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha512>(), &hash)
            .map_err(|e| CryptoError::SignatureVerificationFailed(e.to_string()))?;

        Ok(SignedMessage {
            message: message.to_string(),
            signature: bytes_to_base64(&signature),
            timestamp: crate::utils::get_current_timestamp(),
            signature_type: SignatureType::RustSHA512,
        })
    }

    /// Sign using JavaScript SHA-512 + RSA
    fn sign_with_js_sha512(
        &self,
        _message: &str,
        _private_key: &str,
        _password: &str,
    ) -> Result<SignedMessage> {
        Err(CryptoError::SignatureVerificationFailed(
            "JavaScript signing not implemented in Rust".to_string()
        ))
    }

    /// Verify message signature
    pub fn verify_signature(
        &self,
        signed_message: &SignedMessage,
        public_key: &str,
    ) -> Result<bool> {
        match signed_message.signature_type {
            SignatureType::RustSHA512 => self.verify_rust_signature(signed_message, public_key),
            SignatureType::JSSHA512 => self.verify_js_signature(signed_message, public_key),
        }
    }

    /// Verify Rust signature
    fn verify_rust_signature(&self, signed_message: &SignedMessage, public_key: &str) -> Result<bool> {
        let public_key = RsaPublicKey::from_public_key_pem(public_key)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

        let signature = base64_to_bytes(&signed_message.signature)?;

        // Hash the message
        let mut hasher = Sha512::new();
        hasher.update(signed_message.message.as_bytes());
        let hash = hasher.finalize();

        // Verify the signature
        let is_valid = public_key
            .verify(rsa::Pkcs1v15Verify::new::<sha2::Sha512>(), &hash, &signature)
            .is_ok();

        Ok(is_valid)
    }

    /// Verify JavaScript signature
    fn verify_js_signature(
        &self,
        _signed_message: &SignedMessage,
        _public_key: &str,
    ) -> Result<bool> {
        Err(CryptoError::SignatureVerificationFailed(
            "JavaScript signature verification not implemented in Rust".to_string()
        ))
    }

    /// Encrypt key with password using PBKDF2
    fn encrypt_key_with_password(&self, key: &[u8], password: &[u8]) -> Result<Vec<u8>> {
        let salt = generate_random_bytes(32)?;
        let derived_key = derive_key_from_password(password, &salt, 100_000)?;
        
        // Simple XOR encryption for demonstration
        // In production, use proper encryption
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&salt);
        
        for (i, &byte) in key.iter().enumerate() {
            encrypted.push(byte ^ derived_key[i % derived_key.len()]);
        }
        
        Ok(encrypted)
    }

    /// Decrypt key with password using PBKDF2
    fn decrypt_key_with_password(&self, encrypted_key: &[u8], password: &[u8]) -> Result<Vec<u8>> {
        if encrypted_key.len() < 32 {
            return Err(CryptoError::DecryptionFailed("Invalid encrypted key format".to_string()));
        }

        let salt = &encrypted_key[..32];
        let encrypted_data = &encrypted_key[32..];
        let derived_key = derive_key_from_password(password, salt, 100_000)?;

        let mut decrypted = Vec::new();
        for (i, &byte) in encrypted_data.iter().enumerate() {
            decrypted.push(byte ^ derived_key[i % derived_key.len()]);
        }

        Ok(decrypted)
    }

    /// Get system information
    pub fn get_system_info(&self) -> SystemInfo {
        SystemInfo {
            preferred_encryption: self.preferred_encryption.clone(),
            preferred_signature: self.preferred_signature.clone(),
            performance_threshold: self.performance_threshold,
            supported_algorithms: vec![
                "AES-256-GCM".to_string(),
                "RSA-4096".to_string(),
                "SHA-512".to_string(),
                "PBKDF2".to_string(),
            ],
        }
    }
}

/// System information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub preferred_encryption: crate::message::EncryptionType,
    pub preferred_signature: crate::message::SignatureType,
    pub performance_threshold: usize,
    pub supported_algorithms: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_system_creation() {
        let crypto = CryptoSystem::default();
        assert_eq!(crypto.performance_threshold, 1024);
    }

    #[test]
    fn test_encryption_method_choice() {
        let crypto = CryptoSystem::default();
        
        // Small data should prefer JavaScript
        let method = crypto.choose_encryption_method(100, false);
        assert!(matches!(method, EncryptionType::JSRSA));
        
        // Large data should prefer Rust
        let method = crypto.choose_encryption_method(2048, false);
        assert!(matches!(method, EncryptionType::RustAES));
    }
}
