use crate::error::Result;
use rand::{Rng, RngCore};
use ring::rand::SystemRandom;

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    SystemRandom::new().fill(&mut bytes)?;
    Ok(bytes)
}

/// Generate a random salt for key derivation
pub fn generate_salt() -> Result<Vec<u8>> {
    generate_random_bytes(32)
}

/// Generate a random IV for AES encryption
pub fn generate_iv() -> Result<Vec<u8>> {
    generate_random_bytes(16)
}

/// Generate a random AES key
pub fn generate_aes_key() -> Result<Vec<u8>> {
    generate_random_bytes(32)
}

/// Generate a secure random ID
pub fn generate_secure_id() -> Result<String> {
    let bytes = generate_random_bytes(16)?;
    Ok(hex::encode(bytes))
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(hex)?)
}

/// Convert bytes to base64 string
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

/// Convert base64 string to bytes
pub fn base64_to_bytes(base64: &str) -> Result<Vec<u8>> {
    Ok(base64::decode(base64)?)
}

/// Hash data using SHA-512
pub fn hash_sha512(data: &[u8]) -> Vec<u8> {
    use sha2::{Sha512, Digest};
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data using SHA-512 and return hex string
pub fn hash_sha512_hex(data: &[u8]) -> String {
    bytes_to_hex(&hash_sha512(data))
}

/// Derive key from password using PBKDF2
pub fn derive_key_from_password(
    password: &[u8], 
    salt: &[u8], 
    iterations: u32
) -> Result<Vec<u8>> {
    use pbkdf2::{pbkdf2, Hmac};
    use sha2::Sha512;
    
    let mut key = vec![0u8; 32];
    pbkdf2::<Hmac<Sha512>>(password, salt, iterations, &mut key);
    Ok(key)
}

/// Ensure directory exists, create if it doesn't
pub fn ensure_directory(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Get current timestamp as ISO string
pub fn get_current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Validate username format
pub fn validate_username(username: &str) -> Result<()> {
    if username.len() < 3 {
        return Err(crate::error::CryptoError::InvalidMessageFormat(
            "Username must be at least 3 characters long".to_string()
        ));
    }
    
    if username.chars().any(|c| !c.is_alphanumeric() && c != '_' && c != '-') {
        return Err(crate::error::CryptoError::InvalidMessageFormat(
            "Username contains invalid characters".to_string()
        ));
    }
    
    Ok(())
}

/// Validate password strength
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(crate::error::CryptoError::InvalidMessageFormat(
            "Password must be at least 8 characters long".to_string()
        ));
    }
    
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    if !(has_upper && has_lower && has_digit && has_special) {
        return Err(crate::error::CryptoError::InvalidMessageFormat(
            "Password must contain uppercase, lowercase, digit, and special character".to_string()
        ));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes() {
        let bytes = generate_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_ne!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn test_hex_conversion() {
        let original = vec![1, 2, 3, 4, 5];
        let hex = bytes_to_hex(&original);
        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_base64_conversion() {
        let original = vec![1, 2, 3, 4, 5];
        let base64 = bytes_to_base64(&original);
        let decoded = base64_to_bytes(&base64).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_password_validation() {
        assert!(validate_password("StrongPass123!").is_ok());
        assert!(validate_password("weak").is_err());
        assert!(validate_password("NoSpecial123").is_err());
    }

    #[test]
    fn test_username_validation() {
        assert!(validate_username("valid_user").is_ok());
        assert!(validate_username("ab").is_err());
        assert!(validate_username("invalid@user").is_err());
    }
}
