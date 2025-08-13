use thiserror::Error;

/// Custom error type for crypto operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Key import failed: {0}")]
    KeyImportFailed(String),
    
    #[error("Key export failed: {0}")]
    KeyExportFailed(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("Invalid message format: {0}")]
    InvalidMessageFormat(String),
    
    #[error("File operation failed: {0}")]
    FileOperationFailed(String),
    
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
    
    #[error("Invalid password")]
    InvalidPassword,
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Unauthorized operation: {0}")]
    Unauthorized(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<rsa::Error> for CryptoError {
    fn from(err: rsa::Error) -> Self {
        CryptoError::KeyGenerationFailed(err.to_string())
    }
}

impl From<aes_gcm::Error> for CryptoError {
    fn from(err: aes_gcm::Error) -> Self {
        CryptoError::EncryptionFailed(err.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(err: serde_json::Error) -> Self {
        CryptoError::SerializationFailed(err.to_string())
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::FileOperationFailed(err.to_string())
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::InvalidKeyFormat(err.to_string())
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(err: hex::FromHexError) -> Self {
        CryptoError::InvalidKeyFormat(err.to_string())
    }
}

/// Result type for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;
