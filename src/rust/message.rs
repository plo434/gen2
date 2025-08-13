use serde::{Deserialize, Serialize};
use crate::utils::get_current_timestamp;

/// Message structure for the messaging system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub from: String,
    pub to: String,
    pub content: String,
    pub timestamp: String,
    pub encrypted: bool,
    pub signature: Option<String>,
    pub read: bool,
    pub read_at: Option<String>,
    pub encryption_type: EncryptionType,
}

/// Types of encryption available
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionType {
    None,
    RustAES,      // Rust AES-256-GCM
    RustRSA,      // Rust RSA-4096
    JSRSA,        // JavaScript RSA
    Hybrid,       // Rust AES + JavaScript RSA
}

/// Encrypted message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub encrypted_content: String,
    pub encrypted_key: String,
    pub iv: String,
    pub tag: String,
    pub timestamp: String,
    pub encryption_type: EncryptionType,
    pub algorithm: String,
}

/// Signed message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: String,
    pub signature: String,
    pub timestamp: String,
    pub signature_type: SignatureType,
}

/// Types of digital signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureType {
    RustSHA512,   // Rust SHA-512 + RSA
    JSSHA512,     // JavaScript SHA-512 + RSA
}

impl Message {
    /// Create a new message
    pub fn new(from: String, to: String, content: String) -> Self {
        Self {
            id: crate::utils::generate_secure_id().unwrap_or_default(),
            from,
            to,
            content,
            timestamp: get_current_timestamp(),
            encrypted: false,
            signature: None,
            read: false,
            read_at: None,
            encryption_type: EncryptionType::None,
        }
    }

    /// Mark message as read
    pub fn mark_as_read(&mut self) {
        self.read = true;
        self.read_at = Some(get_current_timestamp());
    }

    /// Get message summary (without sensitive data)
    pub fn get_summary(&self) -> MessageSummary {
        MessageSummary {
            id: self.id.clone(),
            from: self.from.clone(),
            to: self.to.clone(),
            timestamp: self.timestamp.clone(),
            encrypted: self.encrypted,
            read: self.read,
            encryption_type: self.encryption_type.clone(),
        }
    }

    /// Validate message data
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.from.is_empty() || self.to.is_empty() || self.content.is_empty() {
            return Err(crate::error::CryptoError::InvalidMessageFormat(
                "Missing required fields: from, to, content".to_string()
            ));
        }

        if self.from == self.to {
            return Err(crate::error::CryptoError::InvalidMessageFormat(
                "Sender and recipient cannot be the same".to_string()
            ));
        }

        Ok(())
    }
}

/// Message summary for public display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSummary {
    pub id: String,
    pub from: String,
    pub to: String,
    pub timestamp: String,
    pub encrypted: bool,
    pub read: bool,
    pub encryption_type: EncryptionType,
}

impl Default for EncryptionType {
    fn default() -> Self {
        EncryptionType::None
    }
}

impl Default for SignatureType {
    fn default() -> Self {
        SignatureType::RustSHA512
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let msg = Message::new(
            "user1".to_string(),
            "user2".to_string(),
            "Hello!".to_string()
        );
        
        assert_eq!(msg.from, "user1");
        assert_eq!(msg.to, "user2");
        assert_eq!(msg.content, "Hello!");
        assert!(!msg.encrypted);
        assert!(!msg.read);
    }

    #[test]
    fn test_message_validation() {
        let mut msg = Message::new(
            "user1".to_string(),
            "user1".to_string(), // Same sender and recipient
            "Hello!".to_string()
        );
        
        assert!(msg.validate().is_err());
        
        msg.to = "user2".to_string();
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_message_mark_read() {
        let mut msg = Message::new(
            "user1".to_string(),
            "user2".to_string(),
            "Hello!".to_string()
        );
        
        assert!(!msg.read);
        assert!(msg.read_at.is_none());
        
        msg.mark_as_read();
        
        assert!(msg.read);
        assert!(msg.read_at.is_some());
    }
}
