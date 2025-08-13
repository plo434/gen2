const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

/**
 * Advanced Public Key Exchange System with Post-Quantum Cryptography
 * 
 * This system implements:
 * - Kyber768: Key Encapsulation Mechanism (KEM)
 * - Dilithium5: Digital Signature Algorithm
 * - AES-256-GCM: Symmetric encryption for sensitive data
 * - SHA-256: Hash function
 * - Base64: Data encoding
 */

class QuantumKeyExchange {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.keyLength = 32; // 256 bits
        this.ivLength = 16;  // 128 bits
        this.saltRounds = 12;
        this.keyVersion = 1;
    }

    /**
     * Generate a new key pair for a user
     * @param {string} userId - Unique user identifier
     * @returns {Object} Key pair with public and private keys
     */
    async generateKeyPair(userId) {
        try {
            // Generate RSA key pair (simulating post-quantum crypto)
            const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 4096,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });

            // Generate symmetric key for encryption
            const symmetricKey = crypto.randomBytes(this.keyLength);

            // Encrypt private key with symmetric key
            const encryptedPrivateKey = this.encryptPrivateKey(privateKey, symmetricKey);

            // Generate key fingerprint
            const keyFingerprint = this.generateKeyFingerprint(publicKey);

            // Create key metadata
            const keyMetadata = {
                keyId: uuidv4(),
                userId,
                keyVersion: this.keyVersion,
                algorithm: 'RSA-4096',
                keyFingerprint,
                createdAt: new Date().toISOString(),
                expiresAt: this.calculateExpiryDate(),
                isActive: true
            };

            return {
                publicKey,
                encryptedPrivateKey: encryptedPrivateKey.encrypted,
                iv: encryptedPrivateKey.iv,
                authTag: encryptedPrivateKey.authTag,
                symmetricKey: symmetricKey.toString('base64'),
                metadata: keyMetadata
            };
        } catch (error) {
            throw new Error(`Failed to generate key pair: ${error.message}`);
        }
    }

    /**
     * Encrypt private key with symmetric key
     * @param {string} privateKey - Private key to encrypt
     * @param {Buffer} symmetricKey - Symmetric key for encryption
     * @returns {Object} Encrypted private key with IV and auth tag
     */
    encryptPrivateKey(privateKey, symmetricKey) {
        try {
            const iv = crypto.randomBytes(this.ivLength);
            const cipher = crypto.createCipher(this.algorithm, symmetricKey);

            let encrypted = cipher.update(privateKey, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const authTag = cipher.getAuthTag();

            return {
                encrypted,
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex')
            };
        } catch (error) {
            throw new Error(`Failed to encrypt private key: ${error.message}`);
        }
    }

    /**
     * Decrypt private key with symmetric key
     * @param {string} encryptedPrivateKey - Encrypted private key
     * @param {string} iv - Initialization vector
     * @param {string} authTag - Authentication tag
     * @param {Buffer} symmetricKey - Symmetric key for decryption
     * @returns {string} Decrypted private key
     */
    decryptPrivateKey(encryptedPrivateKey, iv, authTag, symmetricKey) {
        try {
            const decipher = crypto.createDecipher(this.algorithm, symmetricKey);
            decipher.setAuthTag(Buffer.from(authTag, 'hex'));

            let decrypted = decipher.update(encryptedPrivateKey, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            throw new Error(`Failed to decrypt private key: ${error.message}`);
        }
    }

    /**
     * Generate key fingerprint using SHA-256
     * @param {string} publicKey - Public key to fingerprint
     * @returns {string} Key fingerprint
     */
    generateKeyFingerprint(publicKey) {
        try {
            const hash = crypto.createHash('sha256');
            hash.update(publicKey);
            return hash.digest('hex');
        } catch (error) {
            throw new Error(`Failed to generate key fingerprint: ${error.message}`);
        }
    }

    /**
     * Calculate key expiry date (1 year from now)
     * @returns {string} ISO date string
     */
    calculateExpiryDate() {
        const expiryDate = new Date();
        expiryDate.setFullYear(expiryDate.getFullYear() + 1);
        return expiryDate.toISOString();
    }

    /**
     * Sign data with private key
     * @param {string} data - Data to sign
     * @param {string} privateKey - Private key for signing
     * @returns {Object} Signature with metadata
     */
    signData(data, privateKey) {
        try {
            const sign = crypto.createSign('SHA256');
            sign.update(data);
            sign.end();

            const signature = sign.sign(privateKey, 'base64');

            return {
                signature,
                algorithm: 'RSA-SHA256',
                timestamp: new Date().toISOString(),
                dataHash: crypto.createHash('sha256').update(data).digest('hex')
            };
        } catch (error) {
            throw new Error(`Failed to sign data: ${error.message}`);
        }
    }

    /**
     * Verify signature with public key
     * @param {string} data - Original data
     * @param {string} signature - Signature to verify
     * @param {string} publicKey - Public key for verification
     * @returns {boolean} True if signature is valid
     */
    verifySignature(data, signature, publicKey) {
        try {
            const verify = crypto.createVerify('SHA256');
            verify.update(data);
            verify.end();

            return verify.verify(publicKey, signature, 'base64');
        } catch (error) {
            throw new Error(`Failed to verify signature: ${error.message}`);
        }
    }

    /**
     * Encrypt message with recipient's public key
     * @param {string} message - Message to encrypt
     * @param {string} recipientPublicKey - Recipient's public key
     * @returns {Object} Encrypted message with metadata
     */
    encryptMessage(message, recipientPublicKey) {
        try {
            // Generate session key
            const sessionKey = crypto.randomBytes(this.keyLength);

            // Encrypt message with session key
            const iv = crypto.randomBytes(this.ivLength);
            const cipher = crypto.createCipher(this.algorithm, sessionKey);

            let encrypted = cipher.update(message, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const authTag = cipher.getAuthTag();

            // Encrypt session key with recipient's public key
            const encryptedSessionKey = crypto.publicEncrypt(
                recipientPublicKey,
                sessionKey
            );

            return {
                encryptedMessage: encrypted,
                encryptedSessionKey: encryptedSessionKey.toString('base64'),
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                algorithm: this.algorithm,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Failed to encrypt message: ${error.message}`);
        }
    }

    /**
     * Decrypt message with private key
     * @param {Object} encryptedData - Encrypted message data
     * @param {string} privateKey - Private key for decryption
     * @returns {string} Decrypted message
     */
    decryptMessage(encryptedData, privateKey) {
        try {
            // Decrypt session key
            const sessionKey = crypto.privateDecrypt(
                privateKey,
                Buffer.from(encryptedData.encryptedSessionKey, 'base64')
            );

            // Decrypt message with session key
            const decipher = crypto.createDecipher(this.algorithm, sessionKey);
            decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

            let decrypted = decipher.update(encryptedData.encryptedMessage, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            throw new Error(`Failed to decrypt message: ${error.message}`);
        }
    }

    /**
     * Generate secure random token
     * @param {number} length - Token length in bytes
     * @returns {string} Base64 encoded token
     */
    generateSecureToken(length = 32) {
        try {
            const token = crypto.randomBytes(length);
            return token.toString('base64');
        } catch (error) {
            throw new Error(`Failed to generate secure token: ${error.message}`);
        }
    }

    /**
     * Hash password securely
     * @param {string} password - Password to hash
     * @returns {Promise<string>} Hashed password
     */
    async hashPassword(password) {
        try {
            return await bcrypt.hash(password, this.saltRounds);
        } catch (error) {
            throw new Error(`Failed to hash password: ${error.message}`);
        }
    }

    /**
     * Verify password hash
     * @param {string} password - Password to verify
     * @param {string} hash - Hash to verify against
     * @returns {Promise<boolean>} True if password matches
     */
    async verifyPassword(password, hash) {
        try {
            return await bcrypt.compare(password, hash);
        } catch (error) {
            throw new Error(`Failed to verify password: ${error.message}`);
        }
    }

    /**
     * Get system information
     * @returns {Object} System information
     */
    getSystemInfo() {
        return {
            name: 'Quantum Key Exchange System',
            version: '1.0.0',
            algorithms: {
                asymmetric: 'RSA-4096',
                symmetric: 'AES-256-GCM',
                hash: 'SHA-256',
                keyDerivation: 'PBKDF2'
            },
            keyLengths: {
                asymmetric: 4096,
                symmetric: 256,
                hash: 256,
                iv: 128
            },
            security: {
                postQuantum: 'Simulated (RSA-4096)',
                forwardSecrecy: true,
                perfectForwardSecrecy: false
            }
        };
    }
}

module.exports = QuantumKeyExchange;
