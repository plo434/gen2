// --- User Model ---
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class User {
    constructor(data) {
        this.id = data.id || this.generateId();
        this.username = data.username;
        this.passwordHash = data.passwordHash;
        this.salt = data.salt || this.generateSalt();
        this.publicKey = data.publicKey || null;
        this.encryptedPrivateKey = data.encryptedPrivateKey || null;
        this.createdAt = data.createdAt || new Date().toISOString();
        this.lastLogin = data.lastLogin || null;
        this.isActive = data.isActive !== false;
    }

    // Generate unique user ID
    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }

    // Generate random salt
    generateSalt() {
        return crypto.randomBytes(32).toString('hex');
    }

    // Hash password with salt
    hashPassword(password) {
        return crypto.pbkdf2Sync(password, this.salt, 100000, 64, 'sha512').toString('hex');
    }

    // Verify password
    verifyPassword(password) {
        const hash = this.hashPassword(password);
        return hash === this.passwordHash;
    }

    // Set password
    setPassword(password) {
        this.passwordHash = this.hashPassword(password);
    }

    // Set encryption keys
    setKeys(publicKey, encryptedPrivateKey) {
        this.publicKey = publicKey;
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    // Update last login
    updateLastLogin() {
        this.lastLogin = new Date().toISOString();
    }

    // Validate user data
    validate() {
        if (!this.username || !this.passwordHash) {
            throw new Error('Missing required fields: username, passwordHash');
        }

        if (this.username.length < 3) {
            throw new Error('Username must be at least 3 characters long');
        }

        return true;
    }

    // Get user summary (without sensitive data)
    getSummary() {
        return {
            id: this.id,
            username: this.username,
            createdAt: this.createdAt,
            lastLogin: this.lastLogin,
            isActive: this.isActive,
            hasKeys: !!(this.publicKey && this.encryptedPrivateKey)
        };
    }

    // Convert to plain object
    toJSON() {
        return {
            id: this.id,
            username: this.username,
            passwordHash: this.passwordHash,
            salt: this.salt,
            publicKey: this.publicKey,
            encryptedPrivateKey: this.encryptedPrivateKey,
            createdAt: this.createdAt,
            lastLogin: this.lastLogin,
            isActive: this.isActive
        };
    }

    // Create user from data
    static fromData(data) {
        return new User(data);
    }
}

module.exports = User;
