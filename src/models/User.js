const { v4: uuidv4 } = require('uuid');

/**
 * User Model for Quantum Key Exchange System
 * 
 * This model represents a user in the system with:
 * - Basic user information
 * - Cryptographic keys
 * - Security settings
 * - Audit information
 */

class User {
    constructor(data = {}) {
        this.userId = data.userId || uuidv4();
        this.username = data.username || '';
        this.email = data.email || '';
        this.passwordHash = data.passwordHash || '';
        this.publicKeys = data.publicKeys || {
            kyber: null,
            dilithium: null,
            keyFingerprint: null,
            keyVersion: 1
        };
        this.securitySettings = data.securitySettings || {
            twoFactorEnabled: false,
            keyRotationEnabled: true,
            keyExpiryDays: 365,
            maxFailedAttempts: 5,
            lockoutDuration: 30 // minutes
        };
        this.status = data.status || 'active'; // active, suspended, deleted
        this.createdAt = data.createdAt || new Date().toISOString();
        this.lastUpdated = data.lastUpdated || new Date().toISOString();
        this.lastLogin = data.lastLogin || null;
        this.failedLoginAttempts = data.failedLoginAttempts || 0;
        this.lockoutUntil = data.lockoutUntil || null;
    }

    /**
     * Validate user data
     * @returns {Object} Validation result
     */
    validate() {
        const errors = [];

        if (!this.username || this.username.length < 3) {
            errors.push('Username must be at least 3 characters long');
        }

        if (!this.email || !this.isValidEmail(this.email)) {
            errors.push('Valid email address is required');
        }

        if (!this.passwordHash) {
            errors.push('Password hash is required');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }

    /**
     * Validate email format
     * @param {string} email - Email to validate
     * @returns {boolean} True if email is valid
     */
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Update public keys
     * @param {Object} newKeys - New public keys
     */
    updatePublicKeys(newKeys) {
        this.publicKeys = {
            ...this.publicKeys,
            ...newKeys,
            keyVersion: this.publicKeys.keyVersion + 1,
            lastUpdated: new Date().toISOString()
        };
    }

    /**
     * Check if user is locked out
     * @returns {boolean} True if user is locked out
     */
    isLockedOut() {
        if (!this.lockoutUntil) return false;
        return new Date() < new Date(this.lockoutUntil);
    }

    /**
     * Record failed login attempt
     */
    recordFailedLogin() {
        this.failedLoginAttempts += 1;
        this.lastUpdated = new Date().toISOString();

        if (this.failedLoginAttempts >= this.securitySettings.maxFailedAttempts) {
            const lockoutTime = new Date();
            lockoutTime.setMinutes(lockoutTime.getMinutes() + this.securitySettings.lockoutDuration);
            this.lockoutUntil = lockoutTime.toISOString();
        }
    }

    /**
     * Record successful login
     */
    recordSuccessfulLogin() {
        this.failedLoginAttempts = 0;
        this.lockoutUntil = null;
        this.lastLogin = new Date().toISOString();
        this.lastUpdated = new Date().toISOString();
    }

    /**
     * Check if keys are expired
     * @returns {boolean} True if keys are expired
     */
    areKeysExpired() {
        if (!this.publicKeys.keyFingerprint) return true;

        const keyAge = new Date() - new Date(this.createdAt);
        const maxAge = this.securitySettings.keyExpiryDays * 24 * 60 * 60 * 1000;

        return keyAge > maxAge;
    }

    /**
     * Get user summary (without sensitive data)
     * @returns {Object} User summary
     */
    getSummary() {
        return {
            userId: this.userId,
            username: this.username,
            email: this.email,
            status: this.status,
            createdAt: this.createdAt,
            lastUpdated: this.lastUpdated,
            lastLogin: this.lastLogin,
            hasKeys: !!this.publicKeys.keyFingerprint,
            keyVersion: this.publicKeys.keyVersion,
            isLockedOut: this.isLockedOut()
        };
    }

    /**
     * Get public key information
     * @returns {Object} Public key information
     */
    getPublicKeyInfo() {
        return {
            userId: this.userId,
            username: this.username,
            publicKeys: {
                kyber: this.publicKeys.kyber,
                dilithium: this.publicKeys.dilithium,
                keyFingerprint: this.publicKeys.keyFingerprint,
                keyVersion: this.publicKeys.keyVersion
            },
            lastUpdated: this.lastUpdated
        };
    }

    /**
     * Convert to database object
     * @returns {Object} Database object
     */
    toDatabase() {
        return {
            userId: this.userId,
            username: this.username,
            email: this.email,
            passwordHash: this.passwordHash,
            publicKeys: JSON.stringify(this.publicKeys),
            securitySettings: JSON.stringify(this.securitySettings),
            status: this.status,
            createdAt: this.createdAt,
            lastUpdated: this.lastUpdated,
            lastLogin: this.lastLogin,
            failedLoginAttempts: this.failedLoginAttempts,
            lockoutUntil: this.lockoutUntil
        };
    }

    /**
     * Create from database object
     * @param {Object} dbObject - Database object
     * @returns {User} User instance
     */
    static fromDatabase(dbObject) {
        return new User({
            userId: dbObject.user_id,
            username: dbObject.username,
            email: dbObject.email,
            passwordHash: dbObject.password_hash,
            publicKeys: JSON.parse(dbObject.public_keys || '{}'),
            securitySettings: JSON.parse(dbObject.security_settings || '{}'),
            status: dbObject.status,
            createdAt: dbObject.created_at,
            lastUpdated: dbObject.last_updated,
            lastLogin: dbObject.last_login,
            failedLoginAttempts: dbObject.failed_login_attempts,
            lockoutUntil: dbObject.lockout_until
        });
    }
}

module.exports = User;
