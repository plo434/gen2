const User = require('../models/User');
const QuantumKeyExchange = require('../crypto/key-exchange');
const jwt = require('jsonwebtoken');

/**
 * User Service for Quantum Key Exchange System
 * 
 * This service handles:
 * - User registration and authentication
 * - Key generation and management
 * - Security operations
 * - User validation
 */

class UserService {
    constructor() {
        this.cryptoSystem = new QuantumKeyExchange();
        this.users = new Map(); // In-memory storage (replace with database)
        this.jwtSecret = process.env.JWT_SECRET || 'your-secret-key';
        this.jwtExpiry = '24h';
    }

    /**
     * Register a new user
     * @param {Object} userData - User registration data
     * @returns {Object} Registration result
     */
    async registerUser(userData) {
        try {
            // Validate input data
            if (!userData.username || !userData.email || !userData.password) {
                throw new Error('Username, email, and password are required');
            }

            // Check if user already exists
            if (this.users.has(userData.username) || this.users.has(userData.email)) {
                throw new Error('User already exists');
            }

            // Create user instance
            const user = new User({
                username: userData.username,
                email: userData.email
            });

            // Hash password
            user.passwordHash = await this.cryptoSystem.hashPassword(userData.password);

            // Generate cryptographic keys
            const keyPair = await this.cryptoSystem.generateKeyPair(user.userId);

            // Update user with public keys
            user.updatePublicKeys({
                kyber: keyPair.publicKey,
                dilithium: keyPair.publicKey, // Using same key for both for now
                keyFingerprint: keyPair.metadata.keyFingerprint
            });

            // Store user
            this.users.set(user.userId, user);
            this.users.set(user.username, user);
            this.users.set(user.email, user);

            // Generate JWT token
            const token = this.generateJWT(user);

            return {
                success: true,
                message: 'User registered successfully',
                user: user.getSummary(),
                token,
                keys: {
                    publicKey: keyPair.publicKey,
                    keyFingerprint: keyPair.metadata.keyFingerprint,
                    keyVersion: keyPair.metadata.keyVersion
                }
            };
        } catch (error) {
            throw new Error(`Registration failed: ${error.message}`);
        }
    }

    /**
     * Authenticate user
     * @param {string} username - Username or email
     * @param {string} password - Password
     * @returns {Object} Authentication result
     */
    async authenticateUser(username, password) {
        try {
            // Find user
            const user = this.users.get(username);
            if (!user) {
                throw new Error('Invalid credentials');
            }

            // Check if user is locked out
            if (user.isLockedOut()) {
                throw new Error('Account is temporarily locked');
            }

            // Verify password
            const isValidPassword = await this.cryptoSystem.verifyPassword(password, user.passwordHash);
            if (!isValidPassword) {
                user.recordFailedLogin();
                throw new Error('Invalid credentials');
            }

            // Record successful login
            user.recordSuccessfulLogin();

            // Generate JWT token
            const token = this.generateJWT(user);

            return {
                success: true,
                message: 'Authentication successful',
                user: user.getSummary(),
                token,
                keys: user.getPublicKeyInfo()
            };
        } catch (error) {
            throw new Error(`Authentication failed: ${error.message}`);
        }
    }

    /**
     * Get user by ID
     * @param {string} userId - User ID
     * @returns {User|null} User instance or null
     */
    getUserById(userId) {
        return this.users.get(userId) || null;
    }

    /**
     * Get user by username
     * @param {string} username - Username
     * @returns {User|null} User instance or null
     */
    getUserByUsername(username) {
        return this.users.get(username) || null;
    }

    /**
     * Get user's public keys
     * @param {string} username - Username
     * @returns {Object|null} Public key information or null
     */
    getPublicKeys(username) {
        const user = this.getUserByUsername(username);
        if (!user) return null;

        return user.getPublicKeyInfo();
    }

    /**
     * Update user's public keys
     * @param {string} userId - User ID
     * @param {Object} newKeys - New public keys
     * @returns {Object} Update result
     */
    async updatePublicKeys(userId, newKeys) {
        try {
            const user = this.getUserById(userId);
            if (!user) {
                throw new Error('User not found');
            }

            // Generate new key pair
            const keyPair = await this.cryptoSystem.generateKeyPair(userId);

            // Update user with new keys
            user.updatePublicKeys({
                kyber: keyPair.publicKey,
                dilithium: keyPair.publicKey,
                keyFingerprint: keyPair.metadata.keyFingerprint
            });

            return {
                success: true,
                message: 'Public keys updated successfully',
                keys: {
                    publicKey: keyPair.publicKey,
                    keyFingerprint: keyPair.metadata.keyFingerprint,
                    keyVersion: keyPair.metadata.keyVersion
                }
            };
        } catch (error) {
            throw new Error(`Failed to update public keys: ${error.message}`);
        }
    }

    /**
     * Verify JWT token
     * @param {string} token - JWT token
     * @returns {Object|null} Decoded token or null
     */
    verifyToken(token) {
        try {
            return jwt.verify(token, this.jwtSecret);
        } catch (error) {
            return null;
        }
    }

    /**
     * Generate JWT token
     * @param {User} user - User instance
     * @returns {string} JWT token
     */
    generateJWT(user) {
        const payload = {
            userId: user.userId,
            username: user.username,
            email: user.email,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
        };

        return jwt.sign(payload, this.jwtSecret);
    }

    /**
     * Get all users (for admin purposes)
     * @returns {Array} Array of user summaries
     */
    getAllUsers() {
        const users = [];
        for (const [key, user] of this.users.entries()) {
            if (key === user.userId) { // Only add once per user
                users.push(user.getSummary());
            }
        }
        return users;
    }

    /**
     * Delete user
     * @param {string} userId - User ID
     * @returns {Object} Deletion result
     */
    deleteUser(userId) {
        const user = this.getUserById(userId);
        if (!user) {
            throw new Error('User not found');
        }

        // Remove user from all maps
        this.users.delete(userId);
        this.users.delete(user.username);
        this.users.delete(user.email);

        return {
            success: true,
            message: 'User deleted successfully'
        };
    }

    /**
     * Get system statistics
     * @returns {Object} System statistics
     */
    getSystemStats() {
        let totalUsers = 0;
        let activeUsers = 0;
        let usersWithKeys = 0;

        for (const [key, user] of this.users.entries()) {
            if (key === user.userId) {
                totalUsers++;
                if (user.status === 'active') activeUsers++;
                if (user.publicKeys.keyFingerprint) usersWithKeys++;
            }
        }

        return {
            totalUsers,
            activeUsers,
            usersWithKeys,
            systemHealth: 'operational'
        };
    }
}

module.exports = UserService;
