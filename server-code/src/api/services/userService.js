// --- User Service ---
const User = require('../models/User');
const fs = require('fs');
const path = require('path');

class UserService {
    constructor() {
        this.users = new Map();
        this.usersFile = path.join(__dirname, '../../data/users.json');
        this.ensureDataDirectory();
        this.loadUsers();
    }

    // Ensure data directory exists
    ensureDataDirectory() {
        const dataDir = path.dirname(this.usersFile);
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
    }

    // Load users from file
    loadUsers() {
        try {
            if (fs.existsSync(this.usersFile)) {
                const data = fs.readFileSync(this.usersFile, 'utf8');
                const usersData = JSON.parse(data);

                for (const userData of usersData) {
                    const user = User.fromData(userData);
                    this.users.set(user.id, user);
                }

                console.log(`Loaded ${this.users.size} users from file`);
            }
        } catch (error) {
            console.error('Error loading users:', error);
        }
    }

    // Save users to file
    saveUsers() {
        try {
            const usersData = Array.from(this.users.values()).map(user => user.toJSON());
            fs.writeFileSync(this.usersFile, JSON.stringify(usersData, null, 2));
            console.log(`Saved ${this.users.size} users to file`);
        } catch (error) {
            console.error('Error saving users:', error);
        }
    }

    // Create new user
    async createUser(userData) {
        try {
            // Check if username already exists
            const existingUser = this.getUserByUsername(userData.username);
            if (existingUser) {
                throw new Error('Username already exists');
            }

            // Create user instance
            const user = User.fromData(userData);

            // Set password
            user.setPassword(userData.password);

            // Validate user
            user.validate();

            // Store user
            this.users.set(user.id, user);

            // Save to file
            this.saveUsers();

            console.log(`User created: ${user.username}`);
            return user.getSummary();

        } catch (error) {
            console.error('Error creating user:', error);
            throw error;
        }
    }

    // Get user by ID
    getUserById(userId) {
        return this.users.get(userId);
    }

    // Get user by username
    getUserByUsername(username) {
        for (const user of this.users.values()) {
            if (user.username === username) {
                return user;
            }
        }
        return null;
    }

    // Authenticate user
    async authenticateUser(username, password) {
        try {
            const user = this.getUserByUsername(username);
            if (!user) {
                throw new Error('User not found');
            }

            if (!user.isActive) {
                throw new Error('User account is deactivated');
            }

            if (!user.verifyPassword(password)) {
                throw new Error('Invalid password');
            }

            // Update last login
            user.updateLastLogin();
            this.saveUsers();

            console.log(`User authenticated: ${username}`);
            return user.getSummary();

        } catch (error) {
            console.error('Authentication error:', error);
            throw error;
        }
    }

    // Update user keys
    async updateUserKeys(userId, publicKey, encryptedPrivateKey) {
        try {
            const user = this.getUserById(userId);
            if (!user) {
                throw new Error('User not found');
            }

            user.setKeys(publicKey, encryptedPrivateKey);
            this.saveUsers();

            console.log(`Keys updated for user: ${user.username}`);
            return user.getSummary();

        } catch (error) {
            console.error('Error updating user keys:', error);
            throw error;
        }
    }

    // Get all users (summaries only)
    getAllUsers() {
        return Array.from(this.users.values()).map(user => user.getSummary());
    }

    // Deactivate user
    async deactivateUser(userId) {
        try {
            const user = this.getUserById(userId);
            if (!user) {
                throw new Error('User not found');
            }

            user.isActive = false;
            this.saveUsers();

            console.log(`User deactivated: ${user.username}`);
            return user.getSummary();

        } catch (error) {
            console.error('Error deactivating user:', error);
            throw error;
        }
    }

    // Delete user
    async deleteUser(userId) {
        try {
            const user = this.getUserById(userId);
            if (!user) {
                throw new Error('User not found');
            }

            this.users.delete(userId);
            this.saveUsers();

            console.log(`User deleted: ${user.username}`);
            return true;

        } catch (error) {
            console.error('Error deleting user:', error);
            throw error;
        }
    }

    // Get user statistics
    async getUserStats() {
        try {
            const totalUsers = this.users.size;
            const activeUsers = Array.from(this.users.values()).filter(user => user.isActive).length;
            const usersWithKeys = Array.from(this.users.values()).filter(user => user.publicKey).length;

            return {
                totalUsers,
                activeUsers,
                inactiveUsers: totalUsers - activeUsers,
                usersWithKeys,
                usersWithoutKeys: totalUsers - usersWithKeys,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error('Error getting user stats:', error);
            throw error;
        }
    }
}

module.exports = new UserService();
