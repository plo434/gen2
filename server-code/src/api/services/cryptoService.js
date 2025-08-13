// --- Hybrid Crypto Service ---
const HybridCryptoBridge = require('../hybrid_bridge');
const path = require('path');

class CryptoService {
    constructor() {
        this.cryptoBridge = new HybridCryptoBridge();
    }

    // Generate keys for user
    async generateUserKeys(username, password) {
        try {
            console.log(`Generating keys for user: ${username}`);

            // Use hybrid bridge for key generation
            const userKeys = await this.cryptoBridge.generateUserKeys(username, password);

            console.log(`Keys generated successfully for user: ${username}`);
            return userKeys;

        } catch (error) {
            console.error('Error generating user keys:', error);
            throw error;
        }
    }

    // Encrypt message using hybrid system
    async encryptMessage(message, recipientPublicKey, options = {}) {
        try {
            const encryptedMessage = await this.cryptoBridge.encryptMessage(message, recipientPublicKey, options);
            console.log('Message encrypted successfully with hybrid system');
            return encryptedMessage;

        } catch (error) {
            console.error('Error encrypting message:', error);
            throw error;
        }
    }

    // Decrypt message using hybrid system
    async decryptMessage(encryptedMessage, userKeys, password, options = {}) {
        try {
            const decryptedMessage = await this.cryptoBridge.decryptMessage(encryptedMessage, userKeys, password, options);
            console.log('Message decrypted successfully with hybrid system');
            return decryptedMessage;

        } catch (error) {
            console.error('Error decrypting message:', error);
            throw error;
        }
    }

    // Sign message using hybrid system
    async signMessage(message, userKeys, password, options = {}) {
        try {
            const signedMessage = await this.cryptoBridge.signMessage(message, userKeys, password, options);
            console.log('Message signed successfully with hybrid system');
            return signedMessage;

        } catch (error) {
            console.error('Error signing message:', error);
            throw error;
        }
    }

    // Verify message signature using hybrid system
    async verifyMessageSignature(signedMessage, senderPublicKey, options = {}) {
        try {
            const verification = await this.cryptoBridge.verifySignature(signedMessage, senderPublicKey, options);
            console.log('Message signature verified with hybrid system');
            return verification;

        } catch (error) {
            console.error('Error verifying message signature:', error);
            throw error;
        }
    }

    // Export public key
    async exportPublicKey(username, publicKey) {
        try {
            // Create a simple export function
            const publicKeyFile = path.join(__dirname, '../../keys', `${username}_public.pem`);
            const fs = require('fs');

            // Ensure keys directory exists
            const keysDir = path.dirname(publicKeyFile);
            if (!fs.existsSync(keysDir)) {
                fs.mkdirSync(keysDir, { recursive: true });
            }

            fs.writeFileSync(publicKeyFile, publicKey);
            console.log(`Public key exported to: ${publicKeyFile}`);
            return publicKeyFile;

        } catch (error) {
            console.error('Error exporting public key:', error);
            throw error;
        }
    }

    // Import public key
    async importPublicKey(username) {
        try {
            const publicKeyFile = path.join(__dirname, '../../keys', `${username}_public.pem`);
            const fs = require('fs');

            if (!fs.existsSync(publicKeyFile)) {
                throw new Error(`Public key file not found for user: ${username}`);
            }

            const publicKey = fs.readFileSync(publicKeyFile, 'utf8');
            console.log(`Public key imported for user: ${username}`);
            return publicKey;

        } catch (error) {
            console.error('Error importing public key:', error);
            throw error;
        }
    }

    // List users with keys
    async listUsersWithKeys() {
        try {
            const keysDir = path.join(__dirname, '../../keys');
            const fs = require('fs');

            if (!fs.existsSync(keysDir)) {
                return [];
            }

            const files = fs.readdirSync(keysDir);
            const users = files
                .filter(file => file.endsWith('_public.pem'))
                .map(file => file.replace('_public.pem', ''));

            console.log(`Found ${users.length} users with keys`);
            return users;

        } catch (error) {
            console.error('Error listing users with keys:', error);
            throw error;
        }
    }

    // Delete user keys
    async deleteUserKeys(username) {
        try {
            const keysDir = path.join(__dirname, '../../keys');
            const fs = require('fs');

            const publicKeyFile = path.join(keysDir, `${username}_public.pem`);
            const privateKeyFile = path.join(keysDir, `${username}_private.pem`);

            if (fs.existsSync(publicKeyFile)) {
                fs.unlinkSync(publicKeyFile);
            }

            if (fs.existsSync(privateKeyFile)) {
                fs.unlinkSync(privateKeyFile);
            }

            console.log(`Keys deleted for user: ${username}`);
            return true;

        } catch (error) {
            console.error('Error deleting user keys:', error);
            throw error;
        }
    }

    // Backup user keys
    async backupUserKeys(username, backupPath) {
        try {
            const keysDir = path.join(__dirname, '../../keys');
            const fs = require('fs');

            const publicKeyFile = path.join(keysDir, `${username}_public.pem`);
            const privateKeyFile = path.join(keysDir, `${username}_private.pem`);

            if (!fs.existsSync(publicKeyFile) && !fs.existsSync(privateKeyFile)) {
                throw new Error(`No keys found for user: ${username}`);
            }

            // Create backup directory
            if (!fs.existsSync(backupPath)) {
                fs.mkdirSync(backupPath, { recursive: true });
            }

            // Copy keys to backup
            if (fs.existsSync(publicKeyFile)) {
                fs.copyFileSync(publicKeyFile, path.join(backupPath, `${username}_public.pem`));
            }

            if (fs.existsSync(privateKeyFile)) {
                fs.copyFileSync(privateKeyFile, path.join(backupPath, `${username}_private.pem`));
            }

            console.log(`Keys backed up for user: ${username}`);
            return backupPath;

        } catch (error) {
            console.error('Error backing up user keys:', error);
            throw error;
        }
    }

    // Restore user keys
    async restoreUserKeys(backupPath) {
        try {
            const keysDir = path.join(__dirname, '../../keys');
            const fs = require('fs');

            if (!fs.existsSync(backupPath)) {
                throw new Error(`Backup path not found: ${backupPath}`);
            }

            // Ensure keys directory exists
            if (!fs.existsSync(keysDir)) {
                fs.mkdirSync(keysDir, { recursive: true });
            }

            // Copy keys from backup
            const backupFiles = fs.readdirSync(backupPath);
            backupFiles.forEach(file => {
                if (file.endsWith('.pem')) {
                    fs.copyFileSync(
                        path.join(backupPath, file),
                        path.join(keysDir, file)
                    );
                }
            });

            console.log('Keys restored successfully');
            return true;

        } catch (error) {
            console.error('Error restoring user keys:', error);
            throw error;
        }
    }

    // Get crypto system info
    getCryptoSystemInfo() {
        try {
            const systemInfo = this.cryptoBridge.getSystemInfo();
            return {
                ...systemInfo,
                hybrid_mode: true,
                rust_available: systemInfo.rust_available,
                javascript_available: systemInfo.javascript_available
            };
        } catch (error) {
            return {
                hybrid_mode: true,
                rust_available: false,
                javascript_available: true,
                error: error.message
            };
        }
    }

    // Test encryption/decryption with hybrid system
    async testEncryption() {
        try {
            const testData = 'Hello, this is a test message for hybrid crypto system!';
            const testPublicKey = 'test-public-key';

            console.log('Testing hybrid encryption system...');

            // Test encryption
            const encrypted = await this.cryptoBridge.encryptMessage(
                { content: testData },
                testPublicKey,
                { requirePerformance: true }
            );

            console.log('✅ Hybrid encryption test completed');

            return {
                success: true,
                original: testData,
                encrypted: encrypted,
                method: encrypted.encryption_type || 'hybrid'
            };

        } catch (error) {
            console.error('Hybrid encryption test failed:', error);
            throw error;
        }
    }

    // Get bridge status
    getBridgeStatus() {
        return {
            rust_available: this.cryptoBridge.isRustAvailable,
            javascript_available: true,
            hybrid_mode: true,
            performance_threshold: this.cryptoBridge.performanceThreshold
        };
    }
}

module.exports = new CryptoService();
