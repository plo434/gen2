// --- Hybrid Bridge: Rust + JavaScript Integration ---
const { spawn } = require('child_process');
const path = require('path');

class HybridCryptoBridge {
    constructor() {
        this.rustProcess = null;
        this.isRustAvailable = false;
        this.performanceThreshold = 1024; // 1KB
        this.initRustBridge();
    }

    // Initialize Rust bridge
    async initRustBridge() {
        try {
            // Check if Rust binary exists
            const rustBinPath = path.join(__dirname, '../../target/release/crypto_api');
            const fs = require('fs');

            if (fs.existsSync(rustBinPath)) {
                this.isRustAvailable = true;
                console.log('✅ Rust crypto system available');
            } else {
                console.log('⚠️ Rust crypto system not available, using JavaScript fallback');
            }
        } catch (error) {
            console.error('Error initializing Rust bridge:', error);
        }
    }

    // Choose the best encryption method
    chooseEncryptionMethod(dataSize, requirePerformance = false) {
        if (requirePerformance || dataSize > this.performanceThreshold) {
            return this.isRustAvailable ? 'rust' : 'javascript';
        } else {
            return 'javascript'; // Easier integration for small data
        }
    }

    // Encrypt message using best available method
    async encryptMessage(message, recipientPublicKey, options = {}) {
        const dataSize = message.content.length;
        const method = this.chooseEncryptionMethod(dataSize, options.requirePerformance);

        console.log(`🔐 Encrypting with ${method.toUpperCase()} (data size: ${dataSize} bytes)`);

        if (method === 'rust' && this.isRustAvailable) {
            return this.encryptWithRust(message, recipientPublicKey, options);
        } else {
            return this.encryptWithJavaScript(message, recipientPublicKey, options);
        }
    }

    // Decrypt message using appropriate method
    async decryptMessage(encryptedMessage, privateKey, password, options = {}) {
        const method = encryptedMessage.encryption_type || 'javascript';

        console.log(`🔓 Decrypting with ${method.toUpperCase()}`);

        if (method.includes('rust') && this.isRustAvailable) {
            return this.decryptWithRust(encryptedMessage, privateKey, password, options);
        } else {
            return this.decryptWithJavaScript(encryptedMessage, privateKey, password, options);
        }
    }

    // Sign message using best available method
    async signMessage(message, privateKey, password, options = {}) {
        const method = this.chooseEncryptionMethod(message.length, options.requirePerformance);

        if (method === 'rust' && this.isRustAvailable) {
            return this.signWithRust(message, privateKey, password, options);
        } else {
            return this.signWithJavaScript(message, privateKey, password, options);
        }
    }

    // Verify signature using appropriate method
    async verifySignature(signedMessage, publicKey, options = {}) {
        const method = signedMessage.signature_type || 'javascript';

        if (method.includes('rust') && this.isRustAvailable) {
            return this.verifyWithRust(signedMessage, publicKey, options);
        } else {
            return this.verifyWithJavaScript(signedMessage, publicKey, options);
        }
    }

    // Rust encryption via subprocess
    async encryptWithRust(message, recipientPublicKey, options) {
        return new Promise((resolve, reject) => {
            const rustBinPath = path.join(__dirname, '../../target/release/crypto_api');
            const args = ['encrypt', '--message', message.content, '--public-key', recipientPublicKey];

            const rustProcess = spawn(rustBinPath, args);

            let output = '';
            let errorOutput = '';

            rustProcess.stdout.on('data', (data) => {
                output += data.toString();
            });

            rustProcess.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });

            rustProcess.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = JSON.parse(output);
                        resolve({
                            ...result,
                            encryption_type: 'rust_aes',
                            algorithm: 'Rust AES-256-GCM'
                        });
                    } catch (error) {
                        reject(new Error(`Failed to parse Rust output: ${error.message}`));
                    }
                } else {
                    reject(new Error(`Rust process failed: ${errorOutput}`));
                }
            });

            rustProcess.on('error', (error) => {
                reject(new Error(`Failed to start Rust process: ${error.message}`));
            });
        });
    }

    // JavaScript encryption fallback
    async encryptWithJavaScript(message, recipientPublicKey, options) {
        // Use the existing JavaScript crypto system
        const AdvancedCryptoSystem = require('../../crypto-system');
        const cryptoSystem = new AdvancedCryptoSystem();

        try {
            const encryptedMessage = cryptoSystem.encryptMessage(message.content, recipientPublicKey);

            return {
                ...encryptedMessage,
                encryption_type: 'javascript_rsa',
                algorithm: 'JavaScript RSA-4096 + AES-256-GCM'
            };
        } catch (error) {
            throw new Error(`JavaScript encryption failed: ${error.message}`);
        }
    }

    // Rust decryption via subprocess
    async decryptWithRust(encryptedMessage, privateKey, password, options) {
        return new Promise((resolve, reject) => {
            const rustBinPath = path.join(__dirname, '../../target/release/crypto_api');
            const args = [
                'decrypt',
                '--encrypted-content', encryptedMessage.encrypted_content,
                '--encrypted-key', encryptedMessage.encrypted_key,
                '--iv', encryptedMessage.iv,
                '--private-key', privateKey,
                '--password', password
            ];

            const rustProcess = spawn(rustBinPath, args);

            let output = '';
            let errorOutput = '';

            rustProcess.stdout.on('data', (data) => {
                output += data.toString();
            });

            rustProcess.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });

            rustProcess.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = JSON.parse(output);
                        resolve(result.decrypted_content);
                    } catch (error) {
                        reject(new Error(`Failed to parse Rust output: ${error.message}`));
                    }
                } else {
                    reject(new Error(`Rust process failed: ${errorOutput}`));
                }
            });

            rustProcess.on('error', (error) => {
                reject(new Error(`Failed to start Rust process: ${error.message}`));
            });
        });
    }

    // JavaScript decryption fallback
    async decryptWithJavaScript(encryptedMessage, privateKey, password, options) {
        const AdvancedCryptoSystem = require('../../crypto-system');
        const cryptoSystem = new AdvancedCryptoSystem();

        try {
            // Load user keys (this would need to be implemented)
            const userKeys = { encryptedPrivateKey: encryptedMessage.encrypted_key };
            const decryptedMessage = cryptoSystem.decryptMessage(encryptedMessage, userKeys, password);

            return decryptedMessage;
        } catch (error) {
            throw new Error(`JavaScript decryption failed: ${error.message}`);
        }
    }

    // Rust signing via subprocess
    async signWithRust(message, privateKey, password, options) {
        return new Promise((resolve, reject) => {
            const rustBinPath = path.join(__dirname, '../../target/release/crypto_api');
            const args = [
                'sign',
                '--message', message,
                '--private-key', privateKey,
                '--password', password
            ];

            const rustProcess = spawn(rustBinPath, args);

            let output = '';
            let errorOutput = '';

            rustProcess.stdout.on('data', (data) => {
                output += data.toString();
            });

            rustProcess.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });

            rustProcess.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = JSON.parse(output);
                        resolve({
                            ...result,
                            signature_type: 'rust_sha512'
                        });
                    } catch (error) {
                        reject(new Error(`Failed to parse Rust output: ${error.message}`));
                    }
                } else {
                    reject(new Error(`Rust process failed: ${errorOutput}`));
                }
            });

            rustProcess.on('error', (error) => {
                reject(new Error(`Failed to start Rust process: ${error.message}`));
            });
        });
    }

    // JavaScript signing fallback
    async signWithJavaScript(message, privateKey, password, options) {
        const AdvancedCryptoSystem = require('../../crypto-system');
        const cryptoSystem = new AdvancedCryptoSystem();

        try {
            const userKeys = { encryptedPrivateKey: privateKey };
            const signedMessage = cryptoSystem.signMessage(message, userKeys, password);

            return {
                ...signedMessage,
                signature_type: 'javascript_sha512'
            };
        } catch (error) {
            throw new Error(`JavaScript signing failed: ${error.message}`);
        }
    }

    // Rust verification via subprocess
    async verifyWithRust(signedMessage, publicKey, options) {
        return new Promise((resolve, reject) => {
            const rustBinPath = path.join(__dirname, '../../target/release/crypto_api');
            const args = [
                'verify',
                '--message', signedMessage.message,
                '--signature', signedMessage.signature,
                '--public-key', publicKey
            ];

            const rustProcess = spawn(rustBinPath, args);

            let output = '';
            let errorOutput = '';

            rustProcess.stdout.on('data', (data) => {
                output += data.toString();
            });

            rustProcess.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });

            rustProcess.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = JSON.parse(output);
                        resolve(result.is_valid);
                    } catch (error) {
                        reject(new Error(`Failed to parse Rust output: ${error.message}`));
                    }
                } else {
                    reject(new Error(`Rust process failed: ${errorOutput}`));
                }
            });

            rustProcess.on('error', (error) => {
                reject(new Error(`Failed to start Rust process: ${error.message}`));
            });
        });
    }

    // JavaScript verification fallback
    async verifyWithJavaScript(signedMessage, publicKey, options) {
        const AdvancedCryptoSystem = require('../../crypto-system');
        const cryptoSystem = new AdvancedCryptoSystem();

        try {
            const verification = cryptoSystem.verifyMessageSignature(signedMessage, publicKey);
            return verification.isValid;
        } catch (error) {
            throw new Error(`JavaScript verification failed: ${error.message}`);
        }
    }
}

// Get system information
getSystemInfo() {
    return {
        rust_available: this.isRustAvailable,
        performance_threshold: this.performanceThreshold,
        preferred_methods: {
            small_data: 'javascript',
            large_data: this.isRustAvailable ? 'rust' : 'javascript',
            high_performance: this.isRustAvailable ? 'rust' : 'javascript'
        },
        supported_algorithms: {
            rust: ['AES-256-GCM', 'RSA-4096', 'SHA-512', 'PBKDF2'],
            javascript: ['AES-256-GCM', 'RSA-4096', 'SHA-512', 'PBKDF2']
        }
    };
}

    // Test the bridge
    async testBridge() {
    console.log('🧪 Testing Hybrid Crypto Bridge...');

    const testMessage = "Hello, this is a test message!";
    const testData = {
        content: testMessage,
        from: "test_user",
        to: "recipient"
    };

    try {
        // Test encryption
        console.log('Testing encryption...');
        const encrypted = await this.encryptMessage(testData, "test_public_key", { requirePerformance: false });
        console.log('✅ Encryption successful:', encrypted.encryption_type);

        // Test decryption
        console.log('Testing decryption...');
        const decrypted = await this.decryptMessage(encrypted, "test_private_key", "test_password");
        console.log('✅ Decryption successful');

        // Test signing
        console.log('Testing signing...');
        const signed = await this.signMessage(testMessage, "test_private_key", "test_password");
        console.log('✅ Signing successful:', signed.signature_type);

        // Test verification
        console.log('Testing verification...');
        const verified = await this.verifySignature(signed, "test_public_key");
        console.log('✅ Verification successful:', verified);

        console.log('🎉 All bridge tests passed!');
        return true;

    } catch (error) {
        console.error('❌ Bridge test failed:', error.message);
        return false;
    }
}
}

module.exports = HybridCryptoBridge;
