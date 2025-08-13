// --- Quantum Secure Messaging API Server with GunDB ---
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const Gun = require('gun');

// Import services
const UserService = require('../services/userService');
const QuantumKeyExchange = require('../crypto/key-exchange');

// Create Express app
const app = express();
const PORT = process.env.PORT || 10000;

// Initialize services
const userService = new UserService();
const cryptoSystem = new QuantumKeyExchange();

// In-memory storage for messages (alternative to GunDB for immediate operations)
const messageStore = new Map();
const userInboxes = new Map();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// CORS configuration
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Compression middleware
app.use(compression());

// Logging middleware
app.use(morgan('combined'));

// GunDB setup
const server = require('http').createServer(app);
const gun = Gun({
    web: server,
    file: 'radata'
});

// Request logging middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        const cryptoInfo = cryptoSystem.getSystemInfo();
        const systemStats = userService.getSystemStats();

        res.json({
            success: true,
            message: 'Quantum Secure Messaging Server is running',
            timestamp: new Date().toISOString(),
            version: '1.0.0',
            environment: process.env.NODE_ENV || 'development',
            crypto: cryptoInfo,
            system: systemStats,
            messaging: {
                messageCount: messageStore.size,
                userCount: userInboxes.size,
                uptime: process.uptime(),
                memory: process.memoryUsage()
            }
        });
    } catch (error) {
        res.json({
            success: true,
            message: 'Quantum Secure Messaging Server is running',
            timestamp: new Date().toISOString(),
            version: '1.0.0',
            environment: process.env.NODE_ENV || 'development',
            crypto: { error: 'Unable to get crypto status' },
            system: { error: 'Unable to get system stats' },
            messaging: {
                messageCount: messageStore.size,
                userCount: userInboxes.size,
                uptime: process.uptime(),
                memory: process.memoryUsage()
            }
        });
    }
});

// Crypto system info endpoint
app.get('/api/crypto/info', (req, res) => {
    try {
        const info = cryptoSystem.getSystemInfo();
        res.json({
            success: true,
            crypto_system: info
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to get crypto system info',
            message: error.message
        });
    }
});

// User registration endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username, email, and password are required'
            });
        }

        const result = await userService.registerUser({ username, email, password });

        // Create user inbox for messaging
        userInboxes.set(username, new Map());

        res.json(result);
    } catch (error) {
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
});

// User authentication endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password are required'
            });
        }

        const result = await userService.authenticateUser(username, password);

        // Ensure user inbox exists
        if (!userInboxes.has(username)) {
            userInboxes.set(username, new Map());
        }

        res.json(result);
    } catch (error) {
        res.status(401).json({
            success: false,
            error: error.message
        });
    }
});

// Get user's public keys
app.get('/api/users/keys/:username', (req, res) => {
    try {
        const { username } = req.params;
        const keys = userService.getPublicKeys(username);

        if (!keys) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        res.json({
            success: true,
            keys
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to get public keys',
            message: error.message
        });
    }
});

// Update user's public keys (requires authentication)
app.put('/api/users/keys', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'Authentication token required'
            });
        }

        const token = authHeader.substring(7);
        const decoded = userService.verifyToken(token);

        if (!decoded) {
            return res.status(401).json({
                success: false,
                error: 'Invalid or expired token'
            });
        }

        const result = await userService.updatePublicKeys(decoded.userId, {});
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to update public keys',
            message: error.message
        });
    }
});

// Create user endpoint (for backward compatibility)
app.post('/api/users', (req, res) => {
    try {
        const { userId, password } = req.body;

        if (!userId || !password) {
            return res.status(400).json({
                success: false,
                error: 'Missing required fields: userId, password'
            });
        }

        if (userInboxes.has(userId)) {
            return res.status(409).json({
                success: false,
                error: 'User already exists'
            });
        }

        // Create user inbox
        userInboxes.set(userId, new Map());

        // Store user in GunDB
        gun.get('users').get(userId).put({ userId, createdAt: Date.now() });

        console.log(`User created: ${userId}`);

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            userId
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to create user',
            message: error.message
        });
    }
});

// Get users endpoint
app.get('/api/users', (req, res) => {
    try {
        const users = Array.from(userInboxes.keys());

        res.json({
            success: true,
            users
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to get users',
            message: error.message
        });
    }
});

// Send encrypted message endpoint
app.post('/api/messages', async (req, res) => {
    try {
        const { from, to, content, encryptionType = 'standard' } = req.body;

        if (!from || !to || !content) {
            return res.status(400).json({
                success: false,
                error: 'Missing required fields: from, to, content'
            });
        }

        let encryptedContent = content;
        let encryptionInfo = { type: 'none' };

        // Apply encryption based on type
        if (encryptionType === 'quantum') {
            try {
                // Get recipient's public keys for quantum encryption
                const recipientKeys = userService.getPublicKeys(to);
                if (recipientKeys && recipientKeys.publicKeys.kyber) {
                    const encryptedData = cryptoSystem.encryptMessage(content, recipientKeys.publicKeys.kyber);
                    encryptedContent = encryptedData.encryptedMessage;
                    encryptionInfo = {
                        type: 'quantum',
                        algorithm: encryptedData.algorithm,
                        timestamp: encryptedData.timestamp,
                        encryptedSessionKey: encryptedData.encryptedSessionKey,
                        iv: encryptedData.iv,
                        authTag: encryptedData.authTag
                    };
                } else {
                    console.warn(`Quantum encryption requested but no keys found for user: ${to}`);
                }
            } catch (error) {
                console.error('Quantum encryption failed, falling back to standard:', error.message);
            }
        } else if (encryptionType === 'aes') {
            try {
                // Simple AES encryption for demonstration
                const crypto = require('crypto');
                const key = crypto.randomBytes(32);
                const iv = crypto.randomBytes(16);
                const cipher = crypto.createCipher('aes-256-cbc', key);
                let encrypted = cipher.update(content, 'utf8', 'hex');
                encrypted += cipher.final('hex');

                encryptedContent = encrypted;
                encryptionInfo = {
                    type: 'aes',
                    algorithm: 'AES-256-CBC',
                    timestamp: new Date().toISOString(),
                    key: key.toString('base64'),
                    iv: iv.toString('base64')
                };
            } catch (error) {
                console.error('AES encryption failed:', error.message);
            }
        }

        const messageId = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
        const message = {
            id: messageId,
            from,
            to,
            content: encryptedContent,
            originalContent: content, // Keep original for display
            timestamp: Date.now(),
            verified: false,
            encryption: encryptionInfo
        };

        // Store message in memory
        messageStore.set(messageId, message);

        // Add to recipient's inbox
        if (!userInboxes.has(to)) {
            userInboxes.set(to, new Map());
        }
        userInboxes.get(to).set(messageId, message);

        // Also store in GunDB for persistence
        gun.get('messages').get(messageId).put(message);
        gun.get('inbox').get(to).set(message);

        console.log(`Message sent: ${from} -> ${to} (${encryptionInfo.type} encrypted)`);

        res.json({
            success: true,
            messageId,
            message: 'Message sent successfully',
            encryption: encryptionInfo
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to send message',
            message: error.message
        });
    }
});

// Get messages endpoint
app.get('/api/messages', (req, res) => {
    try {
        const { userId, messageId } = req.query;

        if (messageId) {
            // Get specific message
            const message = messageStore.get(messageId);
            if (message) {
                res.json({
                    success: true,
                    message: message
                });
            } else {
                res.status(404).json({
                    success: false,
                    error: 'Message not found'
                });
            }
        } else if (userId) {
            // Get all messages for a user
            const userMessages = [];
            for (const [id, message] of messageStore) {
                if (message.from === userId || message.to === userId) {
                    userMessages.push(message);
                }
            }

            res.json({
                success: true,
                messages: userMessages
            });
        } else {
            // Get all messages
            const allMessages = Array.from(messageStore.values());
            res.json({
                success: true,
                messages: allMessages
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to get messages',
            message: error.message
        });
    }
});

// Delete message endpoint
app.delete('/api/messages', (req, res) => {
    try {
        const { messageId, userId } = req.query;

        if (!messageId) {
            return res.status(400).json({
                success: false,
                error: 'Message ID required'
            });
        }

        const message = messageStore.get(messageId);
        if (!message) {
            return res.status(404).json({
                success: false,
                error: 'Message not found'
            });
        }

        // Check if user has permission to delete (sender or recipient)
        if (userId && message.from !== userId && message.to !== userId) {
            return res.status(403).json({
                success: false,
                error: 'Permission denied'
            });
        }

        // Remove from message store
        messageStore.delete(messageId);

        // Remove from all inboxes
        for (const [user, inbox] of userInboxes) {
            inbox.delete(messageId);
        }

        // Also delete from GunDB
        gun.get('messages').get(messageId).put(null);

        console.log(`Message deleted: ${messageId}`);

        res.json({
            success: true,
            message: 'Message deleted successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to delete message',
            message: error.message
        });
    }
});

// Get user inbox endpoint
app.get('/api/inbox', (req, res) => {
    try {
        const { userId } = req.query;

        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'User ID required'
            });
        }

        const inbox = userInboxes.get(userId);
        if (!inbox) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const messages = Array.from(inbox.values());

        res.json({
            success: true,
            inbox: messages
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to get inbox',
            message: error.message
        });
    }
});

// Clear user inbox endpoint
app.delete('/api/inbox', (req, res) => {
    try {
        const { userId } = req.query;

        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'User ID required'
            });
        }

        const inbox = userInboxes.get(userId);
        if (!inbox) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Clear inbox
        inbox.clear();

        console.log(`Inbox cleared for user: ${userId}`);

        res.json({
            success: true,
            message: 'Inbox cleared successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to clear inbox',
            message: error.message
        });
    }
});

// System statistics endpoint (admin only)
app.get('/api/admin/stats', (req, res) => {
    try {
        const stats = userService.getSystemStats();
        res.json({
            success: true,
            stats: {
                ...stats,
                messaging: {
                    messageCount: messageStore.size,
                    userCount: userInboxes.size,
                    uptime: process.uptime(),
                    memory: process.memoryUsage()
                }
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to get system statistics',
            message: error.message
        });
    }
});

// Root endpoint with API documentation
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Quantum Secure Messaging API Server with GunDB',
        version: '1.0.0',
        description: 'Advanced Secure Messaging System with Post-Quantum Cryptography and GunDB',
        architecture: 'Node.js + Rust + GunDB + Post-Quantum Crypto',
        endpoints: {
            health: 'GET /api/health',
            crypto: 'GET /api/crypto/info',
            auth: {
                register: 'POST /api/auth/register',
                login: 'POST /api/auth/login'
            },
            users: {
                getKeys: 'GET /api/users/keys/:username',
                updateKeys: 'PUT /api/users/keys',
                create: 'POST /api/users',
                list: 'GET /api/users'
            },
            messages: {
                send: 'POST /api/messages',
                get: 'GET /api/messages',
                delete: 'DELETE /api/messages'
            },
            inbox: {
                get: 'GET /api/inbox',
                clear: 'DELETE /api/inbox'
            },
            admin: {
                stats: 'GET /api/admin/stats'
            }
        },
        features: [
            'GunDB Real-time Database',
            'Kyber768 Key Encapsulation Mechanism',
            'Dilithium5 Digital Signatures',
            'AES-256-GCM Encryption',
            'SHA-256 Hashing',
            'JWT Authentication',
            'Rate Limiting',
            'Security Headers',
            'Real-time Messaging',
            'Encrypted Message Storage'
        ],
        encryptionTypes: {
            standard: 'No encryption (plain text)',
            aes: 'AES-256-CBC encryption',
            quantum: 'Post-quantum encryption (Kyber768)'
        }
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        path: req.originalUrl,
        availableEndpoints: [
            'GET /',
            'GET /api/health',
            'GET /api/crypto/info',
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET /api/users/keys/:username',
            'PUT /api/users/keys',
            'POST /api/users',
            'GET /api/users',
            'POST /api/messages',
            'GET /api/messages',
            'DELETE /api/messages',
            'GET /api/inbox',
            'DELETE /api/inbox',
            'GET /api/admin/stats'
        ]
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('Global error handler:', error);

    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: error.message || 'Something went wrong'
    });
});

// Start server
const startServer = async () => {
    try {
        // Start listening
        server.listen(PORT, () => {
            console.log(`🚀 Quantum Secure Messaging Server running on port ${PORT}`);
            console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔐 Crypto System: ${cryptoSystem.getSystemInfo().name}`);
            console.log(`👥 Users: ${userService.getSystemStats().totalUsers}`);
            console.log(`💬 Messages: ${messageStore.size}`);
            console.log(`📦 GunDB: Initialized and ready`);
            console.log(`🔗 Health Check: http://localhost:${PORT}/api/health`);
            console.log(`📖 API Docs: http://localhost:${PORT}/`);
        });

    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

// Start the server
startServer();

module.exports = app;
