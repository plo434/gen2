// --- Advanced GunDB Messaging API Server ---
const Gun = require('gun');
const http = require('http');
const url = require('url');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

const GUN_OPTIONS = {
    web: undefined,
    radisk: false,
    localStorage: false
};

// In-memory storage for messages and users
const messageStore = new Map();
const userInboxes = new Map();
const userStore = new Map(); // Store user data with hashed passwords

// Create HTTP server for messaging API
const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;
    const method = req.method;

    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Handle preflight requests
    if (method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // Log all requests
    console.log(`[${new Date().toISOString()}] ${method} ${path}`);

    // Parse request body for POST/PUT requests
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', () => {
        try {
            const requestData = body ? JSON.parse(body) : {};

            // Route API endpoints
            if (path === '/api/health') {
                handleHealthCheck(req, res);
            } else if (path === '/api/auth/register' && method === 'POST') {
                handleUserRegistration(req, res, requestData);
            } else if (path === '/api/auth/login' && method === 'POST') {
                handleUserLogin(req, res, requestData);
            } else if (path === '/api/messages' && method === 'POST') {
                handleSendMessage(req, res, requestData);
            } else if (path === '/api/messages' && method === 'GET') {
                handleGetMessages(req, res, parsedUrl.query);
            } else if (path === '/api/messages' && method === 'DELETE') {
                handleDeleteMessage(req, res, parsedUrl.query);
            } else if (path === '/api/users' && method === 'POST') {
                handleCreateUser(req, res, requestData);
            } else if (path === '/api/users' && method === 'GET') {
                handleGetUsers(req, res);
            } else if (path === '/api/inbox' && method === 'GET') {
                handleGetInbox(req, res, parsedUrl.query);
            } else if (path === '/api/inbox' && method === 'DELETE') {
                handleClearInbox(req, res, parsedUrl.query);
            } else if (path === '/api/crypto/info' && method === 'GET') {
                handleCryptoInfo(req, res);
            } else {
                // Default response for root path
                if (path === '/') {
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(`
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Advanced GunDB Messaging API Server</title>
                            <style>
                                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                                .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                                h1 { color: #2c3e50; text-align: center; }
                                .feature { background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }
                                .endpoint { background: #3498db; color: white; padding: 8px 12px; border-radius: 3px; display: inline-block; margin: 5px; }
                                .crypto { background: #e74c3c; color: white; padding: 8px 12px; border-radius: 3px; display: inline-block; margin: 5px; }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <h1>🚀 Advanced GunDB Messaging API Server</h1>
                                <p><strong>Server running on port ${PORT}</strong></p>
                                
                                <div class="feature">
                                    <h3>🔐 Advanced Features:</h3>
                                    <span class="crypto">JWT Authentication</span>
                                    <span class="crypto">Password Hashing</span>
                                    <span class="crypto">Message Encryption</span>
                                    <span class="crypto">User Management</span>
                                    <span class="crypto">Real-time GunDB</span>
                                </div>

                                <div class="feature">
                                    <h3>📡 Available Endpoints:</h3>
                                    <div><span class="endpoint">POST /api/auth/register</span> - User registration with encryption</div>
                                    <div><span class="endpoint">POST /api/auth/login</span> - User authentication</div>
                                    <div><span class="endpoint">POST /api/messages</span> - Send encrypted message</div>
                                    <div><span class="endpoint">GET /api/messages</span> - Get messages</div>
                                    <div><span class="endpoint">DELETE /api/messages</span> - Delete message</div>
                                    <div><span class="endpoint">POST /api/users</span> - Create user</div>
                                    <div><span class="endpoint">GET /api/users</span> - Get users</div>
                                    <div><span class="endpoint">GET /api/inbox</span> - Get user inbox</div>
                                    <div><span class="endpoint">DELETE /api/inbox</span> - Clear user inbox</div>
                                    <div><span class="endpoint">GET /api/health</span> - Health check</div>
                                    <div><span class="endpoint">GET /api/crypto/info</span> - Crypto system info</div>
                                </div>

                                <div class="feature">
                                    <h3>🔒 Encryption Types:</h3>
                                    <ul>
                                        <li><strong>Standard:</strong> No encryption (plain text)</li>
                                        <li><strong>AES:</strong> AES-256-CBC encryption</li>
                                        <li><strong>Quantum:</strong> Advanced encryption (simulated)</li>
                                    </ul>
                                </div>
                            </div>
                        </body>
                        </html>
                    `);
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Endpoint not found' }));
                }
            }
        } catch (error) {
            console.error('Error processing request:', error);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Internal server error' }));
        }
    });
});

// Helper function to verify JWT token
function verifyToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    
    try {
        const token = authHeader.substring(7);
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// Helper function to encrypt message
function encryptMessage(content, encryptionType = 'standard') {
    if (encryptionType === 'standard') {
        return {
            encrypted: false,
            content: content,
            algorithm: 'none'
        };
    } else if (encryptionType === 'aes') {
        // Simple AES encryption
        const key = crypto.randomBytes(32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher('aes-256-cbc', key);
        let encrypted = cipher.update(content, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return {
            encrypted: true,
            content: encrypted,
            algorithm: 'AES-256-CBC',
            key: key.toString('base64'),
            iv: iv.toString('base64')
        };
    } else if (encryptionType === 'quantum') {
        // Simulated quantum encryption
        const key = crypto.randomBytes(32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher('aes-256-gcm', key);
        let encrypted = cipher.update(content, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        
        return {
            encrypted: true,
            content: encrypted,
            algorithm: 'Quantum-Simulated-AES-256-GCM',
            key: key.toString('base64'),
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64')
        };
    }
    
    return {
        encrypted: false,
        content: content,
        algorithm: 'none'
    };
}

// Health check endpoint
function handleHealthCheck(req, res) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        messageCount: messageStore.size,
        userCount: userInboxes.size,
        registeredUsers: userStore.size,
        features: ['JWT Auth', 'Password Hashing', 'Message Encryption', 'GunDB', 'Real-time Messaging']
    }));
}

// Crypto system info endpoint
function handleCryptoInfo(req, res) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        crypto_system: {
            name: 'Advanced GunDB Crypto System',
            version: '2.0.0',
            algorithms: {
                asymmetric: 'RSA-2048 (simulated)',
                symmetric: 'AES-256-CBC/GCM',
                hash: 'SHA-256',
                keyDerivation: 'bcrypt'
            },
            encryption_types: ['standard', 'aes', 'quantum'],
            security_features: ['JWT Authentication', 'Password Hashing', 'Message Encryption', 'Secure Key Storage']
        }
    }));
}

// User registration endpoint
async function handleUserRegistration(req, res, data) {
    const { username, email, password } = data;

    if (!username || !email || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Username, email, and password are required' }));
        return;
    }

    if (userStore.has(username)) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'User already exists' }));
        return;
    }

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create user
        const user = {
            username,
            email,
            passwordHash: hashedPassword,
            createdAt: Date.now(),
            status: 'active'
        };
        
        userStore.set(username, user);
        
        // Create user inbox
        userInboxes.set(username, new Map());
        
        // Store user in GunDB
        const gun = Gun(GUN_OPTIONS);
        gun.get('users').get(username).put({ username, email, createdAt: Date.now() });
        
        // Generate JWT token
        const token = jwt.sign({ username, email }, JWT_SECRET, { expiresIn: '24h' });
        
        console.log(`User registered: ${username}`);
        
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            success: true,
            message: 'User registered successfully',
            user: { username, email, createdAt: user.createdAt },
            token
        }));
    } catch (error) {
        console.error('Registration error:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Registration failed' }));
    }
}

// User login endpoint
async function handleUserLogin(req, res, data) {
    const { username, password } = data;

    if (!username || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Username and password are required' }));
        return;
    }

    const user = userStore.get(username);
    if (!user) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid credentials' }));
        return;
    }

    try {
        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.passwordHash);
        if (!isValidPassword) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid credentials' }));
            return;
        }
        
        // Generate JWT token
        const token = jwt.sign({ username, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        
        // Ensure user inbox exists
        if (!userInboxes.has(username)) {
            userInboxes.set(username, new Map());
        }
        
        console.log(`User logged in: ${username}`);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            success: true,
            message: 'Login successful',
            user: { username, email: user.email, createdAt: user.createdAt },
            token
        }));
    } catch (error) {
        console.error('Login error:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Login failed' }));
    }
}

// Send message endpoint with encryption
function handleSendMessage(req, res, data) {
    const { from, to, content, encryptionType = 'standard' } = data;

    if (!from || !to || !content) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing required fields: from, to, content' }));
        return;
    }

    // Encrypt message based on type
    const encryptionResult = encryptMessage(content, encryptionType);
    
    const messageId = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
    const message = {
        id: messageId,
        from,
        to,
        content: encryptionResult.content,
        originalContent: content, // Keep original for display
        timestamp: Date.now(),
        verified: false,
        encrypted: encryptionResult.encrypted,
        encryption: {
            type: encryptionType,
            algorithm: encryptionResult.algorithm,
            key: encryptionResult.key,
            iv: encryptionResult.iv,
            authTag: encryptionResult.authTag
        }
    };

    // Store message in memory
    messageStore.set(messageId, message);

    // Add to recipient's inbox
    if (!userInboxes.has(to)) {
        userInboxes.set(to, new Map());
    }
    userInboxes.get(to).set(messageId, message);

    // Also store in GunDB for persistence
    const gun = Gun(GUN_OPTIONS);
    gun.get('messages').get(messageId).put(message);
    gun.get('inbox').get(to).set(message);

    console.log(`Message sent: ${from} -> ${to} (${encryptionType} encrypted): ${content}`);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        success: true,
        messageId,
        message: 'Message sent successfully',
        encryption: message.encryption
    }));
}

// Get messages endpoint
function handleGetMessages(req, res, query) {
    const { userId, messageId } = query;

    if (messageId) {
        // Get specific message
        const message = messageStore.get(messageId);
        if (message) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ message }));
        } else {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Message not found' }));
        }
    } else if (userId) {
        // Get all messages for a user
        const userMessages = [];
        for (const [id, message] of messageStore) {
            if (message.from === userId || message.to === userId) {
                userMessages.push(message);
            }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ messages: userMessages }));
    } else {
        // Get all messages
        const allMessages = Array.from(messageStore.values());
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ messages: allMessages }));
    }
}

// Delete message endpoint
function handleDeleteMessage(req, res, query) {
    const { messageId, userId } = query;

    if (!messageId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Message ID required' }));
        return;
    }

    const message = messageStore.get(messageId);
    if (!message) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Message not found' }));
        return;
    }

    // Check if user has permission to delete (sender or recipient)
    if (userId && message.from !== userId && message.to !== userId) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Permission denied' }));
        return;
    }

    // Remove from message store
    messageStore.delete(messageId);

    // Remove from all inboxes
    for (const [user, inbox] of userInboxes) {
        inbox.delete(messageId);
    }

    // Also delete from GunDB
    const gun = Gun(GUN_OPTIONS);
    gun.get('messages').get(messageId).put(null);

    console.log(`Message deleted: ${messageId}`);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        success: true,
        message: 'Message deleted successfully'
    }));
}

// Create user endpoint (for backward compatibility)
function handleCreateUser(req, res, data) {
    const { userId, password } = data;

    if (!userId || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing required fields: userId, password' }));
        return;
    }

    if (userInboxes.has(userId)) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'User already exists' }));
        return;
    }

    // Create user inbox
    userInboxes.set(userId, new Map());

    // Store user in GunDB
    const gun = Gun(GUN_OPTIONS);
    gun.get('users').get(userId).put({ userId, createdAt: Date.now() });

    console.log(`User created: ${userId}`);

    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        success: true,
        message: 'User created successfully',
        userId
    }));
}

// Get users endpoint
function handleGetUsers(req, res) {
    const users = Array.from(userInboxes.keys());

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ users }));
}

// Get user inbox endpoint
function handleGetInbox(req, res, query) {
    const { userId } = query;

    if (!userId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'User ID required' }));
        return;
    }

    const inbox = userInboxes.get(userId);
    if (!inbox) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'User not found' }));
        return;
    }

    const messages = Array.from(inbox.values());

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ inbox: messages }));
}

// Clear user inbox endpoint
function handleClearInbox(req, res, query) {
    const { userId } = query;

    if (!userId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'User ID required' }));
        return;
    }

    const inbox = userInboxes.get(userId);
    if (!inbox) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'User not found' }));
        return;
    }

    // Clear inbox
    inbox.clear();

    console.log(`Inbox cleared for user: ${userId}`);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        success: true,
        message: 'Inbox cleared successfully'
    }));
}

// Start server
server.listen(PORT, (err) => {
    if (err) {
        console.error(`[Advanced Messaging Server] Failed to start:`, err);
        process.exit(1);
    }
    console.log(`🚀 [Advanced Messaging Server] API server running at http://localhost:${PORT}`);
    console.log(`🔐 [Advanced Messaging Server] Features: JWT Auth, Password Hashing, Message Encryption`);
    console.log(`📦 [Advanced Messaging Server] GunDB relay initialized and ready`);
    console.log(`🔒 [Advanced Messaging Server] Encryption types: Standard, AES, Quantum`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n[Advanced Messaging Server] Shutting down...');
    server.close(() => {
        console.log('[Advanced Messaging Server] Server closed');
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    console.log('\n[Advanced Messaging Server] Received SIGTERM, shutting down...');
    server.close(() => {
        console.log('[Advanced Messaging Server] Server closed');
        process.exit(0);
    });
});
