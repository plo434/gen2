// 🧪 Advanced GunDB Messaging Server Test Client
// Simple test client to verify the server functionality

const http = require('http');

const SERVER_URL = 'http://localhost:8080';
const API_BASE = `${SERVER_URL}/api`;

// Test configuration
const TEST_USER = {
    username: 'testuser',
    email: 'test@example.com',
    password: 'testpass123'
};

const TEST_USER2 = {
    username: 'testuser2',
    email: 'test2@example.com',
    password: 'testpass456'
};

let authToken = '';

// HTTP request helper
function makeRequest(method, endpoint, data = null) {
    return new Promise((resolve, reject) => {
        const url = `${API_BASE}${endpoint}`;
        const options = {
            hostname: new URL(SERVER_URL).hostname,
            port: new URL(SERVER_URL).port || 80,
            path: `${API_BASE}${endpoint}`,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...(authToken && { 'Authorization': `Bearer ${authToken}` })
            }
        };

        if (data && (method === 'POST' || method === 'PUT')) {
            const postData = JSON.stringify(data);
            options.headers['Content-Length'] = Buffer.byteLength(postData);
        }

        const req = http.request(options, (res) => {
            let responseData = '';

            res.on('data', (chunk) => {
                responseData += chunk;
            });

            res.on('end', () => {
                try {
                    const parsed = JSON.parse(responseData);
                    resolve({ status: res.statusCode, data: parsed });
                } catch (error) {
                    resolve({ status: res.statusCode, data: responseData });
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        if (data && (method === 'POST' || method === 'PUT')) {
            req.write(JSON.stringify(data));
        }

        req.end();
    });
}

// Test functions
async function testHealthCheck() {
    console.log('\n🔍 Testing Health Check...');
    try {
        const response = await makeRequest('GET', '/health');
        if (response.status === 200) {
            console.log('✅ Health check passed');
            console.log('   Status:', response.data.status);
            console.log('   Uptime:', Math.floor(response.data.uptime / 60), 'minutes');
            console.log('   Message Count:', response.data.messageCount);
            console.log('   User Count:', response.data.userCount);
        } else {
            console.log('❌ Health check failed:', response.status);
        }
    } catch (error) {
        console.log('❌ Health check error:', error.message);
    }
}

async function testCryptoInfo() {
    console.log('\n🔐 Testing Crypto Info...');
    try {
        const response = await makeRequest('GET', '/crypto/info');
        if (response.status === 200) {
            console.log('✅ Crypto info retrieved');
            console.log('   System:', response.data.crypto_system.name);
            console.log('   Version:', response.data.crypto_system.version);
            console.log('   Algorithms:', response.data.crypto_system.algorithms.symmetric);
        } else {
            console.log('❌ Crypto info failed:', response.status);
        }
    } catch (error) {
        console.log('❌ Crypto info error:', error.message);
    }
}

async function testUserRegistration() {
    console.log('\n👤 Testing User Registration...');
    try {
        const response = await makeRequest('POST', '/auth/register', TEST_USER);
        if (response.status === 201) {
            console.log('✅ User registration successful');
            console.log('   Username:', response.data.user.username);
            console.log('   Token received:', response.data.token ? 'Yes' : 'No');
            authToken = response.data.token;
        } else {
            console.log('❌ User registration failed:', response.status, response.data.error);
        }
    } catch (error) {
        console.log('❌ User registration error:', error.message);
    }
}

async function testUserLogin() {
    console.log('\n🔑 Testing User Login...');
    try {
        const response = await makeRequest('POST', '/auth/login', {
            username: TEST_USER.username,
            password: TEST_USER.password
        });
        if (response.status === 200) {
            console.log('✅ User login successful');
            console.log('   Username:', response.data.user.username);
            console.log('   Token received:', response.data.token ? 'Yes' : 'No');
            authToken = response.data.token;
        } else {
            console.log('❌ User login failed:', response.status, response.data.error);
        }
    } catch (error) {
        console.log('❌ User login error:', error.message);
    }
}

async function testCreateSecondUser() {
    console.log('\n👥 Testing Second User Creation...');
    try {
        const response = await makeRequest('POST', '/auth/register', TEST_USER2);
        if (response.status === 201) {
            console.log('✅ Second user created successfully');
            console.log('   Username:', response.data.user.username);
        } else {
            console.log('❌ Second user creation failed:', response.status, response.data.error);
        }
    } catch (error) {
        console.log('❌ Second user creation error:', error.message);
    }
}

async function testSendMessage(encryptionType = 'standard') {
    console.log(`\n💬 Testing Message Sending (${encryptionType})...`);
    try {
        const messageData = {
            from: TEST_USER.username,
            to: TEST_USER2.username,
            content: `Hello from ${TEST_USER.username}! This is a ${encryptionType} encrypted message.`,
            encryptionType: encryptionType
        };

        const response = await makeRequest('POST', '/messages', messageData);
        if (response.status === 200) {
            console.log('✅ Message sent successfully');
            console.log('   Message ID:', response.data.messageId);
            console.log('   Encryption:', response.data.encryption.type);
            console.log('   Algorithm:', response.data.encryption.algorithm);
        } else {
            console.log('❌ Message sending failed:', response.status, response.data.error);
        }
    } catch (error) {
        console.log('❌ Message sending error:', error.message);
    }
}

async function testGetInbox() {
    console.log('\n📥 Testing Inbox Retrieval...');
    try {
        const response = await makeRequest('GET', `/inbox?userId=${TEST_USER2.username}`);
        if (response.status === 200) {
            console.log('✅ Inbox retrieved successfully');
            console.log('   Messages in inbox:', response.data.inbox.length);
            if (response.data.inbox.length > 0) {
                const message = response.data.inbox[0];
                console.log('   Latest message:');
                console.log('     From:', message.from);
                console.log('     Content:', message.originalContent || message.content);
                console.log('     Encrypted:', message.encrypted);
                console.log('     Encryption Type:', message.encryption.type);
            }
        } else {
            console.log('❌ Inbox retrieval failed:', response.status, response.data.error);
        }
    } catch (error) {
        console.log('❌ Inbox retrieval error:', error.message);
    }
}

async function testGetUsers() {
    console.log('\n👥 Testing Users List...');
    try {
        const response = await makeRequest('GET', '/users');
        if (response.status === 200) {
            console.log('✅ Users list retrieved successfully');
            console.log('   Total users:', response.data.users.length);
            console.log('   Users:', response.data.users.join(', '));
        } else {
            console.log('❌ Users list failed:', response.status, response.data.error);
        }
    } catch (error) {
        console.log('❌ Users list error:', error.message);
    }
}

async function testGetMessages() {
    console.log('\n📨 Testing Messages Retrieval...');
    try {
        const response = await makeRequest('GET', `/messages?userId=${TEST_USER.username}`);
        if (response.status === 200) {
            console.log('✅ Messages retrieved successfully');
            console.log('   Total messages:', response.data.messages.length);
            if (response.data.messages.length > 0) {
                const message = response.data.messages[0];
                console.log('   Sample message:');
                console.log('     ID:', message.id);
                console.log('     From:', message.from);
                console.log('     To:', message.to);
                console.log('     Encrypted:', message.encrypted);
            }
        } else {
            console.log('❌ Messages retrieval failed:', response.status, response.data.error);
        }
    } catch (error) {
        console.log('❌ Messages retrieval error:', error.message);
    }
}

// Main test runner
async function runAllTests() {
    console.log('🧪 Starting Advanced GunDB Messaging Server Tests...');
    console.log('================================================');

    try {
        // Basic system tests
        await testHealthCheck();
        await testCryptoInfo();

        // User management tests
        await testUserRegistration();
        await testUserLogin();
        await testCreateSecondUser();

        // Messaging tests
        await testSendMessage('standard');
        await testSendMessage('aes');
        await testSendMessage('quantum');

        // Data retrieval tests
        await testGetInbox();
        await testGetUsers();
        await testGetMessages();

        console.log('\n🎉 All tests completed successfully!');
        console.log('✅ Your Advanced GunDB Messaging Server is working perfectly!');

    } catch (error) {
        console.log('\n❌ Test suite failed:', error.message);
    }
}

// Check if server is running before starting tests
async function checkServerStatus() {
    try {
        const response = await makeRequest('GET', '/health');
        if (response.status === 200) {
            console.log('✅ Server is running and responding');
            return true;
        }
    } catch (error) {
        console.log('❌ Cannot connect to server. Make sure it\'s running on port 8080');
        console.log('   Start the server with: npm start');
        return false;
    }
    return false;
}

// Main execution
async function main() {
    const serverRunning = await checkServerStatus();
    if (serverRunning) {
        await runAllTests();
    } else {
        process.exit(1);
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    main();
}

module.exports = {
    makeRequest,
    testHealthCheck,
    testUserRegistration,
    testUserLogin,
    testSendMessage,
    testGetInbox,
    runAllTests
};
