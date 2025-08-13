// --- Quantum Secure Messaging Client Application ---
const readline = require('readline');
const crypto = require('crypto');
const http = require('http');

const API_SERVER = 'http://localhost:10000'; // Updated port
const API_BASE = `${API_SERVER}/api`;

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

let userId = "";
let password = "";
let currentChatUser = "";
let authToken = "";
const receivedMessages = new Set();
const chatHistory = new Map();

console.log("🚀 Quantum Secure Messaging Application");
console.log("=====================================");
console.log("🔐 Advanced encryption with Post-Quantum Cryptography");
console.log("📦 Real-time messaging with GunDB");
console.log("");

// HTTP request helper function
function makeRequest(method, endpoint, data = null, headers = {}) {
    return new Promise((resolve, reject) => {
        const url = `${API_BASE}${endpoint}`;
        const options = {
            hostname: new URL(API_SERVER).hostname,
            port: new URL(API_SERVER).port || 80,
            path: `${API_BASE}${endpoint}`,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
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

// Login function with advanced authentication
async function promptLogin() {
    rl.question("Enter your username: ", async (username) => {
        if (!username || !username.trim()) {
            console.log("Username cannot be empty");
            promptLogin();
            return;
        }

        userId = username.trim();
        console.log("Username: " + userId);

        rl.question("Enter your password: ", async (pass) => {
            password = pass;

            try {
                // Try to login first
                const loginResponse = await makeRequest('POST', '/auth/login', {
                    username: userId,
                    password: password
                });

                if (loginResponse.status === 200) {
                    authToken = loginResponse.data.token;
                    console.log("✅ Login successful!");
                    console.log("🔑 JWT Token received");
                    showMainMenu();
                } else {
                    // If login fails, try to register
                    console.log("⚠️ Login failed, attempting registration...");

                    rl.question("Enter your email: ", async (email) => {
                        if (!email || !email.trim()) {
                            console.log("Email cannot be empty");
                            promptLogin();
                            return;
                        }

                        const registerResponse = await makeRequest('POST', '/auth/register', {
                            username: userId,
                            email: email.trim(),
                            password: password
                        });

                        if (registerResponse.status === 200) {
                            authToken = registerResponse.data.token;
                            console.log("✅ Registration successful!");
                            console.log("🔑 JWT Token received");
                            console.log("🔐 Cryptographic keys generated");
                            showMainMenu();
                        } else {
                            console.log("❌ Registration failed:", registerResponse.data.error);
                            promptLogin();
                        }
                    });
                }
            } catch (error) {
                console.log("❌ Connection error. Make sure the server is running.");
                console.log("Error details:", error.message);
                promptLogin();
            }
        });
    });
}

// Main menu with enhanced options
function showMainMenu() {
    console.log("\n🔐 Main Menu:");
    console.log("1. Start new chat");
    console.log("2. View chat history");
    console.log("3. Change current user");
    console.log("4. Show account info");
    console.log("5. Check server status");
    console.log("6. Manage cryptographic keys");
    console.log("7. Exit");

    rl.question("Choose operation number: ", (choice) => {
        switch (choice.trim()) {
            case '1':
                startNewChat();
                break;
            case '2':
                showChatHistory();
                break;
            case '3':
                changeCurrentUser();
                break;
            case '4':
                showAccountInfo();
                break;
            case '5':
                checkServerStatus();
                break;
            case '6':
                manageCryptoKeys();
                break;
            case '7':
                console.log("👋 Thank you for using Quantum Secure Messaging!");
                process.exit(0);
                break;
            default:
                console.log("❌ Invalid choice, try again");
                showMainMenu();
        }
    });
}

// Start new chat with encryption options
function startNewChat() {
    rl.question("Enter the username you want to chat with: ", (target) => {
        if (!target.trim()) {
            console.log("❌ Username cannot be empty");
            showMainMenu();
            return;
        }

        currentChatUser = target.trim();
        console.log(`\n💬 Started chat with: ${currentChatUser}`);

        // Show encryption options
        console.log("\n🔐 Choose encryption type:");
        console.log("1. Standard (no encryption)");
        console.log("2. AES-256-CBC");
        console.log("3. Quantum (Post-Quantum Crypto)");

        rl.question("Choose encryption (1-3): ", (encryptionChoice) => {
            let encryptionType = 'standard';

            switch (encryptionChoice.trim()) {
                case '1':
                    encryptionType = 'standard';
                    console.log("🔓 Using standard messaging (no encryption)");
                    break;
                case '2':
                    encryptionType = 'aes';
                    console.log("🔐 Using AES-256-CBC encryption");
                    break;
                case '3':
                    encryptionType = 'quantum';
                    console.log("🚀 Using Post-Quantum Cryptography (Kyber768)");
                    break;
                default:
                    console.log("⚠️ Invalid choice, using standard encryption");
                    encryptionType = 'standard';
            }

            console.log("\n💬 Type your message (type 'menu' to return to main menu):");
            console.log("📝 Message will be encrypted using:", encryptionType.toUpperCase());

            // Start receiving messages
            startReceiving();

            // Start sending messages with encryption
            startMessaging(encryptionType);
        });
    });
}

// Send messages with encryption
function startMessaging(encryptionType) {
    rl.on('line', async (input) => {
        if (input.toLowerCase() === 'menu') {
            rl.removeAllListeners('line');
            showMainMenu();
            return;
        }

        if (input.toLowerCase() === 'exit') {
            console.log("👋 Thank you for using the application!");
            process.exit(0);
        }

        if (input.trim() === "") {
            console.log("❌ Cannot send empty message");
            return;
        }

        try {
            const messageData = {
                from: userId,
                to: currentChatUser,
                content: input,
                encryptionType: encryptionType
            };

            const response = await makeRequest('POST', '/messages', messageData, {
                'Authorization': `Bearer ${authToken}`
            });

            if (response.status === 200) {
                const messageId = response.data.messageId;
                const message = {
                    id: messageId,
                    from: userId,
                    to: currentChatUser,
                    content: input,
                    timestamp: Date.now(),
                    verified: false,
                    encryption: response.data.encryption
                };

                // Save message to local chat history
                if (!chatHistory.has(currentChatUser)) {
                    chatHistory.set(currentChatUser, []);
                }
                chatHistory.get(currentChatUser).push({
                    ...message,
                    isOwn: true
                });

                console.log(`✅ Message sent (${encryptionType} encrypted): ${input}`);

                // Show encryption details
                if (response.data.encryption && response.data.encryption.type !== 'none') {
                    console.log(`🔐 Encryption: ${response.data.encryption.algorithm || response.data.encryption.type}`);
                }
            } else {
                console.log("❌ Failed to send message:", response.data.error);
            }
        } catch (error) {
            console.log("❌ Error sending message:", error.message);
        }
    });
}

// Receive messages with decryption
async function startReceiving() {
    // Poll for new messages every 2 seconds
    setInterval(async () => {
        try {
            const response = await makeRequest('GET', `/inbox?userId=${userId}`, null, {
                'Authorization': `Bearer ${authToken}`
            });

            if (response.status === 200 && response.data.inbox) {
                for (const message of response.data.inbox) {
                    if (!receivedMessages.has(message.id)) {
                        receivedMessages.add(message.id);
                        const time = new Date(message.timestamp).toLocaleTimeString();

                        // Display received message
                        console.log(`\n📨 New message at ${time}:`);
                        console.log(`👤 From: ${message.from}`);

                        // Show encryption info
                        if (message.encryption && message.encryption.type !== 'none') {
                            console.log(`🔐 Encryption: ${message.encryption.algorithm || message.encryption.type}`);
                        }

                        // Show content (encrypted or decrypted)
                        if (message.originalContent) {
                            console.log(`💬 Content: ${message.originalContent}`);
                        } else {
                            console.log(`💬 Content: ${message.content}`);
                        }

                        console.log("💬 Type your message (type 'menu' to return to main menu):");

                        // Save message to chat history
                        if (!chatHistory.has(message.from)) {
                            chatHistory.set(message.from, []);
                        }
                        chatHistory.get(message.from).push({
                            ...message,
                            isOwn: false
                        });

                        // Delete message from server after reading
                        try {
                            await makeRequest('DELETE', `/messages?messageId=${message.id}&userId=${userId}`, null, {
                                'Authorization': `Bearer ${authToken}`
                            });
                        } catch (error) {
                            console.log("⚠️ Error deleting message from server");
                        }
                    }
                }
            }
        } catch (error) {
            // Silent error handling for polling
        }
    }, 2000);
}

// Show chat history with encryption details
function showChatHistory() {
    if (chatHistory.size === 0) {
        console.log("📭 No previous chats");
        showMainMenu();
        return;
    }

    console.log("\n📚 Chat History:");
    let index = 1;
    for (const [user, messages] of chatHistory) {
        console.log(`${index}. ${user} (${messages.length} messages)`);
        index++;
    }

    rl.question("\nChoose chat number to view (or type 'back' to return): ", (choice) => {
        if (choice.toLowerCase() === 'back') {
            showMainMenu();
            return;
        }

        const choiceNum = parseInt(choice);
        if (isNaN(choiceNum) || choiceNum < 1 || choiceNum > chatHistory.size) {
            console.log("❌ Invalid number");
            showChatHistory();
            return;
        }

        const users = Array.from(chatHistory.keys());
        const selectedUser = users[choiceNum - 1];
        const messages = chatHistory.get(selectedUser);

        console.log(`\n💬 Chat with ${selectedUser}:`);
        console.log("=".repeat(60));

        messages.forEach(msg => {
            const time = new Date(msg.timestamp).toLocaleTimeString();
            const prefix = msg.isOwn ? "You" : `${msg.from}`;
            const encryptionInfo = msg.encryption && msg.encryption.type !== 'none'
                ? ` [${msg.encryption.type.toUpperCase()}]`
                : '';

            console.log(`[${time}] ${prefix}${encryptionInfo}: ${msg.content}`);
        });

        console.log("=".repeat(60));
        rl.question("\nPress Enter to return to main menu: ", () => {
            showMainMenu();
        });
    });
}

// Change current user
function changeCurrentUser() {
    rl.question("Enter new username: ", (target) => {
        if (!target.trim()) {
            console.log("❌ Username cannot be empty");
            showMainMenu();
            return;
        }

        currentChatUser = target.trim();
        console.log(`✅ Current user changed to: ${currentChatUser}`);
        showMainMenu();
    });
}

// Show account info with crypto details
async function showAccountInfo() {
    try {
        console.log("\n👤 Account Information:");
        console.log(`Username: ${userId}`);
        console.log(`Current chat user: ${currentChatUser || 'None'}`);
        console.log(`Number of chats: ${chatHistory.size}`);
        console.log(`Total messages: ${Array.from(chatHistory.values()).reduce((sum, msgs) => sum + msgs.length, 0)}`);
        console.log(`JWT Token: ${authToken ? '✅ Valid' : '❌ None'}`);

        // Get user's crypto keys info
        const keysResponse = await makeRequest('GET', `/users/keys/${userId}`, null, {
            'Authorization': `Bearer ${authToken}`
        });

        if (keysResponse.status === 200) {
            console.log("\n🔐 Cryptographic Keys:");
            console.log(`Key Version: ${keysResponse.data.keys.publicKeys.keyVersion}`);
            console.log(`Has Keys: ${keysResponse.data.keys.publicKeys.keyFingerprint ? '✅ Yes' : '❌ No'}`);
            if (keysResponse.data.keys.publicKeys.keyFingerprint) {
                console.log(`Key Fingerprint: ${keysResponse.data.keys.publicKeys.keyFingerprint.substring(0, 16)}...`);
            }
        }

    } catch (error) {
        console.log("⚠️ Could not fetch crypto key information");
    }

    rl.question("\nPress Enter to return to main menu: ", () => {
        showMainMenu();
    });
}

// Check server status with crypto info
async function checkServerStatus() {
    try {
        const response = await makeRequest('GET', '/health');
        if (response.status === 200) {
            console.log("\n🖥️ Server Status:");
            console.log(`Status: ${response.data.message}`);
            console.log(`Environment: ${response.data.environment}`);
            console.log(`Uptime: ${Math.floor(response.data.messaging.uptime / 60)} minutes`);
            console.log(`Message Count: ${response.data.messaging.messageCount}`);
            console.log(`User Count: ${response.data.messaging.userCount}`);
            console.log(`Memory Usage: ${Math.round(response.data.messaging.memory.heapUsed / 1024 / 1024)} MB`);

            if (response.data.crypto) {
                console.log("\n🔐 Crypto System:");
                console.log(`Name: ${response.data.crypto.name}`);
                console.log(`Version: ${response.data.crypto.version}`);
                console.log(`Algorithms: ${response.data.crypto.algorithms.asymmetric}, ${response.data.crypto.algorithms.symmetric}`);
            }
        } else {
            console.log("❌ Server error:", response.data.error);
        }
    } catch (error) {
        console.log("❌ Cannot connect to server:", error.message);
    }

    rl.question("\nPress Enter to return to main menu: ", () => {
        showMainMenu();
    });
}

// Manage cryptographic keys
async function manageCryptoKeys() {
    try {
        console.log("\n🔐 Cryptographic Key Management:");

        // Get current keys
        const keysResponse = await makeRequest('GET', `/users/keys/${userId}`, null, {
            'Authorization': `Bearer ${authToken}`
        });

        if (keysResponse.status === 200) {
            const keys = keysResponse.data.keys;
            console.log(`Current Key Version: ${keys.publicKeys.keyVersion}`);
            console.log(`Key Fingerprint: ${keys.publicKeys.keyFingerprint || 'None'}`);
            console.log(`Last Updated: ${keys.lastUpdated || 'Unknown'}`);

            if (keys.publicKeys.keyFingerprint) {
                console.log("\nOptions:");
                console.log("1. Rotate keys (generate new key pair)");
                console.log("2. View key details");
                console.log("3. Back to main menu");

                rl.question("Choose option: ", async (choice) => {
                    switch (choice.trim()) {
                        case '1':
                            await rotateKeys();
                            break;
                        case '2':
                            showKeyDetails(keys);
                            break;
                        case '3':
                            showMainMenu();
                            break;
                        default:
                            console.log("❌ Invalid choice");
                            manageCryptoKeys();
                    }
                });
            } else {
                console.log("❌ No cryptographic keys found");
                rl.question("Press Enter to return to main menu: ", () => {
                    showMainMenu();
                });
            }
        } else {
            console.log("❌ Could not fetch key information");
            rl.question("Press Enter to return to main menu: ", () => {
                showMainMenu();
            });
        }
    } catch (error) {
        console.log("❌ Error managing keys:", error.message);
        rl.question("Press Enter to return to main menu: ", () => {
            showMainMenu();
        });
    }
}

// Rotate cryptographic keys
async function rotateKeys() {
    try {
        console.log("\n🔄 Rotating cryptographic keys...");

        const response = await makeRequest('PUT', '/users/keys', {}, {
            'Authorization': `Bearer ${authToken}`
        });

        if (response.status === 200) {
            console.log("✅ Keys rotated successfully!");
            console.log(`New Key Version: ${response.data.keys.keyVersion}`);
            console.log(`New Fingerprint: ${response.data.keys.keyFingerprint.substring(0, 16)}...`);
        } else {
            console.log("❌ Key rotation failed:", response.data.error);
        }
    } catch (error) {
        console.log("❌ Error rotating keys:", error.message);
    }

    rl.question("Press Enter to return to key management: ", () => {
        manageCryptoKeys();
    });
}

// Show key details
function showKeyDetails(keys) {
    console.log("\n🔍 Key Details:");
    console.log(`User ID: ${keys.userId}`);
    console.log(`Username: ${keys.username}`);
    console.log(`Key Version: ${keys.publicKeys.keyVersion}`);
    console.log(`Key Fingerprint: ${keys.publicKeys.keyFingerprint}`);
    console.log(`Last Updated: ${keys.lastUpdated}`);

    rl.question("Press Enter to return to key management: ", () => {
        manageCryptoKeys();
    });
}

// Start application
console.log("🔌 Connecting to Quantum Secure Messaging server...");
promptLogin();
