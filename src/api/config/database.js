// --- Database Configuration ---
const Gun = require('gun');

class DatabaseConfig {
    constructor() {
        this.gun = null;
        this.messageStore = new Map();
        this.userInboxes = new Map();
    }

    // Initialize GunDB
    initializeGunDB(server) {
        const GUN_OPTIONS = {
            web: server,
            radisk: false,
            localStorage: false
        };

        this.gun = Gun(GUN_OPTIONS);
        console.log('GunDB initialized successfully');
        return this.gun;
    }

    // Get GunDB instance
    getGunDB() {
        return this.gun;
    }

    // Get in-memory message store
    getMessageStore() {
        return this.messageStore;
    }

    // Get in-memory user inboxes
    getUserInboxes() {
        return this.userInboxes;
    }

    // Store message in both memory and GunDB
    storeMessage(messageId, message) {
        // Store in memory
        this.messageStore.set(messageId, message);

        // Store in GunDB
        if (this.gun) {
            this.gun.get('messages').get(messageId).put(message);
            this.gun.get('inbox').get(message.to).set(message);
        }
    }

    // Get message from memory
    getMessage(messageId) {
        return this.messageStore.get(messageId);
    }

    // Delete message from both memory and GunDB
    deleteMessage(messageId) {
        this.messageStore.delete(messageId);

        if (this.gun) {
            this.gun.get('messages').get(messageId).put(null);
        }
    }
}

module.exports = new DatabaseConfig();
