// --- Message Model ---
const crypto = require('crypto');

class Message {
    constructor(data) {
        this.id = data.id || this.generateId();
        this.from = data.from;
        this.to = data.to;
        this.content = data.content;
        this.timestamp = data.timestamp || new Date().toISOString();
        this.encrypted = data.encrypted || false;
        this.signature = data.signature || null;
        this.read = data.read || false;
    }

    // Generate unique message ID
    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }

    // Validate message data
    validate() {
        if (!this.from || !this.to || !this.content) {
            throw new Error('Missing required fields: from, to, content');
        }

        if (this.from === this.to) {
            throw new Error('Sender and recipient cannot be the same');
        }

        return true;
    }

    // Mark message as read
    markAsRead() {
        this.read = true;
        this.readAt = new Date().toISOString();
    }

    // Get message summary
    getSummary() {
        return {
            id: this.id,
            from: this.from,
            to: this.to,
            timestamp: this.timestamp,
            encrypted: this.encrypted,
            read: this.read
        };
    }

    // Convert to plain object
    toJSON() {
        return {
            id: this.id,
            from: this.from,
            to: this.to,
            content: this.content,
            timestamp: this.timestamp,
            encrypted: this.encrypted,
            signature: this.signature,
            read: this.read,
            readAt: this.readAt
        };
    }

    // Create message from data
    static fromData(data) {
        return new Message(data);
    }
}

module.exports = Message;
