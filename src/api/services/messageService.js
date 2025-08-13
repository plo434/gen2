// --- Message Service ---
const Message = require('../models/Message');
const database = require('../config/database');

class MessageService {
    constructor() {
        this.messageStore = database.getMessageStore();
        this.userInboxes = database.getUserInboxes();
    }

    // Send a new message
    async sendMessage(messageData) {
        try {
            // Create message instance
            const message = Message.fromData(messageData);

            // Validate message
            message.validate();

            // Store message in database
            database.storeMessage(message.id, message);

            // Add to recipient's inbox
            if (!this.userInboxes.has(message.to)) {
                this.userInboxes.set(message.to, new Map());
            }
            this.userInboxes.get(message.to).set(message.id, message);

            console.log(`Message sent from ${message.from} to ${message.to}`);
            return message;

        } catch (error) {
            console.error('Error sending message:', error);
            throw error;
        }
    }

    // Get user's inbox
    async getUserInbox(userId) {
        try {
            const inbox = this.userInboxes.get(userId);
            if (!inbox) {
                return [];
            }

            const messages = Array.from(inbox.values());
            return messages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        } catch (error) {
            console.error('Error getting user inbox:', error);
            throw error;
        }
    }

    // Get specific message
    async getMessage(messageId) {
        try {
            const message = this.messageStore.get(messageId);
            if (!message) {
                throw new Error('Message not found');
            }
            return message;

        } catch (error) {
            console.error('Error getting message:', error);
            throw error;
        }
    }

    // Mark message as read
    async markMessageAsRead(messageId, userId) {
        try {
            const message = await this.getMessage(messageId);

            // Verify user owns the message
            if (message.to !== userId) {
                throw new Error('Unauthorized to read this message');
            }

            message.markAsRead();

            // Update in database
            database.storeMessage(messageId, message);

            return message;

        } catch (error) {
            console.error('Error marking message as read:', error);
            throw error;
        }
    }

    // Delete message
    async deleteMessage(messageId, userId) {
        try {
            const message = await this.getMessage(messageId);

            // Verify user owns the message
            if (message.to !== userId && message.from !== userId) {
                throw new Error('Unauthorized to delete this message');
            }

            // Remove from inbox
            const inbox = this.userInboxes.get(message.to);
            if (inbox) {
                inbox.delete(messageId);
            }

            // Remove from database
            database.deleteMessage(messageId);

            console.log(`Message ${messageId} deleted by user ${userId}`);
            return true;

        } catch (error) {
            console.error('Error deleting message:', error);
            throw error;
        }
    }

    // Clear user's inbox
    async clearUserInbox(userId) {
        try {
            const inbox = this.userInboxes.get(userId);
            if (!inbox) {
                return 0;
            }

            const messageCount = inbox.size;

            // Delete all messages from database
            for (const messageId of inbox.keys()) {
                database.deleteMessage(messageId);
            }

            // Clear inbox
            this.userInboxes.delete(userId);

            console.log(`Inbox cleared for user ${userId}, ${messageCount} messages deleted`);
            return messageCount;

        } catch (error) {
            console.error('Error clearing user inbox:', error);
            throw error;
        }
    }

    // Get message statistics
    async getMessageStats() {
        try {
            const totalMessages = this.messageStore.size;
            const totalUsers = this.userInboxes.size;

            let totalUnread = 0;
            for (const inbox of this.userInboxes.values()) {
                for (const message of inbox.values()) {
                    if (!message.read) totalUnread++;
                }
            }

            return {
                totalMessages,
                totalUsers,
                totalUnread,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error('Error getting message stats:', error);
            throw error;
        }
    }
}

module.exports = new MessageService();
