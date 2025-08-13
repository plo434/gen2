// --- Message Controller ---
const messageService = require('../services/messageService');

class MessageController {
    // Send message
    async sendMessage(req, res) {
        try {
            const { from, to, content, encrypted = false, signature = null } = req.body;

            if (!from || !to || !content) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required fields: from, to, content'
                });
            }

            const messageData = {
                from,
                to,
                content,
                encrypted,
                signature
            };

            const message = await messageService.sendMessage(messageData);

            res.status(201).json({
                success: true,
                message: 'Message sent successfully',
                data: message
            });

        } catch (error) {
            console.error('Error in sendMessage controller:', error);
            res.status(500).json({
                success: false,
                error: error.message || 'Internal server error'
            });
        }
    }

    // Get user inbox
    async getUserInbox(req, res) {
        try {
            const { userId } = req.query;

            if (!userId) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required parameter: userId'
                });
            }

            const inbox = await messageService.getUserInbox(userId);

            res.status(200).json({
                success: true,
                message: 'Inbox retrieved successfully',
                data: {
                    userId,
                    messageCount: inbox.length,
                    messages: inbox
                }
            });

        } catch (error) {
            console.error('Error in getUserInbox controller:', error);
            res.status(500).json({
                success: false,
                error: error.message || 'Internal server error'
            });
        }
    }

    // Get specific message
    async getMessage(req, res) {
        try {
            const { messageId } = req.query;

            if (!messageId) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required parameter: messageId'
                });
            }

            const message = await messageService.getMessage(messageId);

            res.status(200).json({
                success: true,
                message: 'Message retrieved successfully',
                data: message
            });

        } catch (error) {
            console.error('Error in getMessage controller:', error);

            if (error.message === 'Message not found') {
                return res.status(404).json({
                    success: false,
                    error: 'Message not found'
                });
            }

            res.status(500).json({
                success: false,
                error: error.message || 'Internal server error'
            });
        }
    }

    // Mark message as read
    async markMessageAsRead(req, res) {
        try {
            const { messageId, userId } = req.body;

            if (!messageId || !userId) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required fields: messageId, userId'
                });
            }

            const message = await messageService.markMessageAsRead(messageId, userId);

            res.status(200).json({
                success: true,
                message: 'Message marked as read',
                data: message
            });

        } catch (error) {
            console.error('Error in markMessageAsRead controller:', error);

            if (error.message === 'Message not found') {
                return res.status(404).json({
                    success: false,
                    error: 'Message not found'
                });
            }

            if (error.message === 'Unauthorized to read this message') {
                return res.status(403).json({
                    success: false,
                    error: 'Unauthorized to read this message'
                });
            }

            res.status(500).json({
                success: false,
                error: error.message || 'Internal server error'
            });
        }
    }

    // Delete message
    async deleteMessage(req, res) {
        try {
            const { messageId, userId } = req.query;

            if (!messageId || !userId) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required parameters: messageId, userId'
                });
            }

            await messageService.deleteMessage(messageId, userId);

            res.status(200).json({
                success: true,
                message: 'Message deleted successfully'
            });

        } catch (error) {
            console.error('Error in deleteMessage controller:', error);

            if (error.message === 'Message not found') {
                return res.status(404).json({
                    success: false,
                    error: 'Message not found'
                });
            }

            if (error.message === 'Unauthorized to delete this message') {
                return res.status(403).json({
                    success: false,
                    error: 'Unauthorized to delete this message'
                });
            }

            res.status(500).json({
                success: false,
                error: error.message || 'Internal server error'
            });
        }
    }

    // Clear user inbox
    async clearUserInbox(req, res) {
        try {
            const { userId } = req.query;

            if (!userId) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required parameter: userId'
                });
            }

            const deletedCount = await messageService.clearUserInbox(userId);

            res.status(200).json({
                success: true,
                message: 'Inbox cleared successfully',
                data: {
                    userId,
                    deletedCount
                }
            });

        } catch (error) {
            console.error('Error in clearUserInbox controller:', error);
            res.status(500).json({
                success: false,
                error: error.message || 'Internal server error'
            });
        }
    }

    // Get message statistics
    async getMessageStats(req, res) {
        try {
            const stats = await messageService.getMessageStats();

            res.status(200).json({
                success: true,
                message: 'Message statistics retrieved successfully',
                data: stats
            });

        } catch (error) {
            console.error('Error in getMessageStats controller:', error);
            res.status(500).json({
                success: false,
                error: error.message || 'Internal server error'
            });
        }
    }
}

module.exports = new MessageController();
