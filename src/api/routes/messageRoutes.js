// --- Message Routes ---
const express = require('express');
const messageController = require('../controllers/messageController');

const router = express.Router();

// POST /api/messages - Send a new message
router.post('/', messageController.sendMessage);

// GET /api/messages - Get specific message
router.get('/', messageController.getMessage);

// DELETE /api/messages - Delete specific message
router.delete('/', messageController.deleteMessage);

// POST /api/messages/read - Mark message as read
router.post('/read', messageController.markMessageAsRead);

// GET /api/messages/stats - Get message statistics
router.get('/stats', messageController.getMessageStats);

module.exports = router;
