// --- Server Configuration ---
require('dotenv').config();

module.exports = {
    // Server configuration
    PORT: process.env.PORT || 10000,
    NODE_ENV: process.env.NODE_ENV || 'development',

    // CORS configuration
    CORS_ORIGIN: process.env.CORS_ORIGIN || '*',

    // Deployed server URL
    DEPLOYED_URL: 'https://gen-kugt.onrender.com',

    // Local development URL
    LOCAL_URL: `http://localhost:${process.env.PORT || 10000}`,

    // Get current server URL based on environment
    getServerUrl() {
        return this.NODE_ENV === 'production' ? this.DEPLOYED_URL : this.LOCAL_URL;
    },

    // API endpoints
    API_BASE: '/api',
    HEALTH_ENDPOINT: '/api/health',
    CRYPTO_ENDPOINT: '/api/crypto/info',
    MESSAGES_ENDPOINT: '/api/messages'
};
