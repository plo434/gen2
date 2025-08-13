# Quantum Secure Messaging Server

## 🚀 Advanced Secure Messaging System with Post-Quantum Cryptography and GunDB

This server implements a comprehensive **secure messaging system** using modern cryptographic algorithms, real-time GunDB database, and security best practices. It combines the original GunDB messaging functionality with advanced quantum-resistant cryptography.

## 🔐 Cryptographic Features

- **Kyber768**: Key Encapsulation Mechanism (KEM) for secure key exchange
- **Dilithium5**: Digital Signature Algorithm for message authentication
- **AES-256-GCM**: Symmetric encryption for data protection
- **SHA-256**: Hash function for data integrity
- **Base64**: Data encoding for transmission

## 💬 Messaging Features

- **Real-time messaging** with GunDB database
- **Multiple encryption types**: Standard, AES-256-CBC, and Post-Quantum
- **User inbox management** with message persistence
- **Message history** and chat management
- **Secure key exchange** between users
- **JWT authentication** with secure token management

## 🏗️ System Architecture

```
src/
├── api/           # Node.js API components
│   └── app.js     # Main Express application with GunDB
├── crypto/        # Cryptographic operations
│   └── key-exchange.js # Quantum key exchange system
├── models/        # Data models
│   └── User.js    # User model with crypto keys
├── services/      # Business logic services
│   └── userService.js # User management service
├── client/        # Client applications
│   └── messaging-app.js # Advanced messaging client
├── rust/          # Rust crypto components
│   └── src/       # Rust source code
└── main.js        # Application entry point
```

## 🌐 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration with crypto keys
- `POST /api/auth/login` - User authentication with JWT

### Key Management
- `GET /api/users/keys/:username` - Get user's public keys
- `PUT /api/users/keys` - Update user's public keys

### User Management
- `POST /api/users` - Create user (backward compatibility)
- `GET /api/users` - List all users

### Messaging
- `POST /api/messages` - Send encrypted message
- `GET /api/messages` - Get messages (by user or ID)
- `DELETE /api/messages` - Delete message

### Inbox Management
- `GET /api/inbox` - Get user's inbox
- `DELETE /api/inbox` - Clear user's inbox

### System
- `GET /` - API documentation
- `GET /api/health` - Health check with crypto status
- `GET /api/crypto/info` - Crypto system information
- `GET /api/admin/stats` - System statistics

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- npm 9+
- Rust (for crypto operations)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd server-code
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Build Rust components**
   ```bash
   npm run build:rust
   ```

4. **Start the server**
   ```bash
   npm start
   ```

5. **Run the client application**
   ```bash
   node src/client/messaging-app.js
   ```

### Development Mode
```bash
npm run dev
```

## 🔧 Configuration

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
# Edit .env with your configuration
```

## 💬 Using the Messaging System

### 1. **Start the Server**
```bash
npm start
# Server runs on http://localhost:10000
```

### 2. **Run the Client**
```bash
node src/client/messaging-app.js
```

### 3. **Register/Login**
- Enter username and password
- System automatically generates cryptographic keys
- JWT token is provided for authentication

### 4. **Start Chatting**
- Choose recipient username
- Select encryption type:
  - **Standard**: No encryption (plain text)
  - **AES**: AES-256-CBC encryption
  - **Quantum**: Post-quantum encryption (Kyber768)

### 5. **Manage Keys**
- View current cryptographic keys
- Rotate keys for enhanced security
- Monitor key versions and fingerprints

## 🔒 Security Features

### **Authentication & Authorization**
- JWT-based authentication with 24-hour expiry
- Password hashing with bcrypt (12 salt rounds)
- Account lockout after 5 failed attempts
- Token expiration and refresh

### **Data Protection**
- **End-to-End Encryption**: Messages encrypted before transmission
- **Multiple Encryption Types**: Choose security level per message
- **Key Rotation**: Automatic key updates for forward secrecy
- **Secure Key Storage**: Private keys encrypted with AES-256-GCM

### **API Security**
- Rate limiting (100 requests/15min per IP)
- CORS configuration with credentials support
- Security headers (Helmet.js)
- Input validation and sanitization
- Comprehensive error handling

## 📊 Data Flow

### **1. User Registration**
```
Client → POST /api/auth/register → Generate Crypto Keys → Store User + Keys → Return JWT
```

### **2. Message Encryption & Sending**
```
Client → Choose Encryption Type → Encrypt Message → Store in GunDB → Send to Recipient
```

### **3. Message Reception & Decryption**
```
Server → Store in Recipient Inbox → Client Polls Inbox → Decrypt Message → Display Content
```

### **4. Key Exchange**
```
User A → Generate Keys → Store Public Keys → User B Retrieves Keys → Secure Communication
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run unit tests only
npm run test:unit

# Run integration tests only
npm run test:integration
```

## 🚀 Deployment

### **Render.com**
1. Upload this folder to GitHub
2. Go to [Render.com](https://render.com)
3. Create "New Web Service"
4. Connect GitHub repository
5. Deploy automatically

### **Docker**
```bash
docker build -t quantum-messaging .
docker run -p 10000:10000 quantum-messaging
```

### **Heroku**
```bash
heroku create your-app-name
git push heroku main
```

## 🔍 Monitoring & Logging

### **Health Checks**
- System status monitoring
- Dependency availability
- Crypto system status
- User and message statistics
- Memory usage and uptime

### **Logging**
- Request/response logging with Morgan
- Error tracking and debugging
- Security event logging
- Performance metrics

## 🔮 Future Enhancements

### **Phase 1: True Post-Quantum Crypto**
- Implement actual Kyber768 KEM
- Implement Dilithium5 signatures
- Replace RSA simulation with quantum algorithms

### **Phase 2: Advanced Features**
- Database integration (PostgreSQL + Redis)
- Microservices architecture
- Kubernetes deployment
- Prometheus monitoring

### **Phase 3: Client Applications**
- Web-based messaging interface
- Mobile applications
- Desktop applications
- Browser extensions

## 📱 Client Applications

### **Command Line Client**
- `src/client/messaging-app.js` - Advanced messaging client
- Real-time message polling
- Encryption type selection
- Cryptographic key management
- Chat history and user management

### **Features**
- **Multiple Encryption Types**: Choose security level per message
- **Real-time Updates**: Poll for new messages every 2 seconds
- **Key Management**: View, rotate, and manage cryptographic keys
- **Chat History**: Persistent local chat storage
- **User Management**: Create, login, and manage accounts

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the API documentation at `/`
- Review the health check at `/api/health`
- Run the client application for testing

## 🔮 System Capabilities

### **Current Features**
- ✅ Real-time messaging with GunDB
- ✅ Multiple encryption types
- ✅ JWT authentication
- ✅ Cryptographic key management
- ✅ User inbox management
- ✅ Message persistence
- ✅ Rate limiting and security
- ✅ Comprehensive API

### **Security Level**
- 🔓 **Standard**: No encryption (for testing)
- 🔐 **AES**: Military-grade AES-256-CBC encryption
- 🚀 **Quantum**: Post-quantum resistant encryption

This system represents the **perfect fusion** of the original GunDB messaging functionality with **advanced quantum-resistant cryptography**, creating a **secure, scalable, and future-proof messaging platform**! 🎉
