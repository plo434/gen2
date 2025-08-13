#!/bin/bash

# 🚀 Advanced GunDB Messaging Server Start Script
# Simple script to start the server

echo "🚀 Starting Advanced GunDB Messaging Server..."
echo "==============================================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 16+ first."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js version 16+ is required. Current version: $(node -v)"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo "❌ package.json not found!"
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "🔧 Creating .env file from template..."
    cp env.example .env
    echo "⚠️  Please edit .env file with your configuration!"
    echo "   - Change JWT_SECRET to a secure random string"
    echo "   - Change PORT if needed (default: 8080)"
    read -p "Press Enter to continue after editing .env file..."
fi

# Create logs directory
mkdir -p logs

# Start the server
echo "🚀 Starting server..."
echo "📡 Server will be available at: http://localhost:8080"
echo "🔍 Health check: http://localhost:8080/api/health"
echo "📖 API docs: http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the server
node advanced-simple-server.js
