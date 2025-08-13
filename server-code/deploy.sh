#!/bin/bash

# 🚀 Advanced GunDB Messaging Server Deployment Script
# This script helps you deploy the server to your server

echo "🚀 Starting deployment of Advanced GunDB Messaging Server..."

# Configuration
SERVER_HOST="your-server-ip"
SERVER_USER="your-username"
SERVER_PATH="/var/www/messaging-server"
LOCAL_FILES=(
    "advanced-simple-server.js"
    "package-simple.json"
    "README-SIMPLE.md"
    "env.example"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required files exist
print_status "Checking local files..."
for file in "${LOCAL_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        print_error "File $file not found!"
        exit 1
    fi
done
print_status "All local files found ✓"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    print_warning ".env file not found, creating from template..."
    cp env.example .env
    print_warning "Please edit .env file with your configuration before deploying!"
    read -p "Press Enter to continue after editing .env file..."
fi

# Upload files to server
print_status "Uploading files to server..."
for file in "${LOCAL_FILES[@]}"; do
    print_status "Uploading $file..."
    scp "$file" "$SERVER_USER@$SERVER_HOST:$SERVER_PATH/"
    if [ $? -eq 0 ]; then
        print_status "$file uploaded successfully ✓"
    else
        print_error "Failed to upload $file"
        exit 1
    fi
done

# Copy .env file
print_status "Uploading .env file..."
scp .env "$SERVER_USER@$SERVER_HOST:$SERVER_PATH/"
if [ $? -eq 0 ]; then
    print_status ".env file uploaded successfully ✓"
else
    print_error "Failed to upload .env file"
    exit 1
fi

# Execute remote commands
print_status "Executing remote setup commands..."
ssh "$SERVER_USER@$SERVER_HOST" << 'EOF'
    cd /var/www/messaging-server
    
    # Install dependencies
    print_status "Installing dependencies..."
    npm install --production
    
    # Set proper permissions
    print_status "Setting permissions..."
    chmod +x advanced-simple-server.js
    
    # Create logs directory
    print_status "Creating logs directory..."
    mkdir -p logs
    
    # Check if PM2 is installed
    if command -v pm2 &> /dev/null; then
        print_status "PM2 found, setting up PM2 process..."
        pm2 delete messaging-server 2>/dev/null || true
        pm2 start advanced-simple-server.js --name "messaging-server"
        pm2 save
        pm2 startup
        print_status "PM2 process started ✓"
    else
        print_warning "PM2 not found. You can install it with: npm install -g pm2"
        print_status "Starting server directly..."
        nohup node advanced-simple-server.js > logs/server.log 2>&1 &
        echo $! > server.pid
        print_status "Server started with PID: $(cat server.pid) ✓"
    fi
    
    # Check server status
    print_status "Checking server status..."
    sleep 3
    if curl -s http://localhost:8080/api/health > /dev/null; then
        print_status "Server is running and responding ✓"
    else
        print_error "Server is not responding!"
        exit 1
    fi
EOF

if [ $? -eq 0 ]; then
    print_status "Deployment completed successfully! 🎉"
    print_status "Your server is now running at: http://$SERVER_HOST:8080"
    print_status "Health check: http://$SERVER_HOST:8080/api/health"
else
    print_error "Deployment failed!"
    exit 1
fi

# Optional: Setup Nginx reverse proxy
read -p "Do you want to setup Nginx reverse proxy? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Setting up Nginx reverse proxy..."
    
    # Create Nginx configuration
    cat > nginx-messaging.conf << EOF
server {
    listen 80;
    server_name your-domain.com;  # Change this to your domain
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
    
    # Upload Nginx config
    scp nginx-messaging.conf "$SERVER_USER@$SERVER_HOST:/tmp/"
    
    # Setup Nginx on server
    ssh "$SERVER_USER@$SERVER_HOST" << 'EOF'
        sudo cp /tmp/nginx-messaging.conf /etc/nginx/sites-available/messaging-server
        sudo ln -sf /etc/nginx/sites-available/messaging-server /etc/nginx/sites-enabled/
        sudo nginx -t
        if [ $? -eq 0 ]; then
            sudo systemctl reload nginx
            print_status "Nginx configured successfully ✓"
        else
            print_error "Nginx configuration failed!"
        fi
EOF
    
    # Clean up local file
    rm nginx-messaging.conf
fi

print_status "Deployment script completed! 🚀"
print_status "Your Advanced GunDB Messaging Server is now live!"
