@echo off
chcp 65001 >nul
echo 🚀 Starting Advanced GunDB Messaging Server...
echo ================================================

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js 16+ first.
    echo Download from: https://nodejs.org/
    pause
    exit /b 1
)

REM Check Node.js version
for /f "tokens=1,2 delims=." %%a in ('node --version') do (
    set NODE_VERSION=%%a
    set NODE_VERSION=!NODE_VERSION:~1!
)

if !NODE_VERSION! lss 16 (
    echo ❌ Node.js version 16+ is required. Current version: 
    node --version
    pause
    exit /b 1
)

echo ✅ Node.js version: 
node --version

REM Check if package.json exists
if not exist "package.json" (
    echo ❌ package.json not found!
    pause
    exit /b 1
)

REM Install dependencies if node_modules doesn't exist
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    npm install
)

REM Create .env file if it doesn't exist
if not exist ".env" (
    echo 🔧 Creating .env file from template...
    copy env.example .env >nul
    echo ⚠️  Please edit .env file with your configuration!
    echo    - Change JWT_SECRET to a secure random string
    echo    - Change PORT if needed (default: 8080)
    echo.
    echo Press any key to continue after editing .env file...
    pause >nul
)

REM Create logs directory
if not exist "logs" mkdir logs

REM Start the server
echo 🚀 Starting server...
echo 📡 Server will be available at: http://localhost:8080
echo 🔍 Health check: http://localhost:8080/api/health
echo 📖 API docs: http://localhost:8080
echo.
echo Press Ctrl+C to stop the server
echo.

REM Start the server
node advanced-simple-server.js

pause
