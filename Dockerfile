# Use official Rust image for building
FROM rust:1.70 as rust-builder
WORKDIR /app
COPY src/rust/ ./src/rust/
WORKDIR /app/src/rust
RUN cargo build --release

# Use Node.js image for runtime
FROM node:18-alpine
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY Cargo.toml ./

# Install dependencies
RUN npm ci --only=production

# Copy Rust binary
COPY --from=rust-builder /app/src/rust/target/release/crypto_api ./src/rust/target/release/

# Copy source code
COPY src/ ./src/
COPY demo.js ./

# Create keys directory
RUN mkdir -p src/keys

# Expose port
EXPOSE 10000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:10000/api/health || exit 1

# Start the application
CMD ["npm", "start"]
