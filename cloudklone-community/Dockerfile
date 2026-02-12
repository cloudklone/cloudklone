FROM node:18-alpine

# Install system dependencies
RUN apk add --no-cache \
    rclone \
    openssh-client \
    openssl \
    curl \
    bash \
    ca-certificates

# Install Ollama
# Note: Ollama for Alpine Linux requires manual installation
RUN wget https://ollama.ai/download/ollama-linux-amd64 -O /usr/local/bin/ollama && \
    chmod +x /usr/local/bin/ollama

# Create directory for Ollama models
RUN mkdir -p /root/.ollama

# Set working directory
WORKDIR /app

# Copy package files
COPY backend/package*.json ./

# Install Node.js dependencies
RUN npm install --omit=dev --quiet

# Copy application files
COPY backend/ ./

# Expose ports
EXPOSE 3001 3443 11434

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/api/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start script that runs both Ollama and the app
CMD ["sh", "-c", "ollama serve & sleep 5 && node index.js"]
