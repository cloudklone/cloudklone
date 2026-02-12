FROM node:18-alpine

# Install system dependencies
RUN apk add --no-cache \
    rclone \
    openssh-client \
    openssl \
    curl \
    bash \
    ca-certificates

# Set working directory
WORKDIR /app

# Copy package files
COPY backend/package*.json ./

# Install Node.js dependencies
RUN npm install --omit=dev --quiet

# Copy application files
COPY backend/ ./

# Expose ports
EXPOSE 3001 3443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/api/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start application
CMD ["node", "index.js"]
