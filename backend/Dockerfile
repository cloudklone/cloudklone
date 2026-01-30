FROM node:18-alpine

# Install rclone
RUN apk add --no-cache curl && \
    curl https://rclone.org/install.sh | sh && \
    apk del curl

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Create cache directory
RUN mkdir -p /app/cache

# Expose port
EXPOSE 3001

# Start application
CMD ["npm", "start"]
