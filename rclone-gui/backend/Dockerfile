FROM node:18-alpine

# Install rclone
RUN apk add --no-cache rclone

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application code
COPY . .

# Create cache directory
RUN mkdir -p /app/cache

# Expose port
EXPOSE 3001

# Start application
CMD ["npm", "start"]
