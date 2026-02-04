#!/bin/bash
set -e

# CloudKlone Deployment Script
# This script handles upgrades while preserving your encryption keys and data

INSTALL_DIR="$HOME/cloudklone"
BACKUP_DIR="$HOME/cloudklone-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=========================================="
echo "CloudKlone Deployment Script"
echo "=========================================="
echo ""

# Function to generate random key
generate_key() {
    openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64
}

# Function to backup env file
backup_env() {
    if [ -f "$INSTALL_DIR/.env" ]; then
        mkdir -p "$BACKUP_DIR"
        cp "$INSTALL_DIR/.env" "$BACKUP_DIR/.env.$TIMESTAMP"
        echo "✓ Backed up .env to $BACKUP_DIR/.env.$TIMESTAMP"
        return 0
    fi
    return 1
}

# Function to restore or create env file
setup_env() {
    if [ -f "$INSTALL_DIR/.env.backup" ]; then
        echo "✓ Found existing .env.backup, restoring..."
        cp "$INSTALL_DIR/.env.backup" "$INSTALL_DIR/.env"
        return 0
    elif [ -f "$BACKUP_DIR/.env.$TIMESTAMP" ]; then
        echo "✓ Restoring .env from backup..."
        cp "$BACKUP_DIR/.env.$TIMESTAMP" "$INSTALL_DIR/.env"
        return 0
    else
        echo "⚠ No existing .env found, creating new one..."
        echo "🔑 Generating secure encryption keys..."
        
        ENCRYPTION_KEY=$(generate_key)
        JWT_SECRET=$(generate_key)
        
        cat > "$INSTALL_DIR/.env" << EOF
# CloudKlone Configuration
# Generated: $(date)
# DO NOT CHANGE ENCRYPTION_KEY AFTER REMOTES ARE ADDED!

# Encryption key for remote credentials (KEEP THIS SAFE!)
ENCRYPTION_KEY=$ENCRYPTION_KEY

# JWT secret for user sessions
JWT_SECRET=$JWT_SECRET

# Database connection (auto-configured by docker-compose)
DATABASE_URL=postgresql://cloudklone_user:changeme123@postgres:5432/cloudklone

# Server port
PORT=3001

# Node environment
NODE_ENV=production
EOF
        echo "✓ Created new .env file"
        echo ""
        echo "⚠️  IMPORTANT: Your encryption keys are in .env"
        echo "⚠️  Backup this file! If lost, you'll need to re-add all remotes."
        return 0
    fi
}

# Check if this is an upgrade or fresh install
if [ -d "$INSTALL_DIR" ]; then
    echo "📦 Existing installation detected"
    echo ""
    
    # Ask user what they want to do
    echo "Choose deployment type:"
    echo "1) Upgrade (keeps data, remotes, users)"
    echo "2) Fresh install (deletes everything)"
    read -p "Enter choice [1]: " DEPLOY_TYPE
    DEPLOY_TYPE=${DEPLOY_TYPE:-1}
    
    if [ "$DEPLOY_TYPE" = "2" ]; then
        echo ""
        echo "⚠️  WARNING: This will DELETE all data!"
        read -p "Are you sure? Type 'yes' to confirm: " CONFIRM
        if [ "$CONFIRM" != "yes" ]; then
            echo "Aborted."
            exit 0
        fi
        
        echo "🗑️  Stopping containers and removing volumes..."
        cd "$INSTALL_DIR"
        docker-compose down -v
        
        cd "$HOME"
        rm -rf "$INSTALL_DIR"
        echo "✓ Removed old installation"
    else
        # Upgrade path
        echo "📥 Starting upgrade..."
        
        # Backup env file
        backup_env
        
        # Copy env to temporary location
        if [ -f "$INSTALL_DIR/.env" ]; then
            cp "$INSTALL_DIR/.env" "$INSTALL_DIR/.env.backup"
        fi
        
        # Stop containers but keep volumes
        echo "🛑 Stopping containers..."
        cd "$INSTALL_DIR"
        docker-compose down
        
        # Move old installation
        cd "$HOME"
        if [ -d "$INSTALL_DIR.old" ]; then
            rm -rf "$INSTALL_DIR.old"
        fi
        mv "$INSTALL_DIR" "$INSTALL_DIR.old"
        echo "✓ Moved old installation to cloudklone.old"
    fi
else
    echo "📦 Fresh installation"
fi

# Extract new version
echo ""
echo "📦 Extracting CloudKlone..."
if [ -f "$HOME/cloudklone-v4-final.tar.gz" ]; then
    cd "$HOME"
    tar -xzf cloudklone-v4-final.tar.gz
    echo "✓ Extracted new version"
else
    echo "❌ Error: cloudklone-v4-final.tar.gz not found in $HOME"
    echo "Please download it first."
    exit 1
fi

# Setup or restore env file
cd "$INSTALL_DIR"
setup_env

# Run database migrations if upgrading
if [ -d "$INSTALL_DIR.old" ]; then
    echo ""
    echo "🔧 Running database migrations..."
    
    # Start postgres only
    docker-compose up -d postgres
    sleep 5
    
    # Temporarily disable errexit to handle migration errors gracefully
    set +e
    
    # Run migrations
    docker-compose exec -T postgres psql -U cloudklone_user cloudklone << 'EOSQL'
-- Add scheduling columns
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS schedule_type VARCHAR(20);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS schedule_interval VARCHAR(50);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS last_run TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS next_run TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;

-- Add encryption and groups columns
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS encrypted_config TEXT;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS group_id INTEGER;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS is_shared BOOLEAN DEFAULT false;

-- Create groups table if missing
CREATE TABLE IF NOT EXISTS groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add user management columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user';
ALTER TABLE users ADD COLUMN IF NOT EXISTS group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMP;

\echo '✓ Database migrations complete'
EOSQL
    
    MIGRATION_EXIT_CODE=$?
    
    # Re-enable errexit
    set -e
    
    if [ $MIGRATION_EXIT_CODE -eq 0 ]; then
        echo "✓ Database migrations successful"
    else
        echo "⚠️  Database migrations had errors (may be OK if columns already exist)"
    fi
fi

# Start all services
echo ""
echo "🚀 Starting CloudKlone..."
docker-compose up -d --build

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo ""
    echo "=========================================="
    echo "✅ CloudKlone deployed successfully!"
    echo "=========================================="
    echo ""
    echo "🌐 Access at: http://localhost"
    echo "👤 Default login: admin / admin"
    echo ""
    echo "📁 Installation directory: $INSTALL_DIR"
    echo "🔑 Encryption keys: $INSTALL_DIR/.env"
    echo "📦 Backups: $BACKUP_DIR"
    echo ""
    echo "📝 View logs: cd $INSTALL_DIR && docker-compose logs -f"
    echo ""
    
    if [ -f "$INSTALL_DIR/.env.backup" ]; then
        echo "⚠️  Your encryption keys were preserved from previous install"
        echo "⚠️  All your remotes should still work"
        rm "$INSTALL_DIR/.env.backup"
    else
        echo "⚠️  NEW ENCRYPTION KEYS generated"
        echo "⚠️  You'll need to re-add all remotes"
    fi
    echo ""
else
    echo ""
    echo "❌ Deployment may have failed"
    echo "Check logs: cd $INSTALL_DIR && docker-compose logs"
fi
