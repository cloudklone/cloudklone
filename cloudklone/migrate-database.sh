#!/bin/bash

# CloudKlone Database Migration Script
# Migrates from old naming (rclone_gui/rclone_admin) to new naming (cloudklone/cloudklone_user)

set -e

echo "🔄 CloudKlone Database Migration"
echo "================================"
echo ""
echo "This script will:"
echo "1. Check for existing database with old names"
echo "2. Rename database from 'rclone_gui' to 'cloudklone'"
echo "3. Rename user from 'rclone_admin' to 'cloudklone_user'"
echo ""

# Check if container is running
if ! docker ps | grep -q cloudklone-database; then
    echo "❌ Error: cloudklone-database container is not running"
    echo "Please start CloudKlone first: sudo docker-compose up -d"
    exit 1
fi

echo "Checking current database configuration..."
echo ""

# Check if old database exists
OLD_DB_EXISTS=$(docker exec cloudklone-database psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='rclone_gui'" 2>/dev/null || echo "")

if [ "$OLD_DB_EXISTS" == "1" ]; then
    echo "✅ Found existing database 'rclone_gui'"
    echo ""
    read -p "Migrate to new naming (rclone_gui → cloudklone)? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Migration cancelled"
        exit 0
    fi
    
    echo ""
    echo "🔄 Starting migration..."
    echo ""
    
    # Disconnect all sessions from old database
    echo "1. Disconnecting active sessions..."
    docker exec cloudklone-database psql -U postgres << 'EOF'
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'rclone_gui' AND pid <> pg_backend_pid();
EOF
    
    # Rename database
    echo "2. Renaming database: rclone_gui → cloudklone..."
    docker exec cloudklone-database psql -U postgres -c "ALTER DATABASE rclone_gui RENAME TO cloudklone;"
    
    # Check if old user exists and rename
    OLD_USER_EXISTS=$(docker exec cloudklone-database psql -U postgres -tAc "SELECT 1 FROM pg_user WHERE usename='rclone_admin'" 2>/dev/null || echo "")
    
    if [ "$OLD_USER_EXISTS" == "1" ]; then
        echo "3. Renaming user: rclone_admin → cloudklone_user..."
        docker exec cloudklone-database psql -U postgres -c "ALTER USER rclone_admin RENAME TO cloudklone_user;"
    else
        echo "3. User 'rclone_admin' not found, skipping..."
    fi
    
    # Update ownership
    echo "4. Updating database ownership..."
    docker exec cloudklone-database psql -U postgres << 'EOF'
ALTER DATABASE cloudklone OWNER TO cloudklone_user;
\c cloudklone
ALTER SCHEMA public OWNER TO cloudklone_user;
GRANT ALL PRIVILEGES ON DATABASE cloudklone TO cloudklone_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cloudklone_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cloudklone_user;
EOF
    
    echo ""
    echo "✅ Migration complete!"
    echo ""
    echo "📝 Changes made:"
    echo "  • Database: rclone_gui → cloudklone"
    echo "  • User: rclone_admin → cloudklone_user"
    echo ""
    echo "🔄 Next steps:"
    echo "1. Stop CloudKlone: sudo docker-compose down"
    echo "2. Update .env file (if you have one) with new DATABASE_URL"
    echo "3. Start CloudKlone: sudo docker-compose up -d"
    echo ""
    
else
    echo "ℹ️  No existing 'rclone_gui' database found."
    echo ""
    echo "This is normal for:"
    echo "  • Fresh installations"
    echo "  • Already migrated systems"
    echo ""
    echo "New CloudKlone deployments will use the new naming automatically."
    echo ""
fi

# Verify new configuration
NEW_DB_EXISTS=$(docker exec cloudklone-database psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='cloudklone'" 2>/dev/null || echo "")

if [ "$NEW_DB_EXISTS" == "1" ]; then
    echo "✅ Verified: Database 'cloudklone' exists"
else
    echo "ℹ️  Database 'cloudklone' will be created on next deployment"
fi

echo ""
echo "🎉 Migration check complete!"
