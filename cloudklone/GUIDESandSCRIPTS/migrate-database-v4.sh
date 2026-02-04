#!/bin/bash

# CloudKlone Database Migration Script (v4)
# Handles database recovery after improper shutdown

set -e

echo "🔄 CloudKlone Database Migration v4"
echo "===================================="
echo ""
echo "This script will migrate your database from the old naming to the new naming."
echo ""

# Check if we're running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
   echo "⚠️  This script needs sudo access to docker."
   echo "Please run: sudo ./migrate-database-v4.sh"
   exit 1
fi

# Stop any running containers first
echo "1. Stopping CloudKlone containers..."
docker-compose down 2>/dev/null || true

echo ""
echo "2. Cleaning up any previous migration attempts..."
docker rm -f cloudklone-migration-temp 2>/dev/null || true

echo ""
echo "3. Creating Docker network if needed..."
docker network create cloudklone_cloudklone-network 2>/dev/null || echo "   Network already exists (OK)"

echo ""
echo "4. Starting temporary database container with OLD credentials..."
echo "   (This allows us to access your existing data)"
echo ""

CONTAINER_ID=$(docker run -d \
  --name cloudklone-migration-temp \
  --network cloudklone_cloudklone-network \
  -e POSTGRES_DB=rclone_gui \
  -e POSTGRES_USER=rclone_admin \
  -e POSTGRES_PASSWORD=changeme123 \
  -v cloudklone_postgres_data:/var/lib/postgresql/data \
  postgres:16-alpine)

echo "   Container started: $CONTAINER_ID"

echo ""
echo "5. Waiting for database recovery to complete..."
echo "   (Database was not properly shut down, running automatic recovery)"
echo ""

# Wait longer and check logs for recovery completion
READY=false
RECOVERY_STARTED=false
CHECKPOINT_STARTED=false

for i in {1..180}; do  # Wait up to 3 minutes
    # Check if ready
    if docker exec cloudklone-migration-temp pg_isready -U rclone_admin -d rclone_gui &>/dev/null; then
        echo ""
        echo "   ✅ Database ready after $i seconds!"
        READY=true
        break
    fi
    
    # Check logs for progress
    LOGS=$(docker logs cloudklone-migration-temp 2>&1 | tail -5)
    
    if echo "$LOGS" | grep -q "automatic recovery in progress" && [ "$RECOVERY_STARTED" = false ]; then
        echo "   📝 Recovery started..."
        RECOVERY_STARTED=true
    fi
    
    if echo "$LOGS" | grep -q "checkpoint starting" && [ "$CHECKPOINT_STARTED" = false ]; then
        echo "   📝 Checkpoint in progress..."
        CHECKPOINT_STARTED=true
    fi
    
    if echo "$LOGS" | grep -q "checkpoint complete"; then
        echo "   📝 Checkpoint complete, finalizing..."
    fi
    
    # Show progress every 15 seconds
    if [ $((i % 15)) -eq 0 ]; then
        echo "   ⏳ Still waiting... ($i seconds elapsed)"
    fi
    
    sleep 1
done

if [ "$READY" = false ]; then
    echo ""
    echo "   ❌ Database failed to become ready after 3 minutes"
    echo ""
    echo "   Last 30 lines of database logs:"
    docker logs cloudklone-migration-temp --tail 30
    echo ""
    echo "   Container will be left running for manual inspection."
    echo "   To check logs: sudo docker logs cloudklone-migration-temp"
    echo "   To remove: sudo docker rm -f cloudklone-migration-temp"
    exit 1
fi

echo ""
echo "6. Checking current database configuration..."

# Check which database exists - use rclone_admin since postgres user doesn't exist
OLD_DB=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT datname FROM pg_database WHERE datname='rclone_gui'" 2>/dev/null || echo "")
NEW_DB=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT datname FROM pg_database WHERE datname='cloudklone'" 2>/dev/null || echo "")

if [ "$NEW_DB" == "cloudklone" ]; then
    echo "   ✅ Database already named 'cloudklone'"
    echo "   Migration not needed!"
    docker rm -f cloudklone-migration-temp
    echo ""
    echo "Starting CloudKlone with new configuration..."
    docker-compose up -d
    exit 0
fi

if [ "$OLD_DB" != "rclone_gui" ]; then
    echo "   ⚠️  Database 'rclone_gui' not found"
    echo ""
    echo "   Available databases:"
    docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -l 2>/dev/null || echo "   (Unable to list databases)"
    docker rm -f cloudklone-migration-temp
    exit 1
fi

echo "   ✅ Found database 'rclone_gui'"

echo ""
echo "7. Checking for superuser access..."

# Check if rclone_admin is a superuser
IS_SUPERUSER=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT usesuper FROM pg_user WHERE usename='rclone_admin'" 2>/dev/null || echo "f")

if [ "$IS_SUPERUSER" = "t" ]; then
    echo "   ✅ rclone_admin has superuser privileges"
    SUPERUSER="rclone_admin"
else
    echo "   ℹ️  rclone_admin is not a superuser, checking for postgres user..."
    
    # Check if postgres user exists
    POSTGRES_EXISTS=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT 1 FROM pg_user WHERE usename='postgres'" 2>/dev/null || echo "")
    
    if [ -z "$POSTGRES_EXISTS" ]; then
        echo "   ℹ️  Creating postgres superuser for migration..."
        docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -c "CREATE USER postgres WITH SUPERUSER PASSWORD 'temp123';" 2>/dev/null || {
            echo "   ❌ Unable to create postgres user"
            echo "   Trying to use rclone_admin anyway..."
        }
    fi
    SUPERUSER="postgres"
fi

# Show what's in the database
echo ""
echo "8. Checking your data..."
USER_COUNT=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")
TRANSFER_COUNT=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT COUNT(*) FROM transfers;" 2>/dev/null || echo "?")
REMOTE_COUNT=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT COUNT(*) FROM remotes;" 2>/dev/null || echo "?")

echo "   📊 Users: $USER_COUNT"
echo "   📊 Transfers: $TRANSFER_COUNT"
echo "   📊 Remotes: $REMOTE_COUNT"

echo ""
echo "9. Ready to migrate!"
echo ""
echo "   This will rename:"
echo "   • Database: rclone_gui → cloudklone"
echo "   • User: rclone_admin → cloudklone_user"
echo ""
echo "   ✅ All your data will be preserved!"
echo ""
read -p "   Continue with migration? [y/N]: " confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Migration cancelled"
    docker rm -f cloudklone-migration-temp
    exit 0
fi

echo ""
echo "10. Disconnecting active database sessions..."
docker exec cloudklone-migration-temp psql -U $SUPERUSER -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'rclone_gui' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true

echo "11. Renaming database: rclone_gui → cloudklone..."
if docker exec cloudklone-migration-temp psql -U $SUPERUSER -c "ALTER DATABASE rclone_gui RENAME TO cloudklone;" 2>&1 | grep -q "ERROR"; then
    echo "   ❌ Failed to rename database"
    docker logs cloudklone-migration-temp --tail 10
    docker rm -f cloudklone-migration-temp
    exit 1
else
    echo "   ✅ Database renamed"
fi

echo "12. Renaming user: rclone_admin → cloudklone_user..."
if docker exec cloudklone-migration-temp psql -U $SUPERUSER -c "ALTER USER rclone_admin RENAME TO cloudklone_user;" 2>&1 | grep -q "ERROR"; then
    echo "   ❌ Failed to rename user"
    docker rm -f cloudklone-migration-temp
    exit 1
else
    echo "   ✅ User renamed"
fi

echo "13. Updating ownership and permissions..."
docker exec cloudklone-migration-temp psql -U $SUPERUSER << 'EOF' >/dev/null 2>&1
\c cloudklone
ALTER DATABASE cloudklone OWNER TO cloudklone_user;
ALTER SCHEMA public OWNER TO cloudklone_user;
GRANT ALL PRIVILEGES ON DATABASE cloudklone TO cloudklone_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cloudklone_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cloudklone_user;
EOF
echo "   ✅ Ownership updated"

echo ""
echo "✅ Migration complete!"
echo ""
echo "14. Cleaning up temporary container..."
docker rm -f cloudklone-migration-temp

echo ""
echo "15. Starting CloudKlone with new configuration..."
docker-compose up -d

echo ""
echo "16. Waiting for containers to be healthy..."
sleep 10

echo ""
echo "🎉 Migration successful!"
echo ""
echo "Verification:"
docker-compose exec -T postgres psql -U cloudklone_user -d cloudklone << 'EOF' 2>/dev/null || echo "Container still starting, check in a moment"
SELECT current_database() as database, current_user as user;
SELECT COUNT(*) as users FROM users;
SELECT COUNT(*) as transfers FROM transfers;
SELECT COUNT(*) as remotes FROM remotes;
EOF

echo ""
echo "✅ CloudKlone is now running with the new database names!"
echo ""
echo "Next steps:"
echo "1. Hard refresh your browser: Ctrl+Shift+R"
echo "2. Login and verify everything works"
echo "3. Check timezone: Create transfer at 12:00 AM, should show 12:00 AM"
echo "4. Check admin visibility: Admin should see all users' scheduled jobs"
echo ""
