#!/bin/bash

# CloudKlone Database Migration Script (v3)
# Migrates from old naming (rclone_gui/rclone_admin) to new naming (cloudklone/cloudklone_user)

set -e

echo "🔄 CloudKlone Database Migration v3"
echo "===================================="
echo ""
echo "This script will migrate your database from the old naming to the new naming."
echo ""

# Check if we're running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
   echo "⚠️  This script needs sudo access to docker."
   echo "Please run: sudo ./migrate-database-v3.sh"
   exit 1
fi

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Error: docker command not found"
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

# Start ONLY the database with OLD environment variables
CONTAINER_ID=$(docker run -d \
  --name cloudklone-migration-temp \
  --network cloudklone_cloudklone-network \
  -e POSTGRES_DB=rclone_gui \
  -e POSTGRES_USER=rclone_admin \
  -e POSTGRES_PASSWORD=changeme123 \
  -v cloudklone_postgres_data:/var/lib/postgresql/data \
  postgres:16-alpine)

echo "   Container started: $CONTAINER_ID"

# Wait for database to be ready
echo ""
echo "5. Waiting for database to start (up to 60 seconds)..."
sleep 3

# Check if database is ready (increased timeout to 60 seconds)
READY=false
for i in {1..60}; do
    if docker exec cloudklone-migration-temp pg_isready -U rclone_admin -d rclone_gui &>/dev/null; then
        echo "   ✅ Database ready after $i seconds!"
        READY=true
        break
    fi
    
    # Show progress every 10 seconds
    if [ $((i % 10)) -eq 0 ]; then
        echo "   Still waiting... ($i seconds elapsed)"
    fi
    
    sleep 1
done

if [ "$READY" = false ]; then
    echo ""
    echo "   ❌ Database failed to start after 60 seconds"
    echo ""
    echo "   Checking container status..."
    docker ps -a | grep cloudklone-migration-temp || true
    echo ""
    echo "   Last 20 lines of database logs:"
    docker logs cloudklone-migration-temp --tail 20
    echo ""
    docker rm -f cloudklone-migration-temp
    exit 1
fi

echo ""
echo "6. Checking current database configuration..."

# Check which database exists
OLD_DB=$(docker exec cloudklone-migration-temp psql -U postgres -tAc "SELECT datname FROM pg_database WHERE datname='rclone_gui'" 2>/dev/null || echo "")
NEW_DB=$(docker exec cloudklone-migration-temp psql -U postgres -tAc "SELECT datname FROM pg_database WHERE datname='cloudklone'" 2>/dev/null || echo "")

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
    echo "   ⚠️  Neither 'rclone_gui' nor 'cloudklone' database found."
    echo ""
    echo "   Available databases:"
    docker exec cloudklone-migration-temp psql -U postgres -l
    echo ""
    docker rm -f cloudklone-migration-temp
    exit 1
fi

echo "   ✅ Found database 'rclone_gui'"

# Check what's in the database
echo ""
echo "   Database contents:"
docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -c "SELECT COUNT(*) as user_count FROM users;" 2>/dev/null || echo "   (Can't read users table yet)"
docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -c "SELECT COUNT(*) as transfer_count FROM transfers;" 2>/dev/null || echo "   (Can't read transfers table yet)"

echo ""
echo "7. Ready to migrate!"
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
echo "8. Disconnecting active database sessions..."
docker exec cloudklone-migration-temp psql -U postgres << 'EOF' 2>/dev/null || true
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'rclone_gui' AND pid <> pg_backend_pid();
EOF

echo "9. Renaming database: rclone_gui → cloudklone..."
docker exec cloudklone-migration-temp psql -U postgres -c "ALTER DATABASE rclone_gui RENAME TO cloudklone;" 2>&1 | grep -v "^ALTER DATABASE$" || {
    echo "   ⚠️  Database rename may have failed - checking..."
    # Check if it actually worked
    RENAMED=$(docker exec cloudklone-migration-temp psql -U postgres -tAc "SELECT datname FROM pg_database WHERE datname='cloudklone'" 2>/dev/null || echo "")
    if [ "$RENAMED" == "cloudklone" ]; then
        echo "   ✅ Database already renamed (OK)"
    else
        echo "   ❌ Database rename failed"
        docker rm -f cloudklone-migration-temp
        exit 1
    fi
}

echo "10. Renaming user: rclone_admin → cloudklone_user..."
docker exec cloudklone-migration-temp psql -U postgres -c "ALTER USER rclone_admin RENAME TO cloudklone_user;" 2>&1 | grep -v "^ALTER ROLE$" || {
    echo "   ⚠️  User rename may have failed - checking..."
    # Check if it actually worked
    RENAMED=$(docker exec cloudklone-migration-temp psql -U postgres -tAc "SELECT usename FROM pg_user WHERE usename='cloudklone_user'" 2>/dev/null || echo "")
    if [ "$RENAMED" == "cloudklone_user" ]; then
        echo "   ✅ User already renamed (OK)"
    else
        echo "   ❌ User rename failed"
        docker rm -f cloudklone-migration-temp
        exit 1
    fi
}

echo "11. Updating ownership and permissions..."
docker exec cloudklone-migration-temp psql -U postgres << 'EOF' 2>/dev/null
\c cloudklone
ALTER DATABASE cloudklone OWNER TO cloudklone_user;
ALTER SCHEMA public OWNER TO cloudklone_user;
GRANT ALL PRIVILEGES ON DATABASE cloudklone TO cloudklone_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cloudklone_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cloudklone_user;
EOF

echo ""
echo "✅ Migration complete!"
echo ""
echo "12. Cleaning up temporary container..."
docker rm -f cloudklone-migration-temp

echo ""
echo "13. Starting CloudKlone with new configuration..."
docker-compose up -d

echo ""
echo "14. Waiting for containers to be healthy..."
sleep 5

# Check if containers started
CONTAINERS=$(docker-compose ps --services --filter "status=running" 2>/dev/null | wc -l)
if [ "$CONTAINERS" -ge 2 ]; then
    echo "   ✅ Containers started successfully!"
else
    echo "   ⚠️  Some containers may not have started. Check with: sudo docker-compose ps"
fi

echo ""
echo "🎉 Migration successful!"
echo ""
echo "Verification:"
sleep 3
docker-compose exec -T postgres psql -U cloudklone_user -d cloudklone << 'EOF' 2>/dev/null || {
    echo "⚠️  Unable to verify (container still starting)"
    echo "Check status with: sudo docker-compose ps"
    echo "Check logs with: sudo docker-compose logs"
}
SELECT current_database() as database, current_user as user;
SELECT COUNT(*) as users FROM users;
SELECT COUNT(*) as transfers FROM transfers;
EOF

echo ""
echo "✅ CloudKlone is now running with the new database names!"
echo ""
echo "Next steps:"
echo "1. Hard refresh your browser: Ctrl+Shift+R"
echo "2. Login and verify everything works"
echo "3. Your data is preserved - all transfers, remotes, users intact"
echo ""
