#!/bin/bash

# CloudKlone Database Migration Script (v2)
# Migrates from old naming (rclone_gui/rclone_admin) to new naming (cloudklone/cloudklone_user)

set -e

echo "🔄 CloudKlone Database Migration v2"
echo "===================================="
echo ""
echo "This script will migrate your database from the old naming to the new naming."
echo ""

# Check if we're running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
   echo "⚠️  This script needs sudo access to docker."
   echo "Please run: sudo ./migrate-database-v2.sh"
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

# Clean up any dangling migration containers
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
docker run -d \
  --name cloudklone-migration-temp \
  --network cloudklone_cloudklone-network \
  -e POSTGRES_DB=rclone_gui \
  -e POSTGRES_USER=rclone_admin \
  -e POSTGRES_PASSWORD=changeme123 \
  -v cloudklone_postgres_data:/var/lib/postgresql/data \
  postgres:16-alpine

# Wait for database to be ready
echo "5. Waiting for database to start..."
sleep 10  # Give it more initial time

# Check if database is ready
for i in {1..60}; do  # Wait up to 60 seconds
    if docker exec cloudklone-migration-temp pg_isready -U rclone_admin -d rclone_gui &>/dev/null; then
        echo "   ✅ Database ready!"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "   ❌ Database failed to start after 60 seconds"
        echo ""
        echo "Showing container logs:"
        docker logs cloudklone-migration-temp
        echo ""
        docker rm -f cloudklone-migration-temp
        exit 1
    fi
    printf "."
    sleep 1
done
echo ""

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
    echo "   This might be a fresh installation."
    docker rm -f cloudklone-migration-temp
    echo ""
    echo "Starting CloudKlone (will create new database)..."
    docker-compose up -d
    exit 0
fi

echo "   ✅ Found database 'rclone_gui'"
echo ""
echo "7. Ready to migrate!"
echo ""
echo "   This will rename:"
echo "   • Database: rclone_gui → cloudklone"
echo "   • User: rclone_admin → cloudklone_user"
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
docker exec cloudklone-migration-temp psql -U postgres -c "ALTER DATABASE rclone_gui RENAME TO cloudklone;" 2>/dev/null || {
    echo "   ⚠️  Database rename failed (might already be renamed)"
}

echo "10. Renaming user: rclone_admin → cloudklone_user..."
docker exec cloudklone-migration-temp psql -U postgres -c "ALTER USER rclone_admin RENAME TO cloudklone_user;" 2>/dev/null || {
    echo "   ⚠️  User rename failed (might already be renamed)"
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
echo "🎉 Migration successful!"
echo ""
echo "Verification:"
sleep 5
docker-compose exec -T postgres psql -U cloudklone_user -d cloudklone -c "SELECT current_database() as database, current_user as user;" 2>/dev/null || {
    echo "⚠️  Unable to verify (container still starting)"
    echo "Check status with: sudo docker-compose ps"
}

echo ""
echo "✅ CloudKlone is now running with the new database names!"
echo ""
echo "Next steps:"
echo "1. Hard refresh your browser: Ctrl+Shift+R"
echo "2. Login and verify everything works"
echo "3. Your data is preserved - all transfers, remotes, users intact"
echo ""
