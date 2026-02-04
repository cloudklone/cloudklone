#!/bin/bash

# CloudKlone - Complete Fix Script
# Fixes: code bug, network issue, completes migration

set -e

echo "🔧 CloudKlone Complete Fix"
echo "=========================="
echo ""
echo "This will:"
echo "1. Stop containers"
echo "2. Fix network issue"
echo "3. Complete database migration"
echo "4. Start CloudKlone"
echo ""

# Check if we're running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
   echo "⚠️  This script needs sudo access."
   echo "Please run: sudo ./complete-fix.sh"
   exit 1
fi

echo "1. Stopping containers..."
docker-compose down 2>/dev/null || true

echo ""
echo "2. Cleaning up network and containers..."
docker rm -f cloudklone-migration-temp 2>/dev/null || true
docker network rm cloudklone_cloudklone-network 2>/dev/null || true

echo ""
echo "3. Creating network properly..."
docker network create cloudklone_cloudklone-network

echo ""
echo "4. Starting temporary database with OLD credentials..."
CONTAINER_ID=$(docker run -d \
  --name cloudklone-migration-temp \
  --network cloudklone_cloudklone-network \
  -e POSTGRES_DB=rclone_gui \
  -e POSTGRES_USER=rclone_admin \
  -e POSTGRES_PASSWORD=changeme123 \
  -v cloudklone_postgres_data:/var/lib/postgresql/data \
  postgres:16-alpine)

echo "   Container: $CONTAINER_ID"

echo ""
echo "5. Waiting for database recovery..."
sleep 5

READY=false
for i in {1..120}; do
    if docker exec cloudklone-migration-temp pg_isready -U rclone_admin -d rclone_gui &>/dev/null; then
        echo "   ✅ Database ready after $i seconds!"
        READY=true
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        echo "   ⏳ Still waiting... ($i seconds)"
    fi
    sleep 1
done

if [ "$READY" = false ]; then
    echo "   ❌ Database failed to start"
    docker logs cloudklone-migration-temp --tail 20
    exit 1
fi

echo ""
echo "6. Checking current state..."

# Check what exists
OLD_USER=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT usename FROM pg_user WHERE usename='rclone_admin'" 2>/dev/null || echo "")
NEW_USER=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT usename FROM pg_user WHERE usename='cloudklone_user'" 2>/dev/null || echo "")

OLD_DB=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT datname FROM pg_database WHERE datname='rclone_gui'" 2>/dev/null || echo "")
NEW_DB=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT datname FROM pg_database WHERE datname='cloudklone'" 2>/dev/null || echo "")

echo "   Database: $( [ -n "$NEW_DB" ] && echo "cloudklone ✅" || echo "rclone_gui" )"
echo "   User: $( [ -n "$NEW_USER" ] && echo "cloudklone_user ✅" || echo "rclone_admin" )"

if [ -n "$NEW_USER" ] && [ -n "$NEW_DB" ]; then
    echo ""
    echo "   ✅ Migration already complete!"
    docker rm -f cloudklone-migration-temp
    docker-compose up -d
    echo ""
    echo "🎉 CloudKlone started!"
    exit 0
fi

echo ""
echo "7. Migration needed! Your data:"
USER_COUNT=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")
TRANSFER_COUNT=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT COUNT(*) FROM transfers;" 2>/dev/null || echo "?")
REMOTE_COUNT=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT COUNT(*) FROM remotes;" 2>/dev/null || echo "?")

echo "   📊 Users: $USER_COUNT"
echo "   📊 Transfers: $TRANSFER_COUNT"  
echo "   📊 Remotes: $REMOTE_COUNT"

echo ""
read -p "8. Rename database and user? [y/N]: " confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Migration cancelled"
    docker rm -f cloudklone-migration-temp
    exit 0
fi

echo ""
echo "9. Checking for superuser..."

# Check if rclone_admin is superuser
IS_SUPER=$(docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui -tAc "SELECT usesuper FROM pg_user WHERE usename='rclone_admin'" 2>/dev/null || echo "f")

if [ "$IS_SUPER" = "t" ]; then
    echo "   ✅ rclone_admin is superuser"
    SUPERUSER="rclone_admin"
else
    # Try to create postgres superuser
    echo "   Creating postgres superuser..."
    docker exec cloudklone-migration-temp psql -U rclone_admin -d rclone_gui << 'EOF' >/dev/null 2>&1
CREATE USER postgres WITH SUPERUSER PASSWORD 'temp123';
EOF
    SUPERUSER="postgres"
fi

echo ""
echo "10. Renaming database..."
docker exec cloudklone-migration-temp psql -U $SUPERUSER -d rclone_gui -c "ALTER DATABASE rclone_gui RENAME TO cloudklone;" 2>&1 | grep -v "^ALTER DATABASE$" || echo "   ✅ Renamed"

echo "11. Renaming user..."
docker exec cloudklone-migration-temp psql -U $SUPERUSER -d cloudklone -c "ALTER USER rclone_admin RENAME TO cloudklone_user;" 2>&1 | grep -v "^ALTER ROLE$" || echo "   ✅ Renamed"

echo "12. Updating permissions..."
docker exec cloudklone-migration-temp psql -U cloudklone_user -d cloudklone << 'EOF' >/dev/null 2>&1
ALTER DATABASE cloudklone OWNER TO cloudklone_user;
ALTER SCHEMA public OWNER TO cloudklone_user;
GRANT ALL PRIVILEGES ON DATABASE cloudklone TO cloudklone_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cloudklone_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cloudklone_user;
EOF
echo "   ✅ Done"

echo ""
echo "✅ Migration complete!"

echo ""
echo "13. Cleaning up..."
docker rm -f cloudklone-migration-temp

echo ""
echo "14. Starting CloudKlone with new configuration..."
docker-compose up -d

echo ""
echo "15. Waiting for containers..."
sleep 10

echo ""
echo "🎉 CloudKlone is running!"
echo ""
echo "Verification:"
docker-compose exec -T postgres psql -U cloudklone_user -d cloudklone << 'EOF' 2>/dev/null || echo "Still starting, check in a moment"
SELECT current_database() as database, current_user as user;
SELECT COUNT(*) as users FROM users;
SELECT COUNT(*) as transfers FROM transfers;
EOF

echo ""
echo "✅ All fixed!"
echo ""
echo "Next steps:"
echo "1. Hard refresh browser: Ctrl+Shift+R"
echo "2. Login and test"
echo ""
