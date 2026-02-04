#!/bin/bash

# CloudKlone Volume Diagnostic Script
# Checks what data exists in your database volume

echo "🔍 CloudKlone Volume Diagnostic"
echo "================================"
echo ""

# Check if we're running as root
if [ "$EUID" -ne 0 ]; then 
   echo "⚠️  This script needs sudo access."
   echo "Please run: sudo ./check-volume.sh"
   exit 1
fi

echo "1. Checking for Docker volumes..."
echo ""

# Check if volume exists
VOLUME_EXISTS=$(docker volume ls | grep cloudklone_postgres_data || echo "")

if [ -z "$VOLUME_EXISTS" ]; then
    echo "❌ No cloudklone_postgres_data volume found"
    echo ""
    echo "This means:"
    echo "  • Fresh installation (never deployed before)"
    echo "  • OR volumes were deleted with 'docker-compose down -v'"
    echo ""
    echo "✅ Solution: Just deploy normally (no migration needed)"
    echo ""
    echo "Deploy command:"
    echo "  sudo docker-compose up -d"
    echo ""
    exit 0
fi

echo "✅ Found volume: cloudklone_postgres_data"
echo ""

echo "2. Inspecting volume contents..."
echo ""

# Start temporary container to inspect volume
docker run --rm \
  -v cloudklone_postgres_data:/data \
  alpine sh -c "
    if [ -d /data/base ]; then
      echo '✅ Volume contains PostgreSQL data'
      echo ''
      echo 'Database directories found:'
      ls -la /data/base/ | head -10
      echo ''
      echo 'Total size:'
      du -sh /data
    else
      echo '❌ Volume exists but contains no PostgreSQL data'
      echo ''
      echo 'Volume contents:'
      ls -la /data
    fi
  "

echo ""
echo "3. Checking for running containers..."
echo ""

RUNNING=$(docker ps --format "{{.Names}}" | grep cloudklone || echo "")

if [ -z "$RUNNING" ]; then
    echo "❌ No CloudKlone containers running"
else
    echo "✅ Running containers:"
    docker ps --filter "name=cloudklone" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
fi

echo ""
echo "4. Checking for stopped/dangling containers..."
echo ""

STOPPED=$(docker ps -a --filter "name=cloudklone" --format "{{.Names}}" || echo "")

if [ -z "$STOPPED" ]; then
    echo "✅ No stopped containers"
else
    echo "⚠️  Found stopped/dangling containers:"
    docker ps -a --filter "name=cloudklone" --format "table {{.Names}}\t{{.Status}}"
    echo ""
    echo "Clean up with: sudo docker rm \$(sudo docker ps -a --filter 'name=cloudklone' -q)"
fi

echo ""
echo "5. Recommendation..."
echo ""

if [ -z "$VOLUME_EXISTS" ]; then
    echo "📋 FRESH INSTALLATION"
    echo "  • No volume found"
    echo "  • No migration needed"
    echo "  • Just deploy: sudo docker-compose up -d"
elif docker run --rm -v cloudklone_postgres_data:/data alpine test -d /data/base; then
    echo "📋 EXISTING DATA FOUND"
    echo "  • Volume has PostgreSQL data"
    echo "  • Migration might be needed"
    echo ""
    echo "Next steps:"
    echo "  1. Clean up: sudo docker rm \$(sudo docker ps -a --filter 'name=cloudklone' -q) 2>/dev/null"
    echo "  2. Try migration: sudo ./migrate-database-v2.sh"
    echo "  3. Or fresh start: sudo docker-compose down -v && sudo docker-compose up -d"
else
    echo "📋 EMPTY VOLUME"
    echo "  • Volume exists but empty"
    echo "  • Treat as fresh installation"
    echo "  • Just deploy: sudo docker-compose up -d"
fi

echo ""
echo "🎯 Most likely scenario:"
echo ""

if [ -z "$VOLUME_EXISTS" ] || ! docker run --rm -v cloudklone_postgres_data:/data alpine test -d /data/base 2>/dev/null; then
    echo "This is a FRESH installation - no existing data to migrate."
    echo ""
    echo "✅ Deploy command:"
    echo "   sudo docker-compose down"
    echo "   sudo docker-compose up -d"
    echo ""
    echo "Then access at: http://localhost"
    echo "Login: admin / admin"
else
    echo "You have existing data that needs migration."
    echo ""
    echo "✅ Migration command:"
    echo "   sudo docker rm \$(sudo docker ps -a --filter 'name=cloudklone' -q) 2>/dev/null"
    echo "   sudo ./migrate-database-v2.sh"
fi

echo ""
