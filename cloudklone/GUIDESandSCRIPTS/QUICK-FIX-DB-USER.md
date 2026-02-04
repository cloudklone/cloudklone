# Quick Fix: Database User Mismatch

## The Problem

Your existing database uses:
- User: `rclone_admin`  
- Database: `rclone_gui`
- Password: `changeme123`

But the new docker-compose.yml expected:
- User: `cloudklone`
- Database: `cloudklone`  
- Password: different

## The Fix

The new package (cloudklone-v4-final.tar.gz) now matches your existing database.

## Deploy Now

```bash
cd ~/cloudklone
docker-compose down

# Extract new version (overwrites docker-compose.yml)
cd ~ && tar -xzf cloudklone-v4-final.tar.gz
cd cloudklone

# Add missing database columns
docker-compose up -d postgres
sleep 5

docker-compose exec postgres psql -U rclone_admin rclone_gui << 'EOF'
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS schedule_type VARCHAR(20);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS schedule_interval VARCHAR(50);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS last_run TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS next_run TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS encrypted_config TEXT;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS group_id INTEGER;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS is_shared BOOLEAN DEFAULT false;
EOF

# Start the app
docker-compose up -d app

# Check logs
docker-compose logs -f app
```

You should see:
```
⚠ Generated new ENCRYPTION_KEY - saving to /app/.env
✓ Saved ENCRYPTION_KEY to /app/.env
⚠ Generated new JWT_SECRET - saving to /app/.env
✓ Saved JWT_SECRET to /app/.env
✓ CloudKlone server listening on 0.0.0.0:3001
```

## Test Your Transfer

1. Open http://localhost
2. Login: admin / admin
3. Try your B2 transfer again:
   - Source: backblaze-test:cloudklone
   - Dest: backblaze-test:cloudklone/test
   - Should work now!

## Why This Happened

When I updated docker-compose.yml, I changed the database credentials to be more descriptive (`cloudklone` instead of `rclone_admin`). But your existing database volume already had the old user, causing the mismatch.

The new package reverts to your original credentials, so everything is compatible!

## Future Upgrades

For future versions, your database credentials will stay as:
- `rclone_admin` / `rclone_gui` / `changeme123`

⚠️ **SECURITY WARNING**: The default password `changeme123` is **INSECURE** and must be changed immediately, especially if your server is exposed to the internet or untrusted networks!

**To rotate your database password NOW:**

```bash
# 1. Connect to database
docker-compose exec postgres psql -U rclone_admin rclone_gui

# 2. Change password (replace with a strong unique password)
ALTER USER rclone_admin WITH PASSWORD 'your_strong_unique_password_here';
\q

# 3. Update .env file
nano .env
# Change DATABASE_URL to: postgresql://rclone_admin:your_strong_unique_password_here@postgres:5432/rclone_gui

# 4. Restart CloudKlone
docker-compose restart app
```

**Password security checklist:**
- ✅ Use a unique, strong password (20+ characters)
- ✅ Store in a password vault/manager
- ✅ Never reuse this password elsewhere
- ✅ Rotate regularly (every 90 days)

This is important for production environments!

```bash
docker-compose exec postgres psql -U rclone_admin rclone_gui
ALTER USER rclone_admin WITH PASSWORD 'new_secure_password';
\q

# Then update docker-compose.yml to match
```
