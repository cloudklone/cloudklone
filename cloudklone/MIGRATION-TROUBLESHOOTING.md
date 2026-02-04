# CloudKlone Migration - Troubleshooting Guide 🔧

## ❌ Error: "dependency failed to start: container cloudklone-database is unhealthy"

### Why This Happens

Your existing database volume has data with the OLD names (`rclone_gui`/`rclone_admin`), but the new `docker-compose.yml` expects NEW names (`cloudklone`/`cloudklone_user`).

When Docker tries to start, it fails because:
```
Container expects: cloudklone database
Volume contains:   rclone_gui database
Result:            Unhealthy container ❌
```

---

## ✅ Solution: Use Migration Script v2

The new migration script solves this chicken-and-egg problem:

```bash
cd ~/cloudklone
sudo docker-compose down
sudo ./migrate-database-v2.sh
```

**What it does:**
1. Stops all containers
2. Starts temporary container with **OLD** credentials
3. Connects to your **existing** data
4. Renames database and user
5. Removes temporary container
6. Starts CloudKlone with **NEW** credentials
7. Everything works! ✅

---

## 🔍 Step-by-Step Fix

### 1. Stop Everything
```bash
cd ~/cloudklone
sudo docker-compose down
```

### 2. Run Migration Script v2
```bash
sudo ./migrate-database-v2.sh
```

**Expected output:**
```
🔄 CloudKlone Database Migration v2
====================================

1. Stopping CloudKlone containers...
2. Starting temporary database container with OLD credentials...
3. Waiting for database to start...
   ✅ Database ready!
4. Checking current database configuration...
   ✅ Found database 'rclone_gui'
5. Ready to migrate!

   This will rename:
   • Database: rclone_gui → cloudklone
   • User: rclone_admin → cloudklone_user

   Continue with migration? [y/N]: y

6. Disconnecting active database sessions...
7. Renaming database: rclone_gui → cloudklone...
8. Renaming user: rclone_admin → cloudklone_user...
9. Updating ownership and permissions...

✅ Migration complete!

10. Cleaning up temporary container...
11. Starting CloudKlone with new configuration...

🎉 Migration successful!
```

### 3. Verify It Worked
```bash
# Check containers are running
sudo docker-compose ps

# Should show:
# cloudklone-app         running
# cloudklone-database    running (healthy)
```

### 4. Test Database Connection
```bash
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "SELECT current_database(), current_user;"
```

**Expected output:**
```
 current_database | current_user
------------------+----------------
 cloudklone       | cloudklone_user
```

### 5. Hard Refresh Browser
```
Ctrl+Shift+R (Windows/Linux)
Cmd+Shift+R (Mac)
```

---

## 🛠️ Alternative Manual Fix

If the script doesn't work, here's the manual process:

### Step 1: Remove New Docker Compose Config Temporarily
```bash
cd ~/cloudklone
sudo docker-compose down

# Backup new docker-compose.yml
cp docker-compose.yml docker-compose.yml.new

# Create temporary old config
cat > docker-compose.yml << 'EOF'
services:
  postgres:
    container_name: cloudklone-database
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: rclone_gui
      POSTGRES_USER: rclone_admin
      POSTGRES_PASSWORD: changeme123
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - cloudklone-network

volumes:
  postgres_data:

networks:
  cloudklone-network:
EOF
```

### Step 2: Start with Old Config
```bash
sudo docker-compose up -d
sleep 10
```

### Step 3: Rename Database
```bash
sudo docker-compose exec postgres psql -U postgres << 'EOF'
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'rclone_gui';

ALTER DATABASE rclone_gui RENAME TO cloudklone;
ALTER USER rclone_admin RENAME TO cloudklone_user;

\c cloudklone
ALTER DATABASE cloudklone OWNER TO cloudklone_user;
GRANT ALL PRIVILEGES ON DATABASE cloudklone TO cloudklone_user;
EOF
```

### Step 4: Restore New Config and Restart
```bash
sudo docker-compose down
mv docker-compose.yml.new docker-compose.yml
sudo docker-compose up -d
```

---

## 📊 Common Errors and Solutions

### Error: "permission denied while trying to connect to docker"
**Solution:** Use `sudo`
```bash
sudo ./migrate-database-v2.sh
```

### Error: "pg_isready: could not connect to server"
**Solution:** Database is still starting, wait longer
```bash
# Check database logs
sudo docker-compose logs postgres

# Wait 30 seconds and try again
sleep 30
sudo ./migrate-database-v2.sh
```

### Error: "database 'rclone_gui' does not exist"
**This means:**
- Fresh installation (no migration needed) ✅
- Already migrated (no migration needed) ✅

**Solution:** Just start CloudKlone normally
```bash
sudo docker-compose up -d
```

### Error: "user 'cloudklone_user' does not exist"
**Solution:** Rename wasn't complete, finish manually
```bash
sudo docker-compose exec postgres psql -U postgres << 'EOF'
ALTER USER rclone_admin RENAME TO cloudklone_user;
GRANT ALL PRIVILEGES ON DATABASE cloudklone TO cloudklone_user;
EOF

sudo docker-compose restart
```

---

## 🔍 Diagnosis Commands

### Check what's in the database
```bash
# List databases
sudo docker-compose exec postgres psql -U postgres -l

# List users
sudo docker-compose exec postgres psql -U postgres -c "\du"
```

### Check container health
```bash
# Container status
sudo docker-compose ps

# Database logs
sudo docker-compose logs postgres --tail 50

# App logs
sudo docker-compose logs app --tail 50
```

### Check which database Docker expects
```bash
# View environment variables
sudo docker-compose config | grep POSTGRES
```

### Check which database actually exists
```bash
# Connect as postgres superuser
sudo docker-compose exec postgres psql -U postgres

# Then run:
\l          # List databases
\du         # List users
\q          # Quit
```

---

## 🎯 Quick Decision Tree

**Is this a fresh installation?**
→ YES: Just run `sudo docker-compose up -d`
→ NO: Continue below

**Do you have existing data?**
→ YES: Use `sudo ./migrate-database-v2.sh`
→ NO: Delete volumes and start fresh

**Is database container unhealthy?**
→ YES: You need to migrate (use script v2)
→ NO: Check other issues

**Has migration already run?**
→ YES: Just start normally
→ NO: Run migration script

---

## 💡 Understanding the Problem

### The Issue
```
Old Setup:
docker-compose.yml says: POSTGRES_DB=rclone_gui
Database volume has:     rclone_gui ✅ Match!

New Setup:
docker-compose.yml says: POSTGRES_DB=cloudklone
Database volume has:     rclone_gui ❌ Mismatch!
Container is unhealthy!
```

### The Solution
```
Migration:
1. Start container with OLD env vars
2. Connect to existing database
3. Rename inside database
4. Start with NEW env vars
5. Everything matches! ✅
```

---

## 📝 Post-Migration Checklist

After successful migration, verify:

- [ ] Containers are running: `sudo docker-compose ps`
- [ ] Database is healthy: `sudo docker-compose exec postgres pg_isready -U cloudklone_user -d cloudklone`
- [ ] Can connect: `sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "SELECT 1"`
- [ ] App is running: `curl http://localhost`
- [ ] Can login to web interface
- [ ] All transfers are visible
- [ ] All remotes are visible
- [ ] All users are present
- [ ] Schedule times are correct

---

## 🆘 Still Having Issues?

### Nuclear Option (Last Resort)

**⚠️ WARNING: This deletes all data!**

```bash
sudo docker-compose down -v  # Deletes volumes
sudo docker-compose up -d     # Fresh start
```

Only use if:
- Migration completely failed
- You have backups
- You don't need existing data

---

## ✅ Success Indicators

You'll know migration worked when:
- ✅ `sudo docker-compose ps` shows both containers running
- ✅ Database container shows "healthy"
- ✅ Web interface loads
- ✅ Can login with existing credentials
- ✅ All data is preserved
- ✅ New scheduled transfers show correct times

---

## 📞 Need More Help?

Check these logs:
```bash
# App logs
sudo docker-compose logs app --tail 100

# Database logs
sudo docker-compose logs postgres --tail 100

# Full logs
sudo docker-compose logs --tail 200
```

Look for error messages and check against this guide!
