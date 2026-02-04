# CloudKlone Migration v3 - Better Diagnostics

## What's New in v3

The database failed to start in v2 after 30 seconds. v3 has:

✅ **60 second timeout** (instead of 30)
✅ **Progress updates** every 10 seconds
✅ **Shows database logs** if it fails
✅ **More diagnostic info** to see what's wrong
✅ **Verifies your data** after migration

---

## 🚀 Run the New Script

```bash
# 1. Extract the package (if you haven't already)
cd ~
tar -xzf cloudklone-v5-final-working.tar.gz

# 2. Go to directory
cd cloudklone

# 3. Run v3 migration script
sudo ./migrate-database-v3.sh
```

---

## 📋 What You'll See

```
🔄 CloudKlone Database Migration v3
====================================

1. Stopping CloudKlone containers...

2. Cleaning up any previous migration attempts...
   cloudklone-migration-temp  ← Removes stuck container

3. Creating Docker network if needed...
   Network already exists (OK)

4. Starting temporary database container with OLD credentials...
   Container started: 0e6cd60cbb77...

5. Waiting for database to start (up to 60 seconds)...
   Still waiting... (10 seconds elapsed)
   Still waiting... (20 seconds elapsed)
   ✅ Database ready after 25 seconds!
   
6. Checking current database configuration...
   ✅ Found database 'rclone_gui'
   
   Database contents:
   user_count: 2
   transfer_count: 5
   
7. Ready to migrate!
   Continue with migration? [y/N]: y

8-11. [Migration steps...]

✅ Migration complete!

12. Cleaning up temporary container...
13. Starting CloudKlone with new configuration...
14. Waiting for containers to be healthy...
   ✅ Containers started successfully!

🎉 Migration successful!

Verification:
 database   | user
------------+----------------
 cloudklone | cloudklone_user
 
 users | transfers
-------+-----------
     2 |         5

✅ CloudKlone is now running with the new database names!
```

---

## 🔍 If Database Fails to Start

If the database still fails after 60 seconds, v3 will show:

```
   ❌ Database failed to start after 60 seconds
   
   Checking container status...
   [container info]
   
   Last 20 lines of database logs:
   [actual error messages from postgres]
```

This will tell us **exactly** what's wrong!

---

## 🛠️ Common Issues & Solutions

### Issue: Volume locked/corrupted
**Logs might show:**
```
FATAL: lock file "postmaster.pid" already exists
```

**Fix:**
```bash
# Stop everything
sudo docker-compose down

# Remove stuck containers
sudo docker rm -f cloudklone-migration-temp

# Try again
sudo ./migrate-database-v3.sh
```

### Issue: Insufficient disk space
**Logs might show:**
```
No space left on device
```

**Fix:**
```bash
# Check disk space
df -h

# Clean up Docker
sudo docker system prune -a
```

### Issue: Permission problems
**Logs might show:**
```
permission denied
```

**Fix:**
```bash
# Run with sudo
sudo ./migrate-database-v3.sh
```

---

## 📊 What Gets Checked

Before migration, v3 shows:
- ✅ Container status
- ✅ Database exists
- ✅ User count in database
- ✅ Transfer count in database

After migration, v3 verifies:
- ✅ Database renamed
- ✅ User renamed  
- ✅ Data still there
- ✅ Containers healthy

---

## 🎯 Next Steps

1. Run `sudo ./migrate-database-v3.sh`
2. If it fails, **copy the error logs** it shows
3. Send me the logs so I can see exactly what's wrong

The v3 script will show us what's happening! 🔍
