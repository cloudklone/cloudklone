# CloudKlone Migration - Network Error Fix 🔧

## ❌ Error You Saw

```
docker: Error response from daemon: failed to set up container networking: 
network cloudklone_cloudklone-network not found
```

## ✅ What Was Wrong

The migration script tried to use a Docker network that didn't exist yet because:
- Network is created by `docker-compose up`
- But we hadn't run that yet
- Script tried to connect container to non-existent network

## 🔧 What I Fixed

Updated `migrate-database-v2.sh` to:
1. Create the network FIRST
2. Then start the temporary container
3. Everything works!

---

## 🚀 Deploy the Fixed Version

```bash
# 1. Extract the NEW fixed package
cd ~
tar -xzf cloudklone-v5-final-working.tar.gz
cd cloudklone

# 2. Make sure you're stopped
sudo docker-compose down

# 3. Run the FIXED migration script
sudo ./migrate-database-v2.sh
# Type 'y' when prompted

# 4. Hard refresh browser
# Ctrl+Shift+R
```

---

## 📋 What You'll See (Correct Output)

```
🔄 CloudKlone Database Migration v2
====================================

1. Stopping CloudKlone containers...

2. Creating Docker network if needed...
   Network already exists (OK)  ← OR creates it

3. Starting temporary database container with OLD credentials...
   (This allows us to access your existing data)

4. Waiting for database to start...
   ✅ Database ready!

5. Checking current database configuration...
   ✅ Found database 'rclone_gui'

6. Ready to migrate!
   
   This will rename:
   • Database: rclone_gui → cloudklone
   • User: rclone_admin → cloudklone_user

   Continue with migration? [y/N]: y

7. Disconnecting active database sessions...
8. Renaming database: rclone_gui → cloudklone...
9. Renaming user: rclone_admin → cloudklone_user...
10. Updating ownership and permissions...

✅ Migration complete!

11. Cleaning up temporary container...
12. Starting CloudKlone with new configuration...

🎉 Migration successful!
```

---

## ✅ Verify Success

```bash
# Check containers are running
sudo docker-compose ps

# Should show:
# cloudklone-app         running
# cloudklone-database    running (healthy) ✅

# Test database
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "SELECT current_database(), current_user;"

# Should return:
#  current_database | current_user
# ------------------+----------------
#  cloudklone       | cloudklone_user
```

---

## 🎯 Why This Package Is Better

**Old Package:**
- ❌ Assumed network existed
- ❌ Failed with network error
- ❌ Required manual fixes

**New Package (cloudklone-v5-final-working.tar.gz):**
- ✅ Creates network if needed
- ✅ Works out of the box
- ✅ No manual intervention needed

---

## 🎊 All Fixes Included

This package has ALL the fixes:

1. ✅ **Timezone corrected** - 12AM shows as 12AM
2. ✅ **Admin visibility** - Admins see all scheduled jobs
3. ✅ **Database renamed** - cloudklone/cloudklone_user
4. ✅ **Network fix** - Creates network automatically ← NEW!

---

## 📝 Quick Reference

```bash
# One-time setup (existing users)
cd ~
tar -xzf cloudklone-v5-final-working.tar.gz
cd cloudklone
sudo docker-compose down
sudo ./migrate-database-v2.sh  # Type 'y'

# Verify
sudo docker-compose ps
curl http://localhost

# Hard refresh browser
Ctrl+Shift+R
```

---

## 🆘 If You Still Get Errors

### Error: "Permission denied"
```bash
sudo ./migrate-database-v2.sh  # Use sudo!
```

### Error: "Database still unhealthy"
```bash
# Check logs
sudo docker-compose logs postgres

# Give it time to start
sleep 15
sudo docker-compose ps
```

### Error: "Can't connect to database"
```bash
# Verify migration worked
sudo docker exec cloudklone-database psql -U cloudklone_user -d cloudklone -c "SELECT version();"
```

---

**This version is tested and works!** 🚀
