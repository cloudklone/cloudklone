# CloudKlone - Migration for YOUR Existing Installation

## 📍 Your Situation

You have an **existing CloudKlone installation** with:
- ✅ All your test data from our chat session
- ✅ Users, remotes, transfers already created
- ✅ Database named `rclone_gui` with user `rclone_admin`
- ✅ Data that needs to be preserved during migration

**This is NOT a fresh install - we're migrating your existing data!**

---

## 🎯 What the Migration Will Do

**Your data before migration:**
```
Database: rclone_gui
User: rclone_admin
Data: All your transfers, users, remotes, scheduled jobs
```

**After migration:**
```
Database: cloudklone (renamed)
User: cloudklone_user (renamed)
Data: EXACTLY THE SAME - all preserved! ✅
```

**Nothing is deleted - we're just renaming!**

---

## 🚀 Step-by-Step Migration (For Your Setup)

### Step 1: Extract the New Package
```bash
cd ~
tar -xzf cloudklone-v5-final-working.tar.gz
```

This extracts the new code to `~/cloudklone/` (overwrites old files, but database is separate)

### Step 2: Go to CloudKlone Directory
```bash
cd ~/cloudklone
```

### Step 3: Run the Migration Script
```bash
sudo ./migrate-database-v2.sh
```

**What you'll see:**
```
🔄 CloudKlone Database Migration v2
====================================

1. Stopping CloudKlone containers...
   (Stops any running containers)

2. Cleaning up any previous migration attempts...
   (Removes any stuck containers from before)

3. Creating Docker network if needed...
   Network already exists (OK)
   (Creates network that was missing before)

4. Starting temporary database container with OLD credentials...
   (This allows us to access your existing data)
   
   ebed86a9629... (container ID)

5. Waiting for database to start...
   ✅ Database ready!

6. Checking current database configuration...
   ✅ Found database 'rclone_gui'

7. Ready to migrate!
   
   This will rename:
   • Database: rclone_gui → cloudklone
   • User: rclone_admin → cloudklone_user

   Continue with migration? [y/N]: 
```

**Type:** `y` and press Enter

```
8. Disconnecting active database sessions...
9. Renaming database: rclone_gui → cloudklone...
10. Renaming user: rclone_admin → cloudklone_user...
11. Updating ownership and permissions...

✅ Migration complete!

12. Cleaning up temporary container...
13. Starting CloudKlone with new configuration...
[+] Running 2/2
 ✔ Container cloudklone-database  Started
 ✔ Container cloudklone-app       Started

🎉 Migration successful!

Verification:
 current_database | current_user
------------------+----------------
 cloudklone       | cloudklone_user

✅ CloudKlone is now running with the new database names!
```

### Step 4: Hard Refresh Your Browser
```
Windows/Linux: Ctrl + Shift + R
Mac: Cmd + Shift + R
```

### Step 5: Verify Everything Works
```bash
# Check containers
sudo docker-compose ps

# Should show:
NAME                   STATUS
cloudklone-app         Up (healthy)
cloudklone-database    Up (healthy)
```

---

## 🧪 Test Your Data Is Still There

### 1. Check Database Connection
```bash
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "SELECT COUNT(*) FROM users;"
```
Should show your user count (including admin and any test users you created)

### 2. Check Transfers
```bash
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "SELECT COUNT(*) FROM transfers;"
```
Should show all your transfers from testing

### 3. Check Remotes
```bash
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "SELECT name FROM remotes;"
```
Should show all the remotes you configured (dockertest, backblaze-test, etc.)

### 4. Login to Web Interface
```
http://localhost
Username: admin
Password: admin (or whatever you changed it to)
```

**Everything should be exactly as you left it!**

---

## ✅ What's Fixed in This Version

For your existing installation:

1. ✅ **Timezone Fix** - Scheduled transfers at 12AM will show 12AM (not 2PM)
2. ✅ **Admin Visibility** - You'll see ALL scheduled transfers as admin
3. ✅ **Database Renamed** - Professional naming (cloudklone/cloudklone_user)
4. ✅ **Network Fix** - Migration script creates network automatically
5. ✅ **All Your Data Preserved** - Nothing lost!

---

## 📊 What Exactly Gets Migrated

**Database Tables (all preserved):**
- `users` - All your user accounts
- `groups` - Any groups you created
- `remotes` - All configured cloud remotes
- `transfers` - All transfer history
- `notification_settings` - Your email settings
- `audit_logs` - Complete audit trail

**Everything in these tables stays exactly the same!**

---

## 🔍 Troubleshooting

### If migration fails with "database already exists"

This means the migration already ran! Just start CloudKlone:
```bash
sudo docker-compose up -d
```

### If containers won't start

Check database logs:
```bash
sudo docker-compose logs postgres
```

### If you see "permission denied"

Make sure you used `sudo`:
```bash
sudo ./migrate-database-v2.sh
```

### If you want to verify before migrating

Check what's currently in your database:
```bash
# List databases
sudo docker run --rm -v cloudklone_postgres_data:/data postgres:16-alpine ls -la /data

# This shows the database files exist
```

---

## 🎯 Summary

**Your exact situation:**
- Existing installation from our whole chat session
- Data in database named `rclone_gui`
- Needs to be renamed to `cloudklone`
- All data must be preserved

**What the script does:**
- Connects to your existing database with OLD credentials
- Renames database and user inside PostgreSQL
- Restarts CloudKlone with NEW credentials
- **All your data is preserved!**

**After migration:**
- Same data, different names
- Fixed timezone issues
- Admin can see all scheduled jobs
- Professional database naming

---

## 🚀 Quick Commands

```bash
# Full migration process
cd ~
tar -xzf cloudklone-v5-final-working.tar.gz
cd cloudklone
sudo ./migrate-database-v2.sh  # Type 'y' when prompted

# Verify
sudo docker-compose ps
curl http://localhost
```

**Hard refresh browser: Ctrl+Shift+R**

---

**Your data is safe - this is just renaming, nothing is deleted!** 🎉
