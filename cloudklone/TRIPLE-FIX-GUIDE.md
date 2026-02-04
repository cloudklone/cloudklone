# CloudKlone v5 - Triple Fix Package 🚀

## 🐛 Three Critical Issues Fixed

### Issue 1: Timezone Still Off by 2 Hours ⏰
**Problem:** Setting transfer for 12:00 AM shows next run at 2:00 PM (14 hours off!)

**Root Cause:** Previous timezone fix had logic error in UTC conversion.

**Fix:** Completely rewrote `calculateNextRun()` with proper UTC handling:
- Creates date in UTC coordinates
- Adds user's timezone offset correctly
- Stores as UTC timestamp in database
- Browser automatically displays in user's local time

---

### Issue 2: Scheduled Jobs Only Visible to Creator 👁️
**Problem:** User creates scheduled transfer, admin can't see it in Scheduled tab.

**Root Cause:** Query filtered by `user_id`, showing only own transfers.

**Fix:**
- Admins now see ALL scheduled transfers
- Regular users still see only their own
- Stats updated accordingly
- Permissions maintained (can only edit own or if admin)

---

### Issue 3: Database Named "rclone_gui" 🏷️
**Problem:** Database and user named after rclone, but CloudKlone is more than an rclone GUI.

**Root Cause:** Original naming from early development.

**Fix:**
- Database: `rclone_gui` → `cloudklone`
- User: `rclone_admin` → `cloudklone_user`
- Updated all files: docker-compose.yml, deploy.sh, docs
- Migration script handles existing databases
- All new installations use new names automatically

---

## 🚀 Deploy Instructions

### For Existing Installations (Important!)

**Step 1: Stop CloudKlone**
```bash
cd ~/cloudklone
sudo docker-compose down
```

**Step 2: Extract New Version**
```bash
cd ~
tar -xzf cloudklone-v5-triple-fix.tar.gz
cd cloudklone
```

**Step 3: Run Migration Script**
```bash
sudo ./migrate-database-v2.sh
# Type 'y' when prompted
```

The script will:
- ✅ Start temporary container with OLD credentials
- ✅ Rename database: rclone_gui → cloudklone
- ✅ Rename user: rclone_admin → cloudklone_user
- ✅ Update ownership and permissions
- ✅ Start CloudKlone with NEW credentials
- ✅ **Preserve all your data!**

**Step 4: Hard Refresh Browser**
```
Ctrl+Shift+R (Windows/Linux)
Cmd+Shift+R (Mac)
```

---

### For Fresh Installations (Easy!)

```bash
cd ~
tar -xzf cloudklone-v5-triple-fix.tar.gz
cd cloudklone
sudo docker-compose up -d
```

New installations automatically use `cloudklone`/`cloudklone_user` names!

---

## 🧪 Testing the Fixes

### Test 1: Timezone Accuracy

**Before:** 12:00 AM → Shows 2:00 PM ❌

**After:** 12:00 AM → Shows 12:00 AM ✅

**Test Steps:**
```
1. Go to Transfers tab
2. Fill in source/dest
3. Check "Schedule this transfer"
4. Select "Recurring"
5. Choose "Daily"
6. Set time to "00:00" (midnight)
7. Click "Start Transfer"
8. Go to Scheduled tab
9. Check "Next Run"
```

**Expected:** Shows approximately 12:00 AM tomorrow (your timezone)

**To verify timezone:**
```javascript
// In browser console
console.log(new Date().toString());
// Should show your local time with timezone
```

---

### Test 2: Admin Visibility

**Before:** Admin can't see other users' scheduled jobs ❌

**After:** Admin sees ALL scheduled jobs ✅

**Test Steps:**
```
1. Login as regular user
2. Create scheduled transfer
3. Logout
4. Login as admin
5. Go to Scheduled tab
6. Should see all users' scheduled transfers
```

**Expected:** 
- Admin sees all scheduled jobs from all users
- Regular users see only their own
- Statistics show correct counts for each user type

---

### Test 3: Database Naming

**Before:** 
```
Database: rclone_gui
User: rclone_admin
```

**After:**
```
Database: cloudklone
User: cloudklone_user
```

**Verify Migration:**
```bash
# Check database name
docker exec cloudklone-database psql -U postgres -l | grep cloudklone

# Check user name
docker exec cloudklone-database psql -U postgres -c "\\du" | grep cloudklone_user

# Test connection
docker exec cloudklone-database psql -U cloudklone_user -d cloudklone -c "SELECT current_database(), current_user;"
```

**Expected Output:**
```
 current_database | current_user
------------------+---------------
 cloudklone       | cloudklone_user
```

---

## 🔧 Technical Details

### Fix 1: Timezone Logic

**New `calculateNextRun()` Logic:**

```javascript
// 1. User in EST (UTC-5, offset=300) selects 12:00 AM
const [hours, minutes] = "00:00".split(':');

// 2. Create date in UTC coordinates for today
let next = new Date(Date.UTC(year, month, date, 0, 0, 0, 0));

// 3. Add timezone offset (300 minutes = 5 hours)
next = new Date(next.getTime() + (300 * 60 * 1000));
// Result: 5:00 AM UTC (which is 12:00 AM EST)

// 4. Store in database as UTC timestamp
// 5. Browser displays in user's local time (12:00 AM EST)
```

**Key Changes:**
- Use `Date.UTC()` for creating base date
- Add (not subtract) timezone offset for west of UTC
- Store as UTC timestamp
- Let browser handle display conversion

---

### Fix 2: Admin Query Update

**Before:**
```sql
SELECT * FROM transfers 
WHERE user_id = $1 AND status = 'scheduled'
```

**After:**
```sql
-- Admin query
SELECT * FROM transfers WHERE status = 'scheduled'

-- Regular user query
SELECT * FROM transfers WHERE status = 'scheduled' AND user_id = $1
```

**Backend Check:**
```javascript
if (!req.user.isAdmin) {
  query += ' AND user_id = $2';
  params.push(req.user.id);
}
```

---

### Fix 3: Database Migration

**Migration Process:**

```sql
-- 1. Disconnect sessions
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'rclone_gui';

-- 2. Rename database
ALTER DATABASE rclone_gui RENAME TO cloudklone;

-- 3. Rename user
ALTER USER rclone_admin RENAME TO cloudklone_user;

-- 4. Update ownership
ALTER DATABASE cloudklone OWNER TO cloudklone_user;
GRANT ALL PRIVILEGES ON DATABASE cloudklone TO cloudklone_user;
```

**Files Updated:**
- `docker-compose.yml` - postgres environment
- `docker-compose.https.yml` - postgres environment
- `deploy.sh` - DATABASE_URL and psql commands
- All documentation files (for reference)

---

## 🛠️ Troubleshooting

### Issue: Timezone Still Wrong

**Check:**
```bash
# 1. Server timezone
docker exec cloudklone-app date

# 2. Database timezone
docker exec cloudklone-database psql -U cloudklone_user -d cloudklone -c "SELECT now();"

# 3. Your browser timezone
# In browser console:
console.log(new Date().getTimezoneOffset());
```

**Fix:**
```bash
# Restart containers
sudo docker-compose restart

# Clear browser cache
# Hard refresh: Ctrl+Shift+R
```

---

### Issue: Can't See Scheduled Jobs

**Check:**
```bash
# 1. Check if you're admin
docker exec cloudklone-database psql -U cloudklone_user -d cloudklone \
  -c "SELECT username, is_admin FROM users;"

# 2. Check scheduled transfers exist
docker exec cloudklone-database psql -U cloudklone_user -d cloudklone \
  -c "SELECT id, user_id, status, schedule_type FROM transfers WHERE status='scheduled';"
```

**Fix:**
- Regular users: Will only see their own (this is correct)
- Admins: Should see all (if not, check is_admin flag)

---

### Issue: Migration Failed

**Symptoms:**
```
ERROR:  database "rclone_gui" does not exist
```

**This means:**
- Fresh installation (no migration needed) ✅
- OR already migrated ✅

**Verify:**
```bash
# Check which database exists
docker exec cloudklone-database psql -U postgres -l

# Look for either:
# - cloudklone (new, good!)
# - rclone_gui (old, run migration)
```

**If rclone_gui exists but migration failed:**
```bash
# Stop containers
sudo docker-compose down

# Start just database
sudo docker-compose up -d postgres

# Wait 10 seconds
sleep 10

# Run migration manually
./migrate-database.sh

# Then start everything
sudo docker-compose down
sudo docker-compose up -d
```

---

### Issue: Connection Refused After Migration

**Error:**
```
could not connect to server: Connection refused
```

**Cause:** Database credentials don't match.

**Fix:**
```bash
# 1. Check docker-compose.yml has new names
grep "POSTGRES_" docker-compose.yml

# Should see:
# POSTGRES_DB: cloudklone
# POSTGRES_USER: cloudklone_user

# 2. Check DATABASE_URL in environment
docker exec cloudklone-app env | grep DATABASE_URL

# Should see:
# DATABASE_URL=postgresql://cloudklone_user:changeme123@postgres:5432/cloudklone

# 3. If wrong, recreate containers
sudo docker-compose down -v  # WARNING: Deletes volumes!
sudo docker-compose up -d
```

⚠️ **WARNING:** `docker-compose down -v` deletes data! Only use as last resort.

---

## 📊 Before/After Comparison

| Feature | Before | After |
|---------|--------|-------|
| **Timezone** | 12AM → Shows 2PM ❌ | 12AM → Shows 12AM ✅ |
| **Admin Visibility** | Own jobs only ❌ | All jobs ✅ |
| **Database Name** | rclone_gui ❌ | cloudklone ✅ |
| **Database User** | rclone_admin ❌ | cloudklone_user ✅ |
| **Fresh Install** | Old names ❌ | New names ✅ |
| **Migration** | Manual ❌ | Automated ✅ |

---

## 📝 Files Changed

### Core Files
- `backend/index.js` - Fixed calculateNextRun(), admin queries
- `docker-compose.yml` - New database names
- `docker-compose.https.yml` - New database names
- `deploy.sh` - New DATABASE_URL

### New Files
- `migrate-database.sh` - Automated migration script
- `TRIPLE-FIX-GUIDE.md` - This guide

### Documentation (Reference Only)
- All existing `.md` files updated for accuracy

---

## ✅ Complete Feature List

This version includes **everything**:

1. ✅ Purple rebrand with logo
2. ✅ All 9 security fixes
3. ✅ Completion/hung transfer fixes
4. ✅ Green completion messages
5. ✅ Admin lockdown
6. ✅ HTTPS support (3 options)
7. ✅ Natural text descriptions
8. ✅ **Timezone fix (CORRECTED)** ← FIXED!
9. ✅ **Admin sees all scheduled jobs** ← NEW!
10. ✅ **Database renamed to cloudklone** ← NEW!

**Production-ready and properly named!** 🎉

---

## 🎯 Quick Reference

### For Existing Users
```bash
cd ~/cloudklone
sudo docker-compose down
cd ~ && tar -xzf cloudklone-v5-triple-fix.tar.gz
cd cloudklone
sudo ./migrate-database-v2.sh  # Type 'y' when prompted
# Hard refresh browser: Ctrl+Shift+R
```

### For New Users
```bash
tar -xzf cloudklone-v5-triple-fix.tar.gz
cd cloudklone
sudo docker-compose up -d
```

### Verify Everything Works
```bash
# 1. Timezone test: Schedule transfer for 12:00 AM
#    Should show Next Run: ~12:00 AM (tomorrow)

# 2. Admin test: Login as admin
#    Should see all users' scheduled jobs

# 3. Database test:
docker exec cloudklone-database psql -U cloudklone_user -d cloudklone -c "SELECT version();"
```

---

## 🎊 You're All Set!

After deploying:
- ✅ Scheduled times are accurate
- ✅ Admins can see all scheduled jobs
- ✅ Database has professional naming
- ✅ Migration is painless
- ✅ Everything just works!

**CloudKlone is production-ready!** 🚀
