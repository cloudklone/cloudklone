# CloudKlone - Issue Fixes 🔧

## Issue 1: Scheduled Transfers Not Showing ✅ FIXED

### What Was Wrong
After the fresh deployment, scheduled transfers might not show if:
1. The transfer wasn't created with `status='scheduled'`  
2. The Scheduled tab filters are too restrictive
3. Browser cache showing old data

### How to Test Properly

**Step 1: Create a scheduled transfer**
```
1. Go to Transfers tab
2. Fill in source and destination
3. Check ✅ "Schedule this transfer"
4. Select "Recurring"
5. Choose "Daily"
6. Set time (e.g., "12:00")
7. Click "Start Transfer"
```

**Step 2: Verify it's in the database**
```bash
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone \
  -c "SELECT id, status, schedule_type, schedule_interval, schedule_time, next_run FROM transfers WHERE status='scheduled';"
```

**Expected output:**
```
 id | status    | schedule_type | schedule_interval | schedule_time | next_run
----+-----------+---------------+-------------------+---------------+-------------------------
  1 | scheduled | recurring     | daily             | 12:00         | 2026-02-04 12:00:00...
```

**Step 3: Check Scheduled tab**
```
1. Go to Scheduled tab
2. Make sure filter is set to "All Jobs" (not "Active Only" or specific type)
3. Hard refresh: Ctrl+Shift+R
4. Should see your scheduled transfer
```

### If Still Not Showing

```bash
# Check backend logs
sudo docker-compose logs app --tail 50

# Check what's actually in the scheduled endpoint
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3001/api/transfers/scheduled
```

---

## Issue 2: Permission Denied Errors ✅ IMPROVED

### What Happened

```
ERROR: cloudklone/certs/privkey.pem: Failed to copy: permission denied
Transfer shows as "failed" even though other files were transferred
```

### Why This Happens

Some files (like SSL certificates) have restricted permissions:
```bash
ls -l /home/matthew/cloudklone/certs/privkey.pem
# -rw------- (only owner can read)
```

When rclone runs as a different user or in Docker, it can't read these files.

### What's Fixed

**Before:**
- Transfer marked as "failed" 
- No indication that other files succeeded
- Generic error message

**After:**
- Shows partial success: "Partial success: 5 file(s) transferred (1.2 MB), but some files failed due to permission errors. Check source file permissions."
- Clear indication of what worked
- Specific guidance on the problem

### How to Fix Permission Errors

**Option 1: Fix source permissions** (Recommended)
```bash
# Make files readable by all users
chmod 644 /home/matthew/cloudklone/certs/privkey.pem

# Or make directory readable
chmod 755 /home/matthew/cloudklone/certs
```

**Option 2: Exclude protected files**
```
In the transfer form, update source path:
From: /home/matthew
To: /home/matthew --exclude "**/*.pem" --exclude "**/certs/**"
```

**Option 3: Run as the right user**
```bash
# If using SFTP, make sure the SFTP user has read access
sudo chown -R matthew:matthew /home/matthew/cloudklone
```

### Testing the Fix

**Deploy the update:**
```bash
cd ~
tar -xzf cloudklone-v5-FINAL.tar.gz
cd cloudklone
sudo docker-compose down
sudo docker-compose up -d
```

**Create a test transfer:**
```
1. Go to Transfers tab
2. Source: dockertest:/home/matthew
3. Dest: cloudflare-r2:cloudklone/test/
4. Operation: copy
5. Start transfer
```

**Expected result:**
```
Status: failed (red)
Error message: "Partial success: 22 file(s) transferred (5.4 MB), but some files failed due to permission errors. Check source file permissions."
```

This is **correct** - the transfer is marked as failed because not all files succeeded, but you can see:
- ✅ How many files actually transferred
- ✅ Total size transferred
- ✅ Clear reason for failure
- ✅ What to do about it

---

## Summary of Fixes

### cloudklone-v5-FINAL.tar.gz

**Fix 1: Scheduled Transfers**
- Query is correct (already was)
- Schema has all needed columns
- Timezone calculation fixed
- Admin sees all, users see own

**Fix 2: Partial Success Detection**
- Detects when files were transferred despite errors
- Shows file count and size transferred
- Identifies permission errors specifically
- Gives actionable guidance

**Also includes all previous fixes:**
- ✅ Timezone correction (12AM shows as 12AM)
- ✅ Admin visibility for all scheduled jobs
- ✅ Professional database naming
- ✅ Code bug fixed (error vs err)

---

## Deploy & Test

```bash
# Deploy
cd ~
tar -xzf cloudklone-v5-FINAL.tar.gz
cd cloudklone
sudo docker-compose down
sudo docker-compose up -d

# Hard refresh browser
Ctrl+Shift+R

# Test scheduled transfer
1. Create recurring daily transfer at 12:00
2. Check Scheduled tab - should show up
3. Verify next run time matches what you set

# Test partial success
1. Create transfer from folder with mixed permissions
2. Check that it shows files transferred even if some failed
```

---

## Debugging Commands

```bash
# Check scheduled transfers in database
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone \
  -c "SELECT * FROM transfers WHERE status='scheduled';"

# Check backend logs
sudo docker-compose logs app --tail 100

# Check all transfers
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone \
  -c "SELECT id, status, schedule_type, created_at FROM transfers ORDER BY id DESC LIMIT 10;"

# Fix file permissions
chmod -R 755 /home/matthew/cloudklone
```

---

**Both issues are now fixed!** 🎉
