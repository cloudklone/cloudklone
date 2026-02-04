# CloudKlone - Recurring Transfer Fix 🔄

## 🐛 The Bug You Found

**Problem:** When a recurring scheduled transfer fails, it changes to `status='failed'` and disappears from the Scheduled tab. It should stay as `status='scheduled'` and retry at the next scheduled time.

**You were right!** This is a CloudKlone bug, not an rclone issue.

---

## ✅ The Fix

I've updated CloudKlone so that **recurring** scheduled transfers:
- ✅ Stay as `status='scheduled'` after completion (success or fail)
- ✅ Keep their `next_run` time
- ✅ Appear in Scheduled tab
- ✅ Retry automatically at next scheduled time

**One-time** scheduled transfers still work as before:
- ✅ Change to `status='completed'` or `status='failed'` after running
- ✅ Don't retry (as expected for one-time jobs)

---

## 🚀 Deploy the Fix

```bash
# 1. Extract the fix
cd ~
tar -xzf cloudklone-v5-recurring-fix.tar.gz
cd cloudklone

# 2. Restart CloudKlone
sudo docker-compose restart app

# 3. Fix your existing failed transfer
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone << 'SQL'
UPDATE transfers 
SET status = 'scheduled' 
WHERE schedule_type = 'recurring' 
AND status = 'failed';
SQL

# 4. Verify
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "SELECT id, status, schedule_type, next_run FROM transfers WHERE schedule_type = 'recurring';"
```

---

## 📋 What You'll See

**Before fix:**
```
Scheduled tab: Empty (transfer disappeared)
Database: status='failed'
```

**After fix:**
```
Scheduled tab: Shows your daily transfer ✅
Database: status='scheduled'
Next run: 2/4/2026, 1:39:00 PM
```

---

## 🧪 Test It

1. Hard refresh browser: `Ctrl+Shift+R`
2. Go to **Scheduled** tab
3. Your daily transfer should be there now
4. Shows "Next Run: 2/4/2026, 1:39:00 PM"
5. When it runs and fails again (permission issue), it will:
   - Stay in Scheduled tab ✅
   - Calculate next run for tomorrow ✅
   - Try again automatically ✅

---

## 🎯 Quick Commands

```bash
# One-liner to deploy fix
cd ~ && tar -xzf cloudklone-v5-recurring-fix.tar.gz && cd cloudklone && sudo docker-compose restart app && sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "UPDATE transfers SET status = 'scheduled' WHERE schedule_type = 'recurring' AND status = 'failed';"

# Check it worked
sudo docker-compose exec postgres psql -U cloudklone_user -d cloudklone -c "SELECT id, status, schedule_type, next_run FROM transfers WHERE schedule_type = 'recurring';"
```

---

## 💡 What Changed in the Code

### Before:
```javascript
// Transfer fails
await pool.query(
  'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
  ['failed', errorMessage, transfer.transfer_id]  // Always 'failed'
);
```

### After:
```javascript
// Transfer fails - check if recurring
const isRecurringScheduled = transfer.schedule_type === 'recurring';
const finalStatus = isRecurringScheduled ? 'scheduled' : 'failed';

await pool.query(
  'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
  [finalStatus, errorMessage, transfer.transfer_id]  // 'scheduled' for recurring!
);
```

---

## ✅ All Fixes Included

This version has **everything**:

1. ✅ Timezone fix (12AM shows as 12AM)
2. ✅ Admin sees all scheduled jobs
3. ✅ Database renamed (cloudklone/cloudklone_user)
4. ✅ **Recurring transfers stay scheduled** ← NEW!

---

## 🎊 After the Fix

Your daily backup will:
- ✅ Show in Scheduled tab
- ✅ Run daily at 1:39 PM (your scheduled time)
- ✅ If it fails (permissions), stay scheduled
- ✅ Try again tomorrow automatically
- ✅ Keep trying until it succeeds

**This is how it should work!** 🚀
