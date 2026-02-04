# CloudKlone v3 - Complete Update

## 🎉 What's New

### 1. ✅ Transfer Scheduling
Schedule transfers to run automatically at specific times or on recurring intervals.

**One-Time Transfers:**
- Select a specific date and time
- Transfer runs once at that time
- Perfect for planned migrations

**Recurring Transfers:**
- **Hourly**: Every hour
- **Daily**: Once per day at specified time
- **Weekly**: Once per week at specified time
- **Monthly**: Once per month at specified time

**How to Use:**
1. Fill in transfer details (source/destination)
2. Check "Schedule this transfer"
3. Choose "Run once" or "Run on repeat"
4. Set date/time or interval
5. Click "Start Transfer"

**Monitoring:**
- Scheduled transfers show "SCHEDULED" badge
- Next run time displayed
- View in History tab
- Runs automatically in background

---

### 2. ✅ Cleaner UI - Logo Removed
Removed the logo image from login and sidebar for a cleaner, less cluttered interface.

**Benefits:**
- More screen space for content
- Faster page load
- Minimalist aesthetic matches Claude's design
- Focus on functionality

---

### 3. ✅ Enhanced Transfer Monitoring
Real-time progress updates with detailed status messages.

**Improvements:**
- **Immediate feedback**: "Starting transfer..." appears instantly
- **Scanning phase**: "Scanning files..." when rclone is checking
- **Real-time updates**: Progress updates every second
- **Detailed logging**: All rclone output logged to console for debugging
- **Better error messages**: Actual rclone errors shown, not generic messages

**Status Timeline:**
1. **"Starting transfer..."** (0-5 seconds)
2. **"Scanning files..."** (5-60 seconds) - rclone is checking source/dest
3. **"15.2 MiB @ 5.3 MiB/s"** (during transfer) - actual progress
4. **"Completed"** or detailed error message

**For Your 730KB Transfer:**
The transfer likely completed but you weren't seeing progress updates. Now you'll see:
- Initial "Starting..." immediately
- "Scanning..." within 10 seconds
- Real progress within 30 seconds
- Or detailed error if something failed

---

## 🔧 Technical Improvements

### Database Changes
Added scheduling columns to `transfers` table:
- `scheduled_for` - One-time execution timestamp
- `schedule_type` - 'once' or 'recurring'
- `schedule_interval` - 'hourly', 'daily', 'weekly', 'monthly'
- `last_run` - When it last executed
- `next_run` - When it will execute next
- `enabled` - Toggle to pause/resume

### Backend Changes
1. **node-cron integration** - Checks for scheduled transfers every minute
2. **Improved rclone monitoring** - Captures stdout AND stderr with verbose logging
3. **Better progress parsing** - Handles "Checking:", "Transferring:", and all rclone output formats
4. **Initial status updates** - Shows "Starting..." and "Scanning..." before progress begins
5. **Console logging** - All rclone output logged with `[transfer_id]` prefix

### Frontend Changes
1. **Scheduling UI** - Collapsible section with date/time pickers
2. **Status badges** - Added "SCHEDULED" status with yellow color
3. **Next run display** - Shows when scheduled transfers will execute
4. **Logo removal** - Cleaner headers and login page

---

## 🚀 Deployment

### Quick Update
```bash
cd ~/cloudklone
sudo docker-compose down
cd ~
tar -xzf cloudklone-final.tar.gz
cd cloudklone
sudo docker-compose up -d --build
sudo docker-compose logs -f
```

### Fresh Install
```bash
tar -xzf cloudklone-final.tar.gz
cd cloudklone
sudo docker-compose up -d
sudo docker-compose logs -f
```

**Important**: The `--build` flag rebuilds the container with the new `node-cron` dependency.

---

## 📊 Viewing Logs

To see real-time transfer progress in console:
```bash
sudo docker-compose logs -f app
```

Look for lines like:
```
[abc-123-def] Transfer started
[abc-123-def] rclone stderr: Transferred: 15.2 MiB / 730 KiB, 100%, ...
[abc-123-def] Progress: 730 KiB (100%) @ 5.3 MiB/s
```

---

## 🐛 Troubleshooting Slow Transfers

If a transfer shows "running" with no progress:

### 1. Check Console Logs
```bash
sudo docker-compose logs app | grep "transfer_id"
```

### 2. Common Causes
- **Authentication issues**: Remote credentials invalid
- **Network issues**: Can't reach remote server
- **Large file scan**: Rclone scanning thousands of files
- **Slow remote**: Some remotes take time to respond

### 3. What You'll See Now
Instead of stuck "running" status, you'll see:
- "Starting transfer..." (first 5 seconds)
- "Scanning files..." (next 10-60 seconds)
- Actual progress or specific error message

### 4. Real Progress Example
```
Transfer Status: RUNNING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 45%

730 KiB transferred        5.3 MiB/s        ETA: 2m 15s
```

---

## 🎯 Scheduling Examples

### Example 1: Nightly Backup
```
Operation: Copy
Source: prod-db:/backups
Destination: b2-archive:/daily
Schedule: Recurring - Daily at 02:00
```

### Example 2: Weekly Sync
```
Operation: Sync
Source: aws-s3:/photos
Destination: wasabi:/photo-backup
Schedule: Recurring - Weekly at 00:00
```

### Example 3: One-Time Migration
```
Operation: Copy
Source: old-nas:/data
Destination: new-s3:/data
Schedule: Once - 2026-02-05 14:30
```

### Example 4: Hourly Incremental
```
Operation: Copy
Source: app-logs:/current
Destination: archive:/logs
Schedule: Recurring - Hourly
```

---

## 📈 Monitoring Scheduled Transfers

### In Transfers Tab
- Shows "SCHEDULED" badge
- Displays next run time
- Shows schedule type (once/recurring)

### In History Tab
- See all past executions
- Filter by status
- Track success/failure rate
- View transfer history

### Via Logs
```bash
# Watch for scheduled execution
sudo docker-compose logs -f app | grep "Executing scheduled transfer"
```

---

## ⚙️ Advanced: Disable/Enable Scheduled Transfers

Currently scheduled transfers run automatically. To pause one:

1. Go to History tab
2. Find the scheduled transfer
3. Delete it to stop future runs
4. Recreate with new schedule when ready

**Coming Soon**: Toggle to pause/resume scheduled transfers without deleting.

---

## 🎨 UI Improvements Summary

**Before:**
- Logo cluttering header and login
- Transfers showing "running" with no info
- No scheduling capability

**After:**
- Clean, minimalist interface
- Real-time progress with detailed status
- Full scheduling system
- Better error messages
- Professional appearance

---

## 📝 Notes

### Scheduling Precision
- Checked every 1 minute
- May run up to 60 seconds late
- Adequate for most backup/sync scenarios
- Use cron on host for second-precision needs

### Transfer Status Flow
```
SCHEDULED → QUEUED → RUNNING → COMPLETED/FAILED
                              ↓
                    (recurring: back to SCHEDULED)
```

### Database Migration
The new columns are added automatically on startup. Existing transfers are unaffected.

---

## 🎯 What's Fixed

1. ✅ **Scheduling**: One-time and recurring transfers
2. ✅ **Logo removal**: Cleaner UI
3. ✅ **Progress visibility**: Real-time status updates
4. ✅ **Better logging**: All rclone output captured
5. ✅ **Error messages**: Actual errors shown, not generic
6. ✅ **Initial feedback**: Immediate status on transfer start

---

## 🚀 Next Steps

After deploying, try:
1. Create a small test transfer to see new progress updates
2. Schedule a test transfer for 2 minutes from now
3. Check console logs to see detailed output
4. View History tab to see all transfers

Your 730KB transfer issue should be resolved - you'll now see exactly what's happening during the transfer! 🎉
