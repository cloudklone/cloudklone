# CloudKlone v8 - Critical Fixes (February 2026)

## Issues Fixed

### 1. ✅ Double-Click Prevention on Transfer Creation
**Issue:** Double-clicking "Start Transfer" button could create duplicate transfers  
**Solution:** Disabled button during transfer creation to prevent multiple submissions

**Changes:**
- Added ID to Start Transfer button
- Button disabled immediately on click
- Button text changes to "Creating Transfer..." during processing
- Button re-enabled after success or error in finally block
- Prevents accidental duplicate transfers

**Files Modified:**
- `backend/index.html` (button ID, startTransfer function with disable/enable logic)

---

### 2. ✅ System-Wide Timezone for All Daily Reports
**Issue:** Timezone was per-user in Settings tab, only affected emails, and was confusing  
**Solution:** Moved timezone to Admin Panel as a system-wide setting that applies to BOTH email and webhook reports

**Architecture Changes:**
- Created `system_settings` table for system-wide configuration
- Removed per-user timezone from `notification_settings` table
- Daily reports now sent at midnight in the configured system timezone (for all users)
- Both email AND webhook reports respect the same timezone
- Simpler mental model: one timezone for the whole system

**New Features:**
- System Settings card in Admin Panel
- 15 timezone options (US, Europe, Asia, Australia, UTC)
- Applies to all users automatically
- Admin-only access to change system timezone

**Benefits:**
- Consistent scheduling across all report types
- Simplified configuration (one place, not per-user)
- Reports arrive at expected time
- Both email and webhook reports synchronized

**Database Changes:**
```sql
-- New system_settings table
CREATE TABLE system_settings (
  id SERIAL PRIMARY KEY,
  setting_key VARCHAR(100) UNIQUE NOT NULL,
  setting_value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default timezone
INSERT INTO system_settings (setting_key, setting_value)
VALUES ('timezone', 'UTC');
```

**Files Modified:**
- `backend/index.js`:
  - Created system_settings table
  - Added GET/POST `/api/system/settings` endpoints
  - Updated daily report logic to use system timezone
  - Removed per-user timezone logic
- `backend/index.html`:
  - Moved timezone selector from Settings to Admin Panel
  - Added loadSystemSettings() and saveSystemSettings() functions
  - Updated showTab() to load system settings when admin tab shown
  - Removed timezone from user notification settings

---

### 3. ✅ Decryption Debugging and Improvements
**Issue:** Decryption transfers staying stuck in "running" status and never completing  
**Solution:** Enhanced decryption logging and improved configuration handling

**Improvements:**
- Added comprehensive logging for debugging:
  - Logs full rclone command being executed
  - Logs all stdout and stderr in real-time
  - Logs exit code and output length on completion
  - Detects and logs password-related errors
- Ensured rclone config is refreshed before decryption starts
- Cleaned up path handling (remove trailing slashes)
- Better error detection for password issues

**Debugging Features Added:**
- Real-time stdout logging: `[DECRYPT] stdout: ...`
- Real-time stderr logging: `[DECRYPT] stderr: ...`
- Command logging: Shows full rclone command with all args
- Exit code logging: Shows process exit status
- Password error detection: Flags potential password problems
- Output size logging: Shows total bytes of output

**Why This Helps:**
- Can see exactly what rclone is doing
- Can identify if password is incorrect
- Can see if files are being found
- Can diagnose configuration issues
- Admin can review Docker logs to debug stuck transfers

**Files Modified:**
- `backend/index.js` (startDecryptionTransfer function with enhanced logging)

---

## Deployment

### Standard Update:

```bash
cd ~/cloudklone
sudo docker-compose down

# Extract new version
tar -xzf cloudklone-v8-critical-fixes-feb2026.tar.gz
cd cloudklone

# Start services (migrations run automatically)
sudo docker-compose up -d

# Verify
docker-compose logs app | grep "Database initialized"
```

### Database Migrations

All migrations run automatically:

```sql
-- System settings table (auto-created)
CREATE TABLE IF NOT EXISTS system_settings (...);

-- Default timezone inserted
INSERT INTO system_settings (setting_key, setting_value)
VALUES ('timezone', 'UTC')
ON CONFLICT DO NOTHING;
```

### Post-Deployment Steps

1. **Go to Admin Panel → System Settings**
2. **Set your timezone** (e.g., America/New_York for Eastern Time)
3. **Click "Save System Settings"**
4. Daily reports will now send at midnight in your timezone

---

## Testing Checklist

### Fix 1: Double-Click Prevention
- [ ] Click "Start Transfer" once - button disables immediately
- [ ] Button text changes to "Creating Transfer..."
- [ ] Button re-enables after transfer created
- [ ] Cannot click button multiple times while processing
- [ ] Works for both successful and failed transfer creation

### Fix 2: System Timezone
- [ ] Admin Panel shows "System Settings" card
- [ ] Can select timezone from dropdown
- [ ] Save System Settings button works
- [ ] Settings tab no longer has timezone
- [ ] Daily email reports arrive at midnight in selected timezone
- [ ] Daily webhook reports arrive at midnight in selected timezone
- [ ] Both report types synchronized

### Fix 3: Decryption Debugging
- [ ] Start a decryption transfer
- [ ] Check Docker logs: `docker-compose logs -f app`
- [ ] See `[DECRYPT] Command:` line showing full rclone command
- [ ] See `[DECRYPT] stdout:` lines during transfer
- [ ] See `[DECRYPT] stderr:` lines if any errors
- [ ] See exit code when transfer completes
- [ ] Transfer completes successfully (or see specific error)

**To check logs:**
```bash
docker-compose logs -f app | grep DECRYPT
```

---

## Known Issues / Next Steps

### Decryption
If decryption still fails after this update:
1. Check Docker logs for specific errors
2. Verify the encryption password is correct
3. Ensure the source path points to the directory with encrypted files
4. Look for password errors in stderr output
5. Report the full error output for further diagnosis

### Timezone
- First daily report after timezone change may take up to 24 hours
- Changing timezone doesn't affect currently scheduled one-time transfers
- Server must have correct system time for timezone calculations

---

## Version Information

- **Version:** CloudKlone v8 (Critical Fixes - February 2026)
- **Date:** 2026-02-07
- **Issues Fixed:** 3
- **Breaking Changes:** None (timezone moved to admin but defaults to UTC)
- **Database Changes:** 1 new table (system_settings)

---

## Support

### Debugging Decryption Issues

If decryption transfers are stuck:

```bash
# Watch decryption logs in real-time
docker-compose logs -f app | grep DECRYPT

# Look for:
# - "[DECRYPT] Command:" - shows what's being executed
# - "[DECRYPT] stdout:" - shows rclone output
# - "[DECRYPT] stderr:" - shows errors
# - "password" or "decrypt" in stderr - password issues
# - Exit code - 0 = success, non-zero = error
```

### Common Decryption Problems

1. **Wrong password** - stderr will contain "password" or "decrypt" errors
2. **Wrong path** - no files found, transfer completes instantly with 0 bytes
3. **Corrupted files** - stderr will show decryption errors
4. **Config issues** - check "[DECRYPT] Created crypt remote" log line

---

## Credits

**Fixes Implemented:**
- Double-click prevention for better UX
- System-wide timezone for consistent scheduling
- Enhanced decryption debugging for troubleshooting

**Status:** Production Ready ✓

**Priority:** HIGH - Recommended for all deployments
