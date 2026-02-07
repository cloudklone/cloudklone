# CloudKlone v8 - February 2026 Updates

## Changes Implemented

### 1. ✅ Egress Warning Updated
**Issue:** Pricing information in egress warnings required constant maintenance  
**Solution:** Removed exact pricing from cloud egress warnings, replaced with generic warning that directs users to consult their provider's pricing documentation

**Changes:**
- Updated egress cost warning dialog in transfer creation
- Removed specific dollar amounts for S3, GCS, and Azure
- Kept warning about providers that charge vs. those that don't (R2, B2)
- Added note directing users to check their provider's current pricing

**Files Modified:**
- `backend/index.html` (egress warning dialog in transfer creation form)

---

### 2. ✅ Dark Mode / Light Mode Toggle
**Issue:** Users requested ability to switch between dark and light themes  
**Solution:** Implemented theme toggle with localStorage persistence

**Features:**
- Theme toggle button in sidebar (above logout button)
- Light mode color scheme with appropriate contrast
- Theme preference saved to localStorage
- Smooth theme switching without page reload
- Button updates to show current mode

**Changes:**
- Added light mode CSS variables (`[data-theme="light"]`)
- Added theme toggle button in sidebar footer
- Added `toggleTheme()` JavaScript function
- Added theme initialization on page load

**Files Modified:**
- `backend/index.html` (CSS variables, sidebar footer, JS functions)

---

### 3. ✅ Timezone Support for Daily Reports
**Issue:** Daily reports sent at midnight UTC instead of user's local time, causing confusion (e.g., midnight scheduled but arrives at 5pm)  
**Solution:** Added per-user timezone selection with timezone-aware report scheduling

**Features:**
- Timezone dropdown in notification settings with 15 common timezones
- Daily reports sent at midnight in user's selected timezone
- Prevents duplicate reports with `last_report_sent` tracking
- Supports all IANA timezone identifiers
- Defaults to UTC if not set

**Changes:**
- Added `timezone` column to `notification_settings` table (default: 'UTC')
- Added `last_report_sent` column to track report delivery
- Added timezone selector dropdown in Settings tab
- Updated daily report logic to check each user's local time
- Updated notification settings endpoints to save/load timezone

**Available Timezones:**
- US: Eastern, Central, Mountain, Pacific, Alaska, Hawaii
- Europe: London, Paris, Berlin
- Asia: Tokyo, Shanghai, Dubai
- Australia: Sydney
- UTC

**Files Modified:**
- `backend/index.js` (database migrations, notification endpoints, daily report logic)
- `backend/index.html` (timezone selector, loadSettings, saveSettings)

---

### 4. ✅ Decryption File Path Fix
**Issue:** Decrypting encrypted files failed with "file not found" errors when users entered encrypted filenames  
**Solution:** Improved decryption logic to automatically handle encrypted directory paths and detect individual file references

**The Problem:**
When files are encrypted, their names become random strings like `g3k8sjf9k2jd9...`. Users tried to enter these encrypted filenames in the source path, but rclone's crypt remote needs to point to the DIRECTORY containing encrypted files, not individual files.

**The Fix:**
- Automatically detects if source path looks like a file (has extension or long random string)
- Strips filename and uses parent directory for crypt remote
- Added intelligent path handling for encrypted content
- Added clear UI guidance explaining to use directory paths

**Features:**
- Smart path detection: removes filenames from paths automatically
- Better logging showing adjusted paths
- Updated decrypt UI with clear instructions
- Explains not to enter individual encrypted filenames

**Files Modified:**
- `backend/index.js` (`startDecryptionTransfer` function - lines ~3306-3350)
- `backend/index.html` (decrypt tab UI guidance)

---

## Database Migrations

All migrations run automatically on container startup:

```sql
-- Timezone support
ALTER TABLE notification_settings ADD COLUMN timezone VARCHAR(50) DEFAULT 'UTC';

-- Track last report sent date
ALTER TABLE notification_settings ADD COLUMN last_report_sent VARCHAR(50);
```

---

## Deployment

### Standard Update:

```bash
cd ~/cloudklone
sudo docker-compose down

# Extract new version
tar -xzf cloudklone-v8-feb2026-updates.tar.gz
cd cloudklone

# Start services (migrations run automatically)
sudo docker-compose up -d

# Verify
docker-compose logs app | grep "Database initialized"
```

### What Gets Updated:
- All four fixes applied
- Database automatically migrated
- No manual intervention required
- All existing data preserved

---

## Testing Checklist

### Egress Warning:
- [ ] Transfer from S3 shows generic warning (no pricing)
- [ ] Transfer from GCS shows generic warning (no pricing)
- [ ] Transfer from Azure shows generic warning (no pricing)
- [ ] Warning mentions Cloudflare R2 and Backblaze B2 have no fees
- [ ] Session dismissal still works

### Theme Toggle:
- [ ] Theme toggle button visible in sidebar
- [ ] Clicking button switches between light and dark
- [ ] Button text updates (🌙 Dark Mode / ☀️ Light Mode)
- [ ] Theme persists after page reload
- [ ] Light mode is readable and has good contrast
- [ ] Dark mode still works as before

### Timezone:
- [ ] Timezone dropdown appears in Settings tab
- [ ] Can select different timezones
- [ ] Timezone saves successfully
- [ ] Daily report sends at midnight in selected timezone
- [ ] No duplicate reports on same day
- [ ] Different users can have different timezones

### Decryption:
- [ ] Can decrypt files encrypted in previous transfers
- [ ] Entering encrypted filename still works (auto-adjusted)
- [ ] Entering directory path works
- [ ] Leaving path blank decrypts everything
- [ ] Password test function works
- [ ] Decrypted files appear correctly

---

## Version Information

- **Version:** CloudKlone v8 (February 2026 Update)
- **Date:** 2026-02-07
- **Issues Fixed:** 4
- **Breaking Changes:** None
- **Database Changes:** 2 new columns (auto-migrated)

---

## Known Issues / Limitations

### Timezone:
- First daily report after timezone change may take up to 24 hours
- Timezone changes won't affect in-progress report scheduling
- Server must have correct time/date for timezone calculations to work

### Decryption:
- Path detection uses heuristics (checks for extensions or long strings)
- Users should still prefer directory paths over file paths
- Encrypted directory names are not human-readable

---

## Support

If you encounter issues:

1. Check Docker logs: `docker-compose logs app`
2. Verify database migration: `docker-compose logs app | grep "notification_settings"`
3. Check timezone setting in Settings tab
4. Review audit logs for failed operations
5. Test with simple transfers first

---

## Credits

**Fixes Implemented:**
- Egress pricing removal for maintainability
- Dark/light mode toggle for accessibility  
- Timezone support for accurate scheduling
- Decryption path handling for usability

**Status:** Production Ready ✓
