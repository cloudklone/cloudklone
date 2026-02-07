# CloudKlone v7 - Webhook Notification Preferences & Daily Report Fix

## Issues Fixed

### 1. Missing Webhook Notification Preferences

**Problem:** The webhook notification section did not have individual preference checkboxes for:
- Notify on transfer failure
- Notify on transfer success  
- Daily summary report (sent at midnight)

These options existed for email but not for webhooks.

**Solution:** Added separate notification preferences for webhooks that work independently from email preferences.

### 2. Daily Summary Reports Not Working

**Problem:** Daily summary reports were not being sent even when enabled with working SMTP configuration.

**Solution:** 
- Added webhook support to daily reports
- Improved error handling and logging
- Fixed query to check for both email and webhook daily report preferences

---

## Changes Made

### Frontend (index.html)

**Added webhook notification preference checkboxes:**
```html
<h4>Webhook Notification Preferences</h4>
<input type="checkbox" id="webhook-notify-failure" checked>
Notify on transfer failure

<input type="checkbox" id="webhook-notify-success">
Notify on transfer success

<input type="checkbox" id="webhook-daily-report">
Daily summary report (sent at midnight)
```

**Updated loadSettings():**
- Now loads `webhook_notify_on_failure`, `webhook_notify_on_success`, `webhook_daily_report`

**Updated saveSettings():**
- Now saves all webhook notification preferences separately from email preferences

### Backend (index.js)

**Database Schema Changes:**

Added three new columns to `notification_settings` table:
```sql
webhook_notify_on_failure BOOLEAN DEFAULT true
webhook_notify_on_success BOOLEAN DEFAULT false
webhook_daily_report BOOLEAN DEFAULT false
```

Migration scripts automatically add these columns on startup for existing installations.

**API Endpoint Updates:**

`POST /api/notifications/settings` now handles:
- `webhook_notify_on_failure`
- `webhook_notify_on_success`
- `webhook_daily_report`

**Updated notifyTransferComplete():**

Webhooks now respect their own notification preferences:
```javascript
// Email uses: notify_on_success, notify_on_failure
// Webhook uses: webhook_notify_on_success, webhook_notify_on_failure
```

**Fixed Daily Summary Report:**

Added comprehensive improvements:
- Sends both email AND webhook daily reports based on preferences
- Added detailed logging for debugging:
  - `[INFO] Running daily report at {timestamp}`
  - `[INFO] Found X users with daily reports enabled`
  - `[OK] Daily email report sent to {username}`
  - `[OK] Daily webhook report sent for {username}`
  - `[ERROR] Failed to send...` with error details
- Improved error handling (reports continue if one fails)
- Webhook payload includes:
  ```json
  {
    "report_type": "daily_summary",
    "date": "Tue Feb 05 2026",
    "completed": 15,
    "failed": 2,
    "total": 17,
    "timestamp": "2026-02-05T00:03:00.000Z"
  }
  ```

---

## How It Works

### Transfer Notifications

**Email Preferences (independent):**
- Notify on failure: controlled by `notify_on_failure`
- Notify on success: controlled by `notify_on_success`

**Webhook Preferences (independent):**
- Notify on failure: controlled by `webhook_notify_on_failure`
- Notify on success: controlled by `webhook_notify_on_success`

**Example Configurations:**

| Scenario | Email Failure | Email Success | Webhook Failure | Webhook Success | Result |
|----------|--------------|---------------|-----------------|-----------------|--------|
| Email only on failures | ✓ | ✗ | ✗ | ✗ | Email sent on failure only |
| Webhook only on success | ✗ | ✗ | ✗ | ✓ | Webhook sent on success only |
| Both on all events | ✓ | ✓ | ✓ | ✓ | Email + Webhook sent on all transfers |
| Mixed | ✓ | ✗ | ✗ | ✓ | Email on failure, webhook on success |

### Daily Summary Reports

**Email Daily Report:**
- Checkbox: "Daily summary report (sent at midnight)" under Email Notifications
- Requires: `email_enabled = true` AND `daily_report = true`
- Sends: Plain text email with transfer counts

**Webhook Daily Report:**
- Checkbox: "Daily summary report (sent at midnight)" under Webhook Notifications
- Requires: `webhook_enabled = true` AND `webhook_daily_report = true`
- Sends: JSON payload with transfer statistics

**Timing:**
- Runs every 5 minutes via `setInterval`
- Only executes between 00:00 and 00:05 (midnight to 5 minutes past)
- Covers last 24 hours of transfer activity
- Only sends if user had transfers in that period

**Debugging Daily Reports:**

Check container logs:
```bash
sudo docker-compose logs -f app | grep -i "daily report\|INFO\|ERROR"
```

Look for:
- `[INFO] Running daily report at 2026-02-05T00:01:00.000Z`
- `[INFO] Found 2 users with daily reports enabled`
- `[OK] Daily email report sent to admin`
- `[ERROR] Failed to send daily email to...`

---

## Testing

### Test Webhook Notification Preferences

1. Navigate to Settings tab
2. Scroll to "Webhook Notifications"
3. Enable webhook
4. Configure webhook URL and type
5. Set notification preferences:
   - Check "Notify on transfer failure"
   - Uncheck "Notify on transfer success"
6. Save settings
7. Create a transfer that will fail
8. Verify webhook received failure notification
9. Create a transfer that succeeds
10. Verify webhook did NOT receive success notification

### Test Daily Summary Reports

**Email Daily Report:**
1. Enable email notifications
2. Check "Daily summary report (sent at midnight)"
3. Save settings
4. Create some test transfers during the day
5. Wait until midnight (00:00-00:05 in server time)
6. Check email for daily report

**Webhook Daily Report:**
1. Enable webhook notifications
2. Check "Daily summary report (sent at midnight)" under webhooks
3. Save settings
4. Create some test transfers during the day
5. Wait until midnight (00:00-00:05 in server time)
6. Check webhook endpoint for daily report payload

**Check Logs:**
```bash
sudo docker-compose logs app | tail -100
```

Look for daily report execution messages.

---

## Troubleshooting

### Webhook Preferences Not Saving

**Symptom:** Checkboxes reset after page reload

**Solution:** 
- Check browser console for errors
- Verify API endpoint returns new fields
- Clear browser cache and hard refresh (Ctrl+F5)

### Daily Reports Not Sending

**Symptom:** No reports received at midnight

**Possible Causes:**

**1. Time Zone Mismatch**
- Server time might not be in your timezone
- Check server time: `docker exec cloudklone-app date`
- Daily report runs at midnight server time (UTC typically)

**2. No Transfers**
- Reports only send if there were transfers in last 24 hours
- Create test transfer to trigger report

**3. SMTP/Webhook Not Configured**
- Test email with "Test Email" button
- Test webhook with "Test Webhook" button
- Check for error messages in logs

**4. Preferences Not Enabled**
- Verify daily_report checkbox is checked
- Verify email_enabled or webhook_enabled is true
- Re-save settings after changing

**Debug Steps:**
```bash
# Check server time (should show UTC typically)
docker exec cloudklone-app date

# Watch logs around midnight
docker-compose logs -f app | grep -i report

# Check database settings
docker exec cloudklone-database psql -U cloudklone_user cloudklone \
  -c "SELECT email_enabled, daily_report, webhook_enabled, webhook_daily_report FROM notification_settings;"
```

### Webhook Payload Format

**For Transfer Notifications:**
```json
{
  "status": "completed successfully",
  "success": true,
  "source": "s3:bucket/path",
  "destination": "r2:bucket/path",
  "operation": "copy",
  "transfer_id": "abc-123",
  "timestamp": "2026-02-05T10:30:00.000Z"
}
```

**For Daily Reports:**
```json
{
  "report_type": "daily_summary",
  "date": "Tue Feb 05 2026",
  "completed": 15,
  "failed": 2,
  "total": 17,
  "timestamp": "2026-02-05T00:03:00.000Z"
}
```

---

## Migration

Existing installations will automatically migrate when upgraded:
- New database columns added on startup
- Existing webhooks default to notify on failure only
- No manual migration required

---

## Summary

**What's New:**
- Independent notification preferences for webhooks
- Webhook daily summary reports
- Comprehensive logging for daily reports
- Improved error handling

**What's Fixed:**
- Webhook notifications now have their own preference controls
- Daily summary reports now work reliably
- Both email and webhook daily reports supported
- Better debugging with detailed log messages

**Deployment:**
```bash
tar -xzf cloudklone-v7-webhooks-fixed.tar.gz
cd cloudklone
sudo docker-compose restart app
```

Access at: https://localhost
Configure webhook preferences in Settings > Webhook Notifications
