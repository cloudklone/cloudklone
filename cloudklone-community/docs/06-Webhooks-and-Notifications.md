# Webhooks and Notifications

Get instant alerts and daily summaries of your transfer activity.

## What are Notifications?

CloudKlone can notify you about transfer activity through:
- **Email** - Daily summary reports
- **Webhooks** - Real-time alerts to other systems

Stay informed without checking the dashboard constantly!

## Email Notifications

### Daily Email Reports

Get a summary email every morning with:
- Yesterday's transfer count
- Success/failure statistics
- Total data transferred
- Failed transfers (with details)
- Scheduled transfer status

**Perfect for:** Morning review, team updates, record keeping

### Setting Up Email

**Step 1: Go to Settings**
1. Click **Settings** tab
2. Find "Daily Email Reports" section

**Step 2: Enable Email**
1. Check **☑ Enable Daily Email Reports**
2. Enter your **Email Address**
3. Click **Save Email Settings**

**Step 3: Configure SMTP** (Admin only)

If SMTP isn't configured, ask your administrator to set:
- SMTP Host (e.g., smtp.gmail.com)
- SMTP Port (usually 587 or 465)
- Username
- Password
- From Email

**Step 4: Test**
1. Click **Send Test Email**
2. Check your inbox
3. Verify email received

### Email Report Contents

**Subject:** CloudKlone Daily Report - Feb 9, 2024

**Body includes:**
```
📊 Transfer Summary (Feb 8, 2024)

✓ Completed: 15 transfers
✗ Failed: 2 transfers
📦 Total Data: 150 GB

Failed Transfers:
- backup-job: Access denied
- sync-website: Network timeout

Scheduled Jobs Status:
- All 5 recurring transfers ran successfully
```

**When sent:** Every day at 8:00 AM (server timezone)

## Webhooks

### What is a Webhook?

A webhook sends real-time notifications to a URL when events happen:
- Transfer completed
- Transfer failed
- Transfer started
- Error occurred

**Use webhooks to:**
- Integrate with Slack, Discord, Teams
- Trigger other automation
- Update dashboards
- Alert on-call staff

### Setting Up Webhooks

**Step 1: Get a Webhook URL**

Most services provide webhook URLs:

**Slack:**
1. Go to Slack settings
2. Create "Incoming Webhook"
3. Copy webhook URL

**Discord:**
1. Server Settings → Integrations → Webhooks
2. Create webhook
3. Copy URL

**Microsoft Teams:**
1. Channel → Connectors → Incoming Webhook
2. Configure
3. Copy URL

**Custom Service:**
- Use any HTTP endpoint that accepts POST requests

**Step 2: Add to CloudKlone**

1. Go to **Settings** tab
2. Find "Webhook Notifications"
3. Paste your **Webhook URL**
4. Click **Save Webhook**

**Step 3: Test**

1. Click **Test Webhook**
2. Check your Slack/Discord/Teams channel
3. You should see a test message

### Webhook Events

CloudKlone sends webhooks for:

**Transfer Complete** ✅
```json
{
  "event": "transfer_complete",
  "transfer_id": "abc-123",
  "source": "aws-s3:/data",
  "destination": "gdrive:/backup",
  "transferred": "25 GB",
  "duration": "15 minutes"
}
```

**Transfer Failed** ❌
```json
{
  "event": "transfer_failed",
  "transfer_id": "def-456",
  "source": "dropbox:/files",
  "destination": "s3:/archive",
  "error": "Access denied"
}
```

**Transfer Started** 🚀
```json
{
  "event": "transfer_started",
  "transfer_id": "ghi-789",
  "source": "local:/backup",
  "destination": "sftp:/remote"
}
```

## Popular Integrations

### Slack Integration

**Setup:**
1. Create Incoming Webhook in Slack
2. Add URL to CloudKlone
3. Choose channel for notifications

**Example notification:**
```
CloudKlone Notification

✅ Transfer Complete
Source: aws-s3:/customer-data
Destination: gdrive:/backup
Transferred: 50 GB
Duration: 30 minutes
```

**Tips:**
- Create dedicated #cloudklone channel
- Use @mentions for failures
- Pin important messages

### Discord Integration

**Setup:**
1. Server Settings → Webhooks → New Webhook
2. Name it "CloudKlone"
3. Select channel
4. Copy URL

**Example notification:**
```
🤖 CloudKlone Alert

❌ Transfer Failed
Job: nightly-backup
Error: Network timeout
Time: 2:30 AM

Action needed: Check network and retry
```

### Microsoft Teams

**Setup:**
1. Channel → ⋯ → Connectors
2. Configure "Incoming Webhook"
3. Name it and copy URL

**Cards display:**
- Transfer status
- Duration
- Data amount
- Next steps

### Custom Integrations

**Your own API:**
```python
# Python example endpoint
@app.post('/cloudklone-webhook')
def handle_webhook(data):
    if data['event'] == 'transfer_failed':
        # Send alert to on-call
        alert_oncall(data['error'])
    elif data['event'] == 'transfer_complete':
        # Update dashboard
        update_metrics(data)
    return {'status': 'ok'}
```

## Notification Best Practices

### Email

✅ **Use for:**
- Daily summaries
- Team updates
- Weekly review prep
- Record keeping

❌ **Don't use for:**
- Real-time alerts (too slow)
- Critical failures (use webhooks)
- High-frequency notifications

### Webhooks

✅ **Use for:**
- Instant alerts
- Critical failures
- Integration with other tools
- Real-time dashboards

❌ **Don't use for:**
- Every single transfer (too noisy)
- Non-critical events
- When email is sufficient

### Notification Fatigue

**Problem:** Too many notifications = ignore them all

**Solutions:**
- Only webhook on failures for recurring transfers
- Email daily summaries instead of per-transfer
- Use filters to send critical only
- Group similar events
- Schedule quiet hours

## Troubleshooting

### Email Not Received

**Check spam folder**
- Email might be filtered
- Mark as "Not Spam"
- Add sender to contacts

**Verify SMTP settings**
- Ask admin to check configuration
- Test with Gmail/Outlook first
- Check SMTP credentials

**Check email address**
- Typo in address?
- Update and retry
- Send test email

### Webhook Not Working

**Test the webhook URL**
```bash
# Test with curl
curl -X POST YOUR_WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{"test": "message"}'
```

**Check URL format**
- Must start with http:// or https://
- No trailing spaces
- Copy/paste to avoid typos

**Verify service is running**
- Check Slack/Discord/Teams
- Webhook still enabled?
- Service not down?

**Check CloudKlone logs**
- Go to **Logs** tab
- Look for webhook errors
- Shows delivery status

### Duplicate Notifications

**Cause:** Multiple webhooks configured

**Solution:**
- Check Settings for duplicate URLs
- Remove old webhooks
- Keep only one active

## Advanced Configurations

### Filtering Events

**Only notify on failures:**
- Most services let you filter on webhook side
- Check if event == "transfer_failed"
- Ignore success events

### Routing to Different Channels

**By severity:**
- Failures → #alerts channel
- Success → #cloudklone channel
- Daily reports → #backups channel

**By source:**
- Production transfers → #production
- Development transfers → #dev
- Archives → #archives

### Custom Messages

**Slack example:**
```javascript
// Custom Slack message formatting
{
  "text": "CloudKlone Alert",
  "attachments": [{
    "color": "danger",  // red for failures
    "title": "Transfer Failed",
    "fields": [
      {"title": "Source", "value": "aws-s3:/data"},
      {"title": "Error", "value": "Access denied"},
      {"title": "Time", "value": "2:30 AM"}
    ]
  }]
}
```

## Email Template Customization

**Default template includes:**
- Date range
- Transfer counts
- Data transferred
- Failed transfer details
- Scheduled job status

**Want custom format?**
- Contact administrator
- Provide desired format
- Admin can modify template

## Security Considerations

### Webhook URLs

⚠️ **Keep webhook URLs private!**
- Anyone with URL can send fake notifications
- Don't commit to git repositories
- Don't share publicly
- Rotate if compromised

### Email Privacy

✅ **Best practices:**
- Use distribution lists for teams
- Don't expose personal emails
- Configure proper SPF/DKIM
- Enable TLS for SMTP

## Quick Reference

| Task | Steps |
|------|-------|
| Enable email reports | Settings → Check "Enable Daily Email" → Save |
| Set up webhook | Settings → Enter Webhook URL → Test → Save |
| Test email | Settings → Click "Send Test Email" |
| Test webhook | Settings → Click "Test Webhook" |
| Update email address | Settings → Change email → Save |
| Remove webhook | Settings → Clear URL → Save |

## Notification Checklist

**For Email:**
- [ ] Email address entered
- [ ] SMTP configured (admin)
- [ ] Test email received
- [ ] Check spam folder
- [ ] Saved settings

**For Webhooks:**
- [ ] Webhook URL created
- [ ] URL pasted in CloudKlone
- [ ] Test webhook sent
- [ ] Message received
- [ ] Format looks good
- [ ] Saved settings

---

**Remember:** Start with daily emails for awareness, add webhooks only for critical alerts. Less is more when it comes to notifications!
