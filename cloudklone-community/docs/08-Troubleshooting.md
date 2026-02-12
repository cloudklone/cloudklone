# Troubleshooting Guide

Common problems and how to solve them quickly.

## General Troubleshooting Steps

When something goes wrong:

1. **Check the error message** - Read what it says
2. **Review logs** - Go to Logs tab for details
3. **Test remotes** - Verify connections work
4. **Check history** - See if it worked before
5. **Try again** - Sometimes temporary issues resolve

## Login Issues

### Cannot Login

**Symptom:** Login fails with "Invalid credentials"

**Causes:**
- Wrong username or password
- Account disabled
- Caps Lock on

**Solutions:**
✅ Double-check username and password  
✅ Try copy/paste to avoid typos  
✅ Check Caps Lock is off  
✅ Contact administrator to verify account  

### Locked Out

**Symptom:** Account locked after failed attempts

**Solutions:**
- Wait 30 minutes for automatic unlock
- Contact administrator for manual unlock
- Reset password if forgotten

### Page Won't Load

**Symptom:** Blank screen or loading forever

**Solutions:**
✅ Refresh browser (Ctrl+F5 or Cmd+Shift+R)  
✅ Clear browser cache  
✅ Try different browser  
✅ Check internet connection  
✅ Verify CloudKlone server is running  

## Remote Issues

### Remote Test Fails

**Symptom:** "Test failed" when testing remote

**Common Causes & Solutions:**

**Access Denied**
```
Cause: Wrong credentials
Fix: Update API key/password
Test: Use provider's console to verify credentials
```

**Network Timeout**
```
Cause: Network connectivity issue
Fix: Check internet connection
Test: Try accessing provider's website
```

**Invalid Region**
```
Cause: Wrong region/endpoint
Fix: Verify region matches your bucket/storage
Example: us-east-1 vs us-west-2
```

**Quota Exceeded**
```
Cause: Storage limit reached
Fix: Free up space or increase quota
Check: Provider's console for usage
```

**Service Unavailable**
```
Cause: Provider having issues
Fix: Check provider's status page
Wait: Retry in a few minutes
```

### Cannot Delete Remote

**Symptom:** Error when trying to delete remote

**Cause:** Remote is being used in transfers

**Solution:**
1. Go to **Transfers** tab
2. Cancel active transfers using this remote
3. Go to **Scheduled** tab
4. Delete or update scheduled transfers
5. Then delete the remote

### Remote Suddenly Stopped Working

**Symptom:** Was working, now fails

**Common Causes:**

**Expired Token**
```
Solution: Regenerate OAuth token
Where: Provider's developer console
Update: Edit remote with new token
```

**Changed Credentials**
```
Solution: Update password/key
Where: Edit remote configuration
Test: Verify with provider first
```

**Provider Changed API**
```
Solution: Check for CloudKlone updates
Contact: Administrator for latest version
```

## Transfer Issues

### Transfer Stuck at 0%

**Symptom:** Transfer starts but never progresses

**Causes:**
- Source path empty or wrong
- Network connectivity issue
- Remote credentials expired
- Firewall blocking

**Solutions:**
✅ Verify source path has files (use Tests & Queries)  
✅ Check network connection  
✅ Test both remotes  
✅ Cancel and restart transfer  
✅ Check logs for specific error  

### Very Slow Transfer

**Symptom:** Transfer taking much longer than expected

**Causes:**
- Many small files
- Provider rate limiting
- Network congestion
- Cross-region transfer

**Solutions:**
✅ Check "Avg Speed" in dashboard  
✅ Compare to previous transfers  
✅ Try during off-peak hours  
✅ Compress files before transfer  
✅ Check provider's rate limits  

**Speed Expectations:**
- Small files (1000s): 5-20 MB/s
- Large files: 50-200 MB/s
- Same region: Faster
- Cross-region: Slower

### Transfer Failed

**Symptom:** Red "failed" status in History

**Check Error Message:**

**"Access Denied"**
```
Fix: Update remote credentials
Verify: Permissions on both source and destination
Test: Both remotes independently
```

**"Network Timeout"**
```
Fix: Check internet connection
Retry: During better network time
Reduce: Batch size if very large
```

**"Quota Exceeded"**
```
Fix: Free up space at destination
Check: Storage limits in provider console
Alternative: Use different destination
```

**"Path Not Found"**
```
Fix: Verify source path exists
Use: Tests & Queries to browse
Correct: Path in transfer settings
```

**"Too Many Requests"**
```
Cause: Provider rate limiting
Fix: Wait a few minutes
Retry: With delays between files
Schedule: During off-peak hours
```

### Partial Transfer

**Symptom:** Some files transferred, some didn't

**Solutions:**
1. Check **History** for error details
2. Note which files failed
3. Fix the issue (permissions, space, etc.)
4. Re-run transfer (Copy skips existing files)

### Destination Empty After Sync

**Symptom:** Ran sync but destination is empty

**Cause:** Source path was wrong (probably empty)

**Solution:**
1. Verify source path with Tests & Queries
2. Use `ls` to see what's actually there
3. Correct the source path
4. Re-run the sync

**Prevention:** Always test paths with Copy first!

## Scheduled Transfer Issues

### Schedule Didn't Run

**Symptom:** Scheduled transfer didn't execute

**Checks:**

**Is it Enabled?**
```
Go to: Scheduled tab
Look for: Green "Active" badge
Fix: Click "Enable" if disabled
```

**Was Server Down?**
```
Check: With administrator
Verify: Server uptime
Note: Missed schedules don't retry
```

**Next Run Time Correct?**
```
Check: "Next run" time shown
Verify: Timezone settings
Compare: To your local time
```

**Remote Still Working?**
```
Test: Both remotes
Verify: Credentials valid
Update: If needed
```

### Wrong Time Execution

**Symptom:** Schedule runs at unexpected time

**Cause:** Timezone difference

**Solution:**
1. Check server timezone (Settings tab → System Settings)
2. Calculate correct time for that timezone
3. Update schedule accordingly

**Example:**
```
Your time: 2:00 AM EST
Server timezone: UTC
Correct schedule: 7:00 AM UTC
```

### Schedule Failed

**Symptom:** Schedule ran but transfer failed

**Solution:**
1. Check **History** for error
2. Fix the underlying issue
3. Schedule will retry next time
4. Or disable and fix before re-enabling

## Notification Issues

### Not Receiving Emails

**Checks:**

**Spam Folder**
```
Check: Spam/junk folder
Action: Mark as "Not Spam"
Add: Sender to contacts
```

**Email Address**
```
Verify: No typos in address
Test: Send test email
Update: If incorrect
```

**SMTP Configuration**
```
Contact: Administrator
Verify: SMTP settings correct
Test: With test email button
```

**Daily Report Time**
```
Note: Reports sent at 8:00 AM server time
Check: Server timezone
Calculate: When you'll receive it
```

### Webhook Not Working

**Checks:**

**URL Format**
```
Must: Start with http:// or https://
No: Trailing spaces
Copy: Carefully to avoid typos
```

**Service Status**
```
Check: Slack/Discord/Teams working?
Verify: Webhook still enabled
Test: With webhook test button
```

**CloudKlone Logs**
```
Go to: Logs tab
Look for: Webhook delivery errors
Read: Error messages
```

**Test Manually**
```bash
curl -X POST YOUR_WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{"test": "message"}'
```

## Performance Issues

### Dashboard Slow to Load

**Solutions:**
✅ Clear browser cache  
✅ Disable browser extensions  
✅ Try different browser  
✅ Check internet speed  
✅ Close other tabs  

### Transfers List Not Updating

**Symptom:** Active transfers don't show progress

**Solutions:**
✅ Refresh page (F5)  
✅ Check browser console for errors (F12)  
✅ Verify WebSocket connection  
✅ Clear browser cache  
✅ Try different browser  

### Queries Taking Forever

**Symptom:** Tests & Queries timeout or very slow

**Causes:**
- Very large directory
- Slow remote
- Network issues

**Solutions:**
✅ Use more specific path  
✅ Try smaller subdirectory  
✅ Check network connection  
✅ Wait patiently for large operations  

## Data Issues

### Files Missing After Transfer

**Investigation:**

**Step 1: Check History**
```
Status: Did transfer complete successfully?
Error: Any error messages?
Data: How much was transferred?
```

**Step 2: Verify Destination**
```
Use: Tests & Queries
Command: lsf on destination path
Compare: File count to source
```

**Step 3: Check Logs**
```
Go to: Logs tab
Search: For this transfer
Look for: File-specific errors
```

**Step 4: Test Manually**
```
Try: Manual copy of one file
Verify: It appears at destination
```

### Files Duplicated

**Symptom:** Same files appear multiple times

**Cause:** Ran Copy multiple times to same destination

**Solution:**
- Copy operation doesn't overwrite by default
- Use Sync to remove duplicates
- Or manually clean up destination

### Wrong Files Transferred

**Symptom:** Unexpected files at destination

**Causes:**
- Wrong source path
- Used Sync instead of Copy
- Path included more than expected

**Solutions:**
1. Verify source path in History
2. Use Tests & Queries to browse source
3. Correct path for next transfer
4. Clean up destination if needed

## Browser Issues

### JavaScript Errors

**Symptom:** Features not working, console shows errors

**Solutions:**
✅ Hard refresh: Ctrl+F5 (Windows) or Cmd+Shift+R (Mac)  
✅ Clear cache completely  
✅ Disable ad blockers  
✅ Try incognito/private mode  
✅ Update browser to latest version  

### Can't Click Buttons

**Symptom:** Buttons don't respond

**Solutions:**
✅ Refresh page  
✅ Check browser console (F12) for errors  
✅ Try different browser  
✅ Disable browser extensions  
✅ Clear cookies and cache  

### Page Looks Broken

**Symptom:** Layout is messed up

**Solutions:**
✅ Hard refresh (Ctrl+F5)  
✅ Clear cache  
✅ Check browser zoom (should be 100%)  
✅ Try different browser  
✅ Update browser  

## Getting Help

### Before Contacting Support

Gather this information:

1. **What you were trying to do**
2. **What happened instead**
3. **Error messages** (exact text or screenshot)
4. **When it happened** (date and time)
5. **What you tried** to fix it

### Information That Helps

✅ Transfer ID (from History)  
✅ Remote names involved  
✅ Screenshot of error  
✅ Browser and version  
✅ Steps to reproduce  

### Logs to Include

1. Go to **Logs** tab
2. Find relevant entries
3. Copy or screenshot
4. Include in support request

### Contact Methods

**Administrator:**
- Email your admin
- Include all details above
- Attach screenshots
- Note urgency level

**Documentation:**
- Check other guides
- Search for specific error
- Review best practices

## Quick Diagnostics

### Transfer Problems Checklist

- [ ] Both remotes test successfully
- [ ] Source path exists (verified with ls)
- [ ] Destination has enough space
- [ ] Network is stable
- [ ] No recent credential changes
- [ ] Firewall not blocking
- [ ] No provider service outages

### Schedule Problems Checklist

- [ ] Schedule is enabled (Active)
- [ ] Next run time is in the future
- [ ] Timezone calculated correctly
- [ ] Remotes still working
- [ ] Server was running at scheduled time
- [ ] No permission changes

### Notification Problems Checklist

- [ ] Email address is correct
- [ ] Webhook URL is valid
- [ ] SMTP configured (for email)
- [ ] Test notification works
- [ ] Not in spam folder
- [ ] Service is working (Slack/Discord/etc.)

---

**Remember:** Most issues are simple fixes - wrong paths, expired credentials, or network issues. Check the basics first!
