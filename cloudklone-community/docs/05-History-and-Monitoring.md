# History and Monitoring

Track your transfers, review past activity, and understand your data movement.

## What is History?

The History tab shows all your past transfers with details about:
- What was transferred
- When it ran
- Success or failure
- Amount of data moved
- Transfer speed

Think of it as your transfer logbook.

## Viewing Transfer History

### Opening History

1. Click **History** tab in the sidebar
2. See all transfers sorted by date (newest first)
3. Scroll to see older transfers

### What You'll See

Each transfer shows:

**Status Badge**
- 🟢 **Completed** - Success (green)
- 🔴 **Failed** - Error occurred (red)
- 🟠 **Running** - In progress (orange)

**Transfer Details**
- Source → Destination path
- Date and time
- Data transferred
- Any error messages

**Statistics at Top**
- **Total Transfers** - All time count
- **Completed** - Successful transfers
- **Failed** - Transfers with errors
- **Running** - Currently active

## Filtering History

Use the **Filter** dropdown to show specific transfers:

**All Transfers** - Shows everything  
**Completed** - Only successful transfers  
**Failed** - Only errors  
**Running** - Currently active  

**Example use cases:**
- Find all failures to investigate
- Review completed backups
- Check running transfers

## Understanding Transfer Status

### Completed ✅
**Meaning:** Transfer finished successfully

**Details shown:**
- Total data transferred
- Completion time
- Source and destination

**What to do:** Nothing, all good!

### Failed ❌
**Meaning:** Transfer encountered an error

**Details shown:**
- Error message
- What went wrong
- When it failed

**What to do:**
1. Read the error message
2. Fix the issue
3. Retry the transfer

### Running ⏳
**Meaning:** Transfer currently in progress

**Details shown:**
- Progress percentage
- Current speed
- ETA
- Amount transferred so far

**What to do:** Monitor or cancel if needed

## Today's Activity Dashboard

On the **Transfers** tab, see real-time stats:

### Active Now
**Current running transfers**
- Updates every 5 seconds
- Shows transfer count
- See details in Active Transfers list

### Completed Today
**Successful transfers since midnight**
- Resets daily at midnight
- Counts all completed transfers
- Good indicator of daily activity

### Failed Today
**Transfers with errors today**
- Resets daily at midnight
- Shows issues needing attention
- Click to see error details

### Data Transferred
**Total bytes moved today**
- Formatted in KB, MB, GB, TB
- Accumulates throughout day
- Resets at midnight

### Avg Speed
**Average transfer speed today**
- Calculated from completed transfers
- Shows in MB/s, GB/s, etc.
- Good for performance monitoring

## Reading Transfer Details

### Successful Transfer Example
```
Status: completed ✓
Path: aws-s3:/photos → gdrive:/backup
Time: Feb 9, 2024 2:30 AM
Transferred: 15.3 GB
```

**What this tells you:**
- Photos backed up successfully
- Moved 15.3 GB of data
- Ran during off-peak hours

### Failed Transfer Example
```
Status: failed ✗
Path: dropbox:/docs → s3:/archive
Time: Feb 9, 2024 3:15 PM
Error: Access denied - check credentials
```

**What this tells you:**
- Transfer failed
- Problem with credentials
- Need to update remote configuration

## Monitoring Active Transfers

### Real-Time Progress

For running transfers, you see:

**Progress Bar**
- Visual indicator (0-100%)
- Updates every second
- Green fill shows completion

**Transfer Speed**
- Current rate (e.g., "25 MB/s")
- Can fluctuate based on network
- Indicates performance

**ETA (Estimated Time)**
- Remaining time estimate
- Updates as speed changes
- Format: "2h 30m" or "45s"

**Data Transferred**
- Amount moved so far
- Format: "1.5 GB / 10 GB"
- Shows total when known

### Taking Action

**Cancel Transfer**
- Click **Cancel** button
- Confirms before stopping
- Partial data remains at destination

**Monitor Multiple Transfers**
- All active transfers shown
- Each has own progress bar
- Update independently

## Using History for Troubleshooting

### Finding Problems

**Step 1: Filter to Failed**
- Use filter dropdown
- Select "Failed"
- See all errors

**Step 2: Read Error Messages**
- Each failure shows why it failed
- Common errors:
  - Access denied
  - Network timeout
  - Quota exceeded
  - Path not found

**Step 3: Fix and Retry**
- Update credentials
- Check network
- Verify paths
- Free up space

### Common Error Patterns

**Access Denied**
```
Fix: Update remote credentials
Check: Permissions on both sides
Test: Use Tests & Queries to verify
```

**Network Timeout**
```
Fix: Check internet connection
Try: Retry during better network time
Consider: Smaller batch sizes
```

**Quota Exceeded**
```
Fix: Free up space at destination
Check: Storage limits
Alternative: Use different destination
```

**Path Not Found**
```
Fix: Verify source path exists
Use: Tests & Queries to browse
Correct: Source path in transfer
```

## Best Practices

### Regular Reviews
✅ Check History daily  
✅ Investigate all failures  
✅ Monitor transfer sizes  
✅ Track performance trends  

### Clean Up
✅ Delete old successful transfers (keeps list clean)  
✅ Keep failed transfers until resolved  
✅ Archive important transfer records  

### Performance Tracking
✅ Note average speeds  
✅ Compare day vs. night performance  
✅ Track data volume trends  
✅ Identify slow providers  

### Documentation
✅ Screenshot important transfers  
✅ Note error resolutions  
✅ Track schedule compliance  
✅ Maintain transfer logs externally  

## Using Stats for Insights

### Daily Patterns

**Morning Check:**
- Review overnight scheduled transfers
- Check all completed successfully
- Note any failures for immediate attention

**End of Day:**
- Review total data transferred
- Compare to expected volumes
- Note any anomalies

### Weekly Review

**Questions to ask:**
- Did all scheduled transfers run?
- Were there any recurring failures?
- Is performance consistent?
- Do we need more capacity?

### Monthly Analysis

**Track trends:**
- Total data transferred per month
- Average transfer speeds
- Failure rates
- Peak usage times

## Tips and Tricks

### Tip 1: Use Filters Effectively
Don't scroll through hundreds of transfers:
```
Need: Check today's failures
Do: Filter to "Failed" → Review → Fix
```

### Tip 2: Monitor During Large Transfers
For big jobs:
```
1. Start transfer
2. Watch first few minutes
3. Verify speed is good
4. Check periodically
5. Verify completion
```

### Tip 3: Compare Speeds
Track which providers are fastest:
```
AWS S3 → Google Drive: 50 MB/s
Dropbox → OneDrive: 20 MB/s

Insight: Use S3↔Drive for large transfers
```

### Tip 4: Set Expectations
Know what's normal:
```
Small files (1000s): Slower (10 MB/s)
Large files (few): Faster (100 MB/s)
Cross-region: Slower (variable)
Same-region: Faster (consistent)
```

### Tip 5: Document Issues
When you see a failure:
```
1. Screenshot the error
2. Note what you tried
3. Record the solution
4. Update your runbook
```

## Quick Reference

| Task | How To |
|------|--------|
| View all history | Click History tab |
| Filter transfers | Use Filter dropdown |
| See today's stats | Check Transfers tab dashboard |
| Check active transfers | Active Transfers section |
| Find failures | Filter → Failed |
| Clean up history | Delete completed transfers |
| Monitor progress | Watch Active Transfers real-time |

## Understanding the Numbers

### Transfer Size
- **B** = Bytes (very small)
- **KB** = Kilobytes (documents)
- **MB** = Megabytes (photos)
- **GB** = Gigabytes (videos, large datasets)
- **TB** = Terabytes (massive datasets)

### Transfer Speed
- **KB/s** = Slow (dialup era)
- **MB/s** = Normal (10-100 MB/s common)
- **GB/s** = Very fast (internal networks)

**Good speeds:**
- 10-50 MB/s: Acceptable for cloud transfers
- 50-100 MB/s: Good performance
- 100+ MB/s: Excellent (usually same-region)

---

**Remember:** History is your best tool for understanding transfer patterns, troubleshooting issues, and optimizing performance!
