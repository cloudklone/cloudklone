# Creating Transfers

Learn how to move and sync files between your cloud storage providers.

## What is a Transfer?

A transfer moves files from one location (source) to another (destination). You can:
- **Copy** files between cloud providers
- **Sync** to mirror directories
- **Transfer** terabytes of data
- **Monitor** progress in real-time

## Quick Start

### Basic Transfer (3 Steps)

**1. Go to Transfers Tab**
Click **Transfers** in the left sidebar.

**2. Choose Operation**
- **Copy** - Duplicates files (original stays)
- **Sync** - Mirrors directories (one-way)

**3. Select Source and Destination**
- **Source Remote** - Where files come from
- **Source Path** - Folder path (or `/` for root)
- **Destination Remote** - Where files go to
- **Destination Path** - Target folder

**4. Start Transfer**
Click **Start Transfer** button.

That's it! Your transfer begins immediately.

## Copy vs Sync

### Copy Operation
**What it does:** Copies files from source to destination

**Behavior:**
- Keeps original files untouched
- Adds files to destination
- Doesn't delete anything
- Safe for backups

**Use when:**
- Creating backups
- Duplicating data
- Moving to a new provider
- Archiving files

**Example:**
```
Source: aws-s3:/photos
Destination: google-drive:/backup

Result: Photos copied to Google Drive, S3 stays unchanged
```

### Sync Operation
**What it does:** Makes destination exactly match source

**Behavior:**
- Copies new/changed files
- Deletes files not in source
- Updates modified files
- One-way mirror

**Use when:**
- Maintaining mirrors
- Disaster recovery replicas
- Publishing content
- Automated backups

**Example:**
```
Source: dropbox:/website
Destination: aws-s3:/www

Result: S3 becomes exact copy of Dropbox (extra files deleted)
```

⚠️ **Warning:** Sync can delete files! Always test first with a dry run.

## Understanding Paths

### Path Format
Paths tell CloudKlone which folder to use:

- `/` - Root directory (everything)
- `/photos` - Just the photos folder
- `/work/reports` - Nested folder
- `/backup/2024/january` - Deep nesting

### Path Rules
- Always start with `/`
- Use forward slashes `/` (not backslashes)
- No trailing slash needed
- Case-sensitive on most systems

### Examples

| Path | What it means |
|------|---------------|
| `/` | Entire remote |
| `/documents` | Documents folder |
| `/photos/2024` | 2024 photos subfolder |
| `/` to `/backup` | Copy everything to backup folder |

## Today's Activity Dashboard

At the top of the Transfers tab, you'll see 5 statistics:

**Active Now** - Transfers currently running  
**Completed Today** - Successful transfers since midnight  
**Failed Today** - Transfers that had errors  
**Data Transferred** - Total amount moved today  
**Avg Speed** - Average transfer speed today  

These update automatically every 5 seconds.

## Monitoring Active Transfers

### Progress Information
For running transfers, you'll see:

**Progress Bar** - Visual completion indicator  
**Transferred** - Amount of data moved (e.g., "1.5 GB")  
**Speed** - Current transfer rate (e.g., "10 MB/s")  
**ETA** - Estimated time remaining  
**Percentage** - Completion percentage  

### Transfer Actions

**Cancel** - Stop a running transfer  
- Click **Cancel** button
- Confirm cancellation
- Transfer stops immediately
- Partial data remains at destination

**Delete** - Remove completed/failed transfer from list  
- Only shows for finished transfers
- Removes from active view
- History is preserved

## Transfer Speed

### What Affects Speed?

**Provider Limits**
- Upload/download caps
- Rate limiting
- Geographic location

**Network**
- Your internet speed
- Provider's network speed
- Distance between providers

**File Characteristics**
- Many small files = slower
- Few large files = faster
- Compression settings

### Improving Speed

✅ Transfer during off-peak hours  
✅ Use same-region providers when possible  
✅ Compress files before transfer  
✅ Combine small files into archives  
✅ Check provider's rate limits  

## Common Scenarios

### Scenario 1: Backup to Cloud
**Goal:** Backup local files to S3

**Setup:**
- Operation: **Copy**
- Source: `local:/home/user/documents`
- Destination: `aws-s3:/backups/documents`

**Why Copy:** Keeps local files intact

### Scenario 2: Migrate Providers
**Goal:** Move everything from Dropbox to Google Drive

**Setup:**
- Operation: **Copy**
- Source: `dropbox:/`
- Destination: `gdrive:/migration`

**Why Copy:** Safer than sync for one-time migration

### Scenario 3: Website Sync
**Goal:** Keep S3 website in sync with local files

**Setup:**
- Operation: **Sync**
- Source: `local:/var/www/website`
- Destination: `aws-s3:/www.example.com`

**Why Sync:** Ensures website matches source exactly

### Scenario 4: Daily Archive
**Goal:** Copy today's files to archive server

**Setup:**
- Operation: **Copy**
- Source: `gdrive:/daily-work`
- Destination: `sftp-server:/archives/2024-02-09`

**Schedule:** Daily at midnight (see Scheduling guide)

## Error Handling

### What Happens on Error?

**Network Issues**
- CloudKlone retries automatically
- Up to 3 retries per file
- Continues with next file

**Permission Errors**
- Transfer stops
- Error logged
- Fix permissions and retry

**Quota Exceeded**
- Transfer stops
- Free up space
- Resume transfer

### Viewing Errors

**In Active Transfers:**
- Red error message appears
- Shows reason for failure

**In History:**
- Failed transfers marked in red
- Click to see error details
- Check logs for full information

## Best Practices

### Before Starting
✅ Test remotes first  
✅ Check available space  
✅ Verify paths are correct  
✅ Use dry-run for sync operations  

### During Transfer
✅ Monitor progress  
✅ Watch for errors  
✅ Don't modify source during sync  

### After Transfer
✅ Verify files arrived  
✅ Check file counts match  
✅ Review History tab  
✅ Delete successful transfers to clean up  

## Tips and Tricks

### Tip 1: Test with Small Subset
Before transferring terabytes, test with a single folder:
- Copy just one directory
- Verify it works correctly
- Then scale up to full transfer

### Tip 2: Use Descriptive Paths
Instead of:
```
Source: remote1:/
Destination: remote2:/
```

Use:
```
Source: production-s3:/customer-data
Destination: backup-s3:/customer-data-backup
```

### Tip 3: Check Costs First
- Some providers charge for downloads (egress)
- Calculate costs before large transfers
- Use same-region transfers when possible

### Tip 4: Schedule Large Transfers
- Don't run huge transfers during business hours
- Schedule overnight or weekend
- See Scheduling guide for details

## Troubleshooting

### Transfer Stuck at 0%
**Solutions:**
- Check network connectivity
- Verify remote credentials
- Test remotes independently
- Check source path has files

### Very Slow Speed
**Solutions:**
- Check internet connection
- Verify no provider rate limits
- Try different time of day
- Consider file size (many small = slow)

### Transfer Failed
**Solutions:**
- Check error message
- Verify permissions
- Ensure enough disk space
- Test remotes
- Check logs for details

### Destination Empty After Sync
**Cause:** Wrong source path (probably empty)

**Solution:**
- Verify source path has files
- Use Tests & Queries to browse first
- Always test sync with Copy first

## Quick Reference

| Task | How To |
|------|--------|
| Copy files | Operation: Copy → Select source/dest → Start |
| Sync directories | Operation: Sync → Select source/dest → Start |
| Cancel transfer | Click Cancel button → Confirm |
| View progress | Active Transfers section shows real-time stats |
| Check errors | Red error message appears on failed transfers |
| Clean up list | Click Delete on completed transfers |

---

**Remember:** Start small, test first, then scale up. Copy is safer than Sync for most use cases!
