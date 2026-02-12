# Scheduling Transfers

Automate your transfers to run on a schedule - set it and forget it!

## What is Scheduling?

Instead of manually starting transfers, you can schedule them to run:
- **Once** at a specific time (future date)
- **Recurring** on a regular interval (hourly, daily, weekly, monthly)

Perfect for backups, syncs, and routine data movement.

## Why Schedule Transfers?

✅ **Automation** - Runs without you  
✅ **Consistency** - Never forget a backup  
✅ **Off-Peak** - Run during nights/weekends  
✅ **Peace of Mind** - Set it and forget it  

## Creating a Scheduled Transfer

### One-Time Schedule

**Use case:** Run a transfer once in the future

**Steps:**
1. Go to **Transfers** tab
2. Set up your transfer (operation, source, destination)
3. Check **☑ Schedule this transfer**
4. Select **Run once at specific time**
5. Choose **Date & Time**
6. Click **Start Transfer**

**Example:**
```
Transfer customer data to archive on Jan 31, 2024 at 11:00 PM
```

### Recurring Schedule

**Use case:** Run a transfer repeatedly

**Steps:**
1. Go to **Transfers** tab
2. Set up your transfer
3. Check **☑ Schedule this transfer**
4. Select **Run on repeat**
5. Choose **Repeat Interval**:
   - Hourly - Every hour
   - Daily - Every day
   - Weekly - Every week
   - Monthly - Every month
6. Set **Start Time** (for daily/weekly/monthly)
7. Click **Start Transfer**

**Example:**
```
Sync website files to S3 daily at 2:00 AM
```

## Schedule Intervals

### Hourly
- Runs every 60 minutes
- Good for: frequent updates, real-time syncs
- Example: Sync logs every hour

### Daily
- Runs once per day at specified time
- Good for: daily backups, reports
- Example: Backup files every day at midnight

### Weekly
- Runs once per week on the same day
- Good for: weekly archives, summaries
- Example: Archive photos every Sunday at 1:00 AM

### Monthly
- Runs once per month on the same day
- Good for: monthly backups, archives
- Example: Archive reports on the 1st at 3:00 AM

## Managing Scheduled Transfers

### View All Schedules

1. Go to **Scheduled** tab
2. See all scheduled transfers with:
   - Source → Destination
   - Schedule type (once/recurring)
   - Next run time
   - Status (active/disabled)

### Dashboard Statistics

At the top of the Scheduled tab:

**Total Scheduled** - All scheduled jobs  
**Active** - Currently enabled  
**Disabled** - Paused schedules  
**Recurring** - Repeating transfers  

### Filter Schedules

Use the filter dropdown to show:
- **All Jobs** - Everything
- **Recurring Only** - Just repeating schedules
- **One-Time Only** - Future one-off transfers
- **Active Only** - Enabled schedules
- **Disabled Only** - Paused schedules

## Enable/Disable Schedules

### Disable a Schedule
**Pauses the schedule without deleting it**

1. Go to **Scheduled** tab
2. Find the transfer
3. Click **Disable**
4. Schedule is paused (won't run)

**Use when:** Temporarily stopping transfers (maintenance, testing)

### Enable a Schedule
**Resumes a disabled schedule**

1. Go to **Scheduled** tab
2. Find the disabled transfer
3. Click **Enable**
4. Schedule becomes active again

### Delete a Schedule
**Permanently removes the schedule**

1. Click **Delete** button
2. Confirm deletion
3. Schedule is removed

**Warning:** Cannot be undone!

## How Schedules Work

### Next Run Time
CloudKlone shows when each transfer will run next:
- One-time: Shows the scheduled date/time
- Recurring: Shows next occurrence

**Example:**
```
Daily backup at 2:00 AM
Next run: Feb 10, 2024 02:00:00 AM
```

### Time Zones
- Schedules use your server's timezone
- Check **Admin** → **System Settings** for timezone
- All times display in this timezone

### Execution
When the scheduled time arrives:
1. CloudKlone queues the transfer
2. Transfer starts automatically
3. Runs like a manual transfer
4. Next run time is calculated
5. Repeats (for recurring schedules)

## Common Scheduling Scenarios

### Scenario 1: Nightly Backups
**Goal:** Backup files every night

**Setup:**
- Schedule: **Recurring** → **Daily**
- Time: **2:00 AM** (off-peak)
- Operation: **Copy**
- Source: Production data
- Destination: Backup location

**Why:** Runs automatically every night during low-usage hours

### Scenario 2: Weekly Archives
**Goal:** Create weekly snapshots

**Setup:**
- Schedule: **Recurring** → **Weekly**
- Time: **Sunday 1:00 AM**
- Operation: **Copy**
- Source: Active files
- Destination: Archive/YYYY-MM-DD

**Why:** Weekly backups without manual intervention

### Scenario 3: End-of-Month Reports
**Goal:** Archive reports monthly

**Setup:**
- Schedule: **Recurring** → **Monthly**
- Time: **1st of month 3:00 AM**
- Operation: **Copy**
- Source: Reports folder
- Destination: Monthly archive

**Why:** Automated monthly archiving

### Scenario 4: Website Sync
**Goal:** Keep website in sync hourly

**Setup:**
- Schedule: **Recurring** → **Hourly**
- Operation: **Sync**
- Source: Content repository
- Destination: Web server

**Why:** Fresh content every hour automatically

### Scenario 5: One-Time Migration
**Goal:** Migrate data on specific date

**Setup:**
- Schedule: **Run once** → **Jan 15, 2024 9:00 PM**
- Operation: **Copy**
- Source: Old storage
- Destination: New storage

**Why:** Plan migration for off-hours

## Best Practices

### Timing
✅ Schedule during off-peak hours (nights/weekends)  
✅ Avoid business hours for large transfers  
✅ Stagger multiple schedules (don't all at midnight)  
✅ Consider timezone differences  

### Testing
✅ Test manually before scheduling  
✅ Start with one-time to verify  
✅ Monitor first few runs  
✅ Check History tab for success  

### Maintenance
✅ Review schedules monthly  
✅ Disable unused schedules  
✅ Delete obsolete schedules  
✅ Update paths as needed  

### Safety
✅ Test sync operations before scheduling  
✅ Use Copy for most backups  
✅ Keep source paths accurate  
✅ Verify destination has space  

## Monitoring Scheduled Transfers

### Check Execution History

1. Go to **History** tab
2. Look for your scheduled transfers
3. Verify they ran successfully
4. Check transfer times and data amounts

**Tip:** Scheduled transfers show schedule info in the history.

### Daily Email Reports

Enable daily reports to get:
- Summary of yesterday's transfers
- Success/failure counts
- Schedule status
- Errors and issues

See **Webhooks and Notifications** guide for setup.

### Webhooks for Alerts

Set up webhooks to get instant notifications when:
- Scheduled transfer completes
- Transfer fails
- Issues occur

See **Webhooks and Notifications** guide.

## Troubleshooting

### Schedule Didn't Run

**Possible causes:**
- Schedule was disabled
- Server was down at scheduled time
- Source/destination unavailable

**Check:**
1. Verify schedule is **Active**
2. Check **History** for error messages
3. Review **Logs** for details
4. Test remote connections

### Wrong Time Execution

**Cause:** Timezone mismatch

**Solution:**
1. Check server timezone (**Admin** → **System Settings**)
2. Calculate correct time for that timezone
3. Update schedule time accordingly

### Transfer Failed on Schedule

**Cause:** Source/destination changed

**Solution:**
1. Check **History** for error details
2. Test remotes manually
3. Verify paths still exist
4. Update schedule if needed

### Can't Delete Schedule

**Cause:** Transfer currently running

**Solution:**
1. Wait for transfer to complete
2. Or cancel the running transfer
3. Then delete schedule

## Tips and Tricks

### Tip 1: Test Before Scheduling
Never schedule a transfer you haven't tested manually first.

```
1. Run manually once
2. Verify it works
3. Then create schedule
```

### Tip 2: Use Descriptive Destinations
Include date stamps in destination paths:

```
Bad:  /backup
Good: /backup/daily/2024-02-09
```

### Tip 3: Monitor First Week
Watch scheduled transfers closely for the first week:
- Check they run on time
- Verify data transferred correctly
- Look for any errors

### Tip 4: Stagger Schedules
Don't run everything at the same time:

```
❌ Bad:
  - Backup A: 2:00 AM
  - Backup B: 2:00 AM
  - Backup C: 2:00 AM

✅ Good:
  - Backup A: 1:00 AM
  - Backup B: 2:00 AM
  - Backup C: 3:00 AM
```

### Tip 5: Keep Schedules Simple
Start simple, add complexity later:

```
Week 1: Daily backup at 2 AM
Week 2: Add weekly full backup
Week 3: Add monthly archive
```

## Quick Reference

| Task | Steps |
|------|-------|
| Schedule one-time | Transfers → Check Schedule → Run once → Set date/time |
| Schedule recurring | Transfers → Check Schedule → Repeat → Set interval |
| View schedules | Go to Scheduled tab |
| Disable schedule | Scheduled → Click Disable |
| Enable schedule | Scheduled → Click Enable |
| Delete schedule | Scheduled → Click Delete → Confirm |
| Check history | History tab → Look for scheduled transfers |

---

**Remember:** Test manually first, schedule second. Start with daily backups, then add more complexity as needed!
