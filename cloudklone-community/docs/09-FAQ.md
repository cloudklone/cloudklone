# Frequently Asked Questions (FAQ)

Quick answers to common questions about CloudKlone.

## General Questions

### What is CloudKlone?

CloudKlone is a platform for transferring and syncing data between cloud storage providers. It supports 40+ providers including AWS S3, Google Drive, Dropbox, OneDrive, and more.

### What can I do with CloudKlone?

- Copy files between cloud providers
- Sync directories to keep them identical
- Schedule automatic backups
- Monitor transfer progress in real-time
- Browse files across multiple cloud services
- Get notifications about transfer activity

### Is my data secure?

Yes! CloudKlone:
- Never stores your files permanently
- Transfers data directly between your cloud providers
- Encrypts credentials in the database
- Uses secure connections (HTTPS)
- Runs on your own infrastructure (self-hosted)

### How much does it cost?

CloudKlone is open-source software that you run on your own server. There's no licensing cost for the software itself, but you'll need:
- A server to run it on
- Cloud storage accounts (AWS, Google, etc.)
- Potential data transfer fees from cloud providers

## Getting Started

### How do I get an account?

Contact your administrator to create an account for you. They'll provide:
- Username
- Temporary password
- CloudKlone URL

### What do I need before starting?

1. CloudKlone account (from admin)
2. Credentials for your cloud storage providers
3. Web browser (Chrome, Firefox, Safari, Edge)
4. Basic knowledge of your file locations

### Can I try it without connecting cloud storage?

Yes! You can:
- Explore the interface
- Read documentation
- Test with local storage
- Learn the features

Just add a "local" type remote to get started.

## Remotes

### What is a remote?

A remote is a saved connection to a cloud storage provider. Think of it like a bookmark to your storage location.

### How many remotes can I have?

There's no limit! Add as many as you need.

### What providers are supported?

40+ providers including:
- **Cloud Storage:** AWS S3, Google Drive, Dropbox, OneDrive, Box
- **File Servers:** SFTP, FTP, WebDAV, SMB
- **Other Cloud:** Google Cloud Storage, Azure Blob, Backblaze B2, Wasabi
- **Local:** Your local filesystem

Full list at: [rclone.org/overview](https://rclone.org/overview/)

### How do I get credentials?

Each provider is different:
- **AWS:** IAM Console → Create access keys
- **Google Drive:** Cloud Console → OAuth credentials
- **Dropbox:** App Console → Generate token
- **SFTP:** Server admin provides username/password

Check your provider's documentation for detailed steps.

### Can I share remotes with other users?

No, remotes are private to your account. Each user configures their own remotes.

## Transfers

### What's the difference between Copy and Sync?

**Copy:**
- Duplicates files
- Keeps source unchanged
- Adds to destination
- Safe for backups

**Sync:**
- Makes destination match source
- Can delete files at destination
- One-way mirror
- Use with caution!

### How long do transfers take?

Depends on:
- Amount of data
- Number of files
- Network speed
- Provider limits
- File sizes

**Typical speeds:** 10-100 MB/s for cloud-to-cloud

**Estimate:** 100 GB ÷ 50 MB/s ≈ 35 minutes

### Can I transfer terabytes of data?

Yes! CloudKlone handles any size. Large transfers just take longer.

**Tips for large transfers:**
- Schedule during off-peak hours
- Monitor progress initially
- Verify completion afterward
- Consider cost implications

### Can I cancel a running transfer?

Yes! Click the **Cancel** button next to the transfer. The transfer stops immediately, but partial data remains at the destination.

### What happens if a transfer fails?

CloudKlone:
- Logs the error
- Shows in History as "failed"
- Leaves partial data at destination

You can:
- Read the error message
- Fix the issue
- Retry the transfer

### Do I pay for data transfer?

CloudKlone itself is free, but cloud providers may charge:
- **Egress fees** - Downloading data out
- **API requests** - For each file
- **Storage** - For the destination

Check your provider's pricing before large transfers.

## Scheduling

### Can I automate transfers?

Yes! Use the scheduling feature to run transfers:
- Once at a specific time
- Hourly, daily, weekly, or monthly

Perfect for backups and regular syncs.

### What timezone do schedules use?

Schedules use the server's timezone (shown in Settings tab → System Settings). Calculate your local time accordingly.

**Example:**
- Server: UTC
- Your time: EST (UTC-5)
- Want 2 AM EST = 7 AM UTC

### What if I miss a scheduled time?

If the server is down when a schedule should run, it won't automatically catch up. It will run at the next scheduled time.

### Can I temporarily pause a schedule?

Yes! Use the **Disable** button. The schedule is paused but not deleted. **Enable** it when ready to resume.

### How do I know if my schedule ran?

Check the **History** tab:
- Scheduled transfers show schedule info
- Look at the timestamp
- Verify success/failure status

Also enable email reports for daily summaries.

## Monitoring

### How do I know if a transfer is running?

The **Transfers** tab shows:
- Active transfers with progress bars
- Current speed and ETA
- Real-time percentage

Updates automatically every 5 seconds.

### Can I see historical transfers?

Yes! The **History** tab shows all past transfers with:
- Date and time
- Source → Destination
- Success/failure status
- Data transferred

### What are the dashboard statistics?

The Transfers tab shows today's stats:
- **Active Now** - Currently running
- **Completed Today** - Successful since midnight
- **Failed Today** - Errors today
- **Data Transferred** - Total GB moved
- **Avg Speed** - Average transfer rate

### How far back does history go?

Depends on your edition:
- **Community:** 30 days
- **Professional:** Unlimited
- **Enterprise:** Unlimited

## Notifications

### Can I get email alerts?

Yes! Enable **Daily Email Reports** in Settings to receive:
- Summary of yesterday's activity
- Success/failure counts
- Data transferred
- Any errors that occurred

Sent every morning at 8 AM (server time).

### Can I get instant notifications?

Yes! Use **Webhooks** to send real-time alerts to:
- Slack
- Discord
- Microsoft Teams
- Custom endpoints

Configure in Settings tab.

### What events trigger notifications?

Webhooks notify on:
- Transfer started
- Transfer completed
- Transfer failed

Email reports are daily summaries only.

## Tests & Queries

### What are Tests & Queries?

Tools to browse and inspect your cloud storage:
- **ls** - List files and folders
- **lsf** - List files only
- **size** - Calculate total size
- **cat** - View text file contents
- **tree** - Show directory structure

### Why should I use them?

✅ Verify paths before transfers  
✅ Estimate transfer sizes  
✅ Find specific files  
✅ Debug issues  
✅ Understand folder structure  

### Can I modify files with queries?

No, queries are read-only. They only view or list information, never modify or delete.

## Troubleshooting

### My transfer failed. What do I do?

1. **Read the error message** in History
2. **Check common causes:**
   - Wrong credentials
   - Path doesn't exist
   - No space at destination
   - Network issues
3. **Fix the issue**
4. **Retry the transfer**

See Troubleshooting guide for detailed help.

### Transfer is stuck at 0%. What's wrong?

Common causes:
- Source path is empty or wrong
- Network connectivity issue
- Remote credentials expired

**Solution:** Cancel and verify:
1. Source path has files (use Tests & Queries)
2. Both remotes test successfully
3. Network is working

### How do I check logs?

Go to **Logs** tab:
- Shows detailed system activity
- Includes transfer events
- Contains error details
- Searchable

Look for entries related to your transfer.

### Who do I contact for help?

1. **Check documentation** - Look for your specific issue
2. **Try troubleshooting** - Follow the guides
3. **Contact admin** - They manage the system
4. **Include details** - Error messages, screenshots, steps

## Security

### Who can see my transfers?

- **Regular users:** Only your own transfers
- **Administrators:** All users' transfers

Permissions can be customized in Enterprise edition.

### Are my cloud credentials stored?

Yes, securely:
- Encrypted in the database
- Never shown in plain text
- Only used for transfers
- Accessible only to you

### Can other users access my remotes?

No, remotes are private to your account. Other users cannot see or use your remote configurations.

### Is data encrypted during transfer?

Data uses HTTPS between CloudKlone and cloud providers. Additionally:
- Most providers use TLS/SSL
- CloudKlone doesn't modify file contents
- Files aren't stored on CloudKlone server

## Performance

### Why is my transfer slow?

Common causes:
- Many small files (slower than few large files)
- Provider rate limiting
- Network congestion
- Cross-region transfer
- Time of day (peak hours)

**Tips to improve:**
- Transfer during off-peak hours
- Compress files first
- Use same-region providers
- Check provider limits

### What's a good transfer speed?

**Typical speeds:**
- 10-50 MB/s: Normal for cloud transfers
- 50-100 MB/s: Good performance
- 100+ MB/s: Excellent (usually same-region)

Compare your "Avg Speed" stat to these ranges.

### Can I run multiple transfers at once?

Yes! CloudKlone can handle multiple simultaneous transfers. They'll share available bandwidth.

**Note:** Too many at once may slow each down.

## Advanced Features

### What is RBAC?

Role-Based Access Control - available in Enterprise edition:
- Custom user roles
- Granular permissions
- Remote-level access control
- Advanced security

### Can CloudKlone run across multiple servers?

This is a planned Enterprise feature:
- Distributed architecture
- Worker nodes for transfers
- High availability
- Geographic distribution

Contact sales for beta access.

### Does CloudKlone support multi-tenancy?

Planned for Enterprise edition:
- Multiple organizations
- Complete data isolation
- MSP-ready
- Shared infrastructure

### Are there APIs available?

Currently, CloudKlone is web-based. REST APIs are planned for future releases.

## Billing & Costs

### Does CloudKlone charge for transfers?

No! CloudKlone software is free (Community edition) or subscription-based (Professional/Enterprise).

However, **cloud providers** may charge for:
- Data egress (downloading)
- Storage space
- API requests

Check your provider's pricing.

### How can I estimate costs?

Before large transfers:
1. Check provider's pricing page
2. Calculate: (GB to transfer) × (egress rate)
3. Add: API request costs
4. Consider: Storage costs at destination

**Example:**
- Transfer 1 TB from AWS S3
- Egress: $0.09/GB × 1000 GB = $90
- Keep in mind: Rates vary by region!

### How do I reduce costs?

✅ Transfer within same provider (often free)  
✅ Use same region when possible  
✅ Compress before transfer  
✅ Check provider's free tiers  
✅ Consider transfer timing  

## Support & Updates

### How do I get new features?

Your administrator handles updates. New features are added regularly in CloudKlone releases.

### Where can I request features?

Contact your administrator with requests. They can:
- Submit to CloudKlone GitHub
- Consider custom development
- Vote on feature priorities

### Is there a community forum?

CloudKlone has:
- GitHub Discussions
- Community chat channels
- Documentation wiki

Ask your admin for links.

### How do I report bugs?

1. Document the bug clearly
2. Include screenshots
3. Note steps to reproduce
4. Contact your administrator
5. They'll report to CloudKlone team

---

**Still have questions?** Check the other documentation guides or contact your administrator!
