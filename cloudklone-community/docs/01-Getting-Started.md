# Getting Started with CloudKlone

Welcome to CloudKlone! This guide will help you get started in just a few minutes.

## What is CloudKlone?

CloudKlone is a platform for moving and syncing data between cloud storage providers. Think of it as a universal remote control for all your cloud storage - you can copy files between AWS S3, Google Drive, Dropbox, OneDrive, and 40+ other providers.

## First Login

1. Open CloudKlone in your web browser
2. Enter your username and password
3. Click **Login**

**First time?** Your administrator will provide your login credentials.

## The Dashboard

After logging in, you'll see the main dashboard with several tabs:

- **Transfers** - Create and monitor file transfers
- **History** - View past transfers
- **Scheduled** - Manage recurring transfers
- **Tests & Queries** - Test connections and browse files
- **Remotes** - Manage your cloud storage connections
- **Settings** - Configure notifications
- **Logs** - View system activity (if enabled)
- **Admin** - User management (administrators only)

## Your First Transfer in 3 Steps

### Step 1: Add a Remote
Before you can transfer files, you need to connect your cloud storage.

1. Go to the **Remotes** tab
2. Click **Add Remote**
3. Fill in:
   - **Name**: Give it a memorable name (e.g., "my-s3-bucket")
   - **Type**: Choose your provider (S3, Google Drive, etc.)
   - **Configuration**: Enter your credentials
4. Click **Test Remote** to verify it works
5. Click **Add Remote**

**Tip:** You can add as many remotes as you need!

### Step 2: Create a Transfer
Now you can move files between your remotes.

1. Go to the **Transfers** tab
2. Choose an **Operation**:
   - **Copy** - Copies files (keeps original)
   - **Sync** - Mirrors files (one-way sync)
3. Select your **Source** (where files come from)
4. Select your **Destination** (where files go to)
5. Click **Start Transfer**

### Step 3: Monitor Progress
Watch your transfer in real-time:

- Progress bar shows completion percentage
- Speed and ETA are displayed
- You can cancel if needed
- Check **History** tab to see completed transfers

## Today's Activity at a Glance

The dashboard shows 5 key stats:
- **Active Now** - Transfers currently running
- **Completed Today** - Successful transfers since midnight
- **Failed Today** - Transfers that need attention
- **Data Transferred** - Total amount moved today
- **Avg Speed** - How fast transfers are running

These update automatically every few seconds.

## Common Tasks

### Browse Files
1. Go to **Tests & Queries** tab
2. Select a remote
3. Choose **ls** (list) or **lsf** (list files only)
4. Enter a path or leave blank for root
5. Click **Run Query**

### Schedule Recurring Transfers
1. Create a transfer as normal
2. Check **Schedule this transfer**
3. Choose:
   - **Run once** - Set a specific date/time
   - **Run on repeat** - Choose hourly, daily, weekly, or monthly
4. Click **Start Transfer**

Your transfer will run automatically on schedule!

### Get Notifications
1. Go to **Settings** tab
2. Enable **Daily Email Reports**
3. Enter your email address
4. Configure SMTP settings (or ask your admin)
5. Optionally add a **Webhook URL** for instant notifications

## Tips for Success

✅ **Test First** - Always test remotes before transferring large amounts of data  
✅ **Use Sync Carefully** - Sync operations can delete files in the destination  
✅ **Monitor Costs** - Some providers charge for data downloads (egress)  
✅ **Check History** - Review completed transfers to verify success  
✅ **Schedule Wisely** - Run large transfers during off-peak hours  

## Need Help?

- **Check Logs** - View detailed transfer logs in the Logs tab
- **Contact Support** - Reach out to your administrator
- **Documentation** - Check the other guides for specific features

## What's Next?

Now that you're set up, explore these guides:
- **Managing Remotes** - Add and configure cloud storage
- **Creating Transfers** - Deep dive into transfer options
- **Scheduling** - Automate your workflows
- **Webhooks** - Integrate with other tools

---

**Remember:** CloudKlone is powerful but simple. Start with a small test transfer to get comfortable, then scale up to your production needs!
