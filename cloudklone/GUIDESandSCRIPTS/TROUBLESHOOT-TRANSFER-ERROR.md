# Troubleshooting "Failed to create transfer: Server error"

## 🔍 What's Happening

The "Server error" message means something crashed on the backend when trying to create your transfer. With the new update, it will show more details.

## 🎯 Most Likely Cause: Missing Database Columns

**Your database doesn't have the new scheduling columns yet!**

When we added scheduling in v3, we added new columns to the `transfers` table:
- `scheduled_for`
- `schedule_type`
- `schedule_interval`
- `last_run`
- `next_run`
- `enabled`

If these don't exist, the INSERT fails with error code `42703` (undefined column).

## ✅ Quick Fix

### Option 1: Fresh Deployment (Safest)
```bash
cd ~/cloudklone
sudo docker-compose down -v  # ⚠️ This deletes all data!
sudo docker-compose up -d --build

# All transfers and remotes will be gone
# But database schema will be correct
```

### Option 2: Add Columns Manually (Keeps Data)
```bash
# Connect to database
sudo docker-compose exec postgres psql -U postgres cloudklone

# Add missing columns
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS schedule_type VARCHAR(20);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS schedule_interval VARCHAR(50);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS last_run TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS next_run TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;

# Also add group/encryption columns for remotes
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS encrypted_config TEXT;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS is_shared BOOLEAN DEFAULT FALSE;

# Exit
\q
```

### Option 3: Restart with --build (Keeps Data)
```bash
cd ~/cloudklone
sudo docker-compose down
sudo docker-compose up -d --build

# Database migrations run automatically
# Your data is preserved
```

## 🔎 Check What You're Missing

### Verify Database Schema
```bash
# Connect
sudo docker-compose exec postgres psql -U postgres cloudklone

# List transfers table columns
\d transfers

# Should show:
# - scheduled_for (timestamp)
# - schedule_type (varchar)
# - schedule_interval (varchar)
# - last_run (timestamp)
# - next_run (timestamp)
# - enabled (boolean)
```

### Check for Groups Table
```bash
# In psql
\dt

# Should show:
# - users
# - remotes
# - transfers
# - groups  ← If missing, schema is old
# - notification_settings
```

## 📊 Verify After Fix

After running Option 2 or 3:

1. **Check logs** (should see no errors):
```bash
sudo docker-compose logs -f app | grep -i error
```

2. **Try your transfer again**:
   - Source: backblaze-test:cloudklone
   - Dest: backblaze-test:cloudklone/test
   - Should work now!

3. **If still failing**, check the actual error:
```bash
sudo docker-compose logs app | tail -50
# Look for "Create transfer error:" followed by details
```

## 🐛 Other Possible Causes

### 1. SFTP Remote Query Failing
If you have an SFTP remote and it can't be queried:
```javascript
// Backend tries to check if remotes are SFTP
const remotes = await pool.query(
  'SELECT name, type FROM remotes WHERE user_id = $1 AND (name = $2 OR name = $3)',
  [userId, transfer.source_remote, transfer.dest_remote]
);
```

**Fix:** Make sure your remotes exist and are accessible.

### 2. Encryption Key Not Set
If `ENCRYPTION_KEY` is not set, encryption fails:

```bash
# Add to docker-compose.yml
environment:
  - ENCRYPTION_KEY=your-64-char-hex-key
```

### 3. calculateNextRun Function Missing
For scheduled transfers, this function must exist:

```bash
# Check if function is defined
sudo docker-compose exec app grep -n "function calculateNextRun" index.js
```

Should return a line number. If not, rebuild container.

## 🎯 Your Specific Case

Based on your screenshot:
- Source: `backblaze-test` (B2)
- Source path: `cloudklone`
- Dest: `backblaze-test` (B2)
- Dest path: `cloudklone/test`
- Operation: Copy (default)
- Schedule: Not enabled

**This should work!** The error is almost certainly missing database columns.

## ✅ Step-by-Step Fix

```bash
# 1. Deploy new version with better error messages
cd ~/cloudklone
sudo docker-compose down
cd ~ && tar -xzf cloudklone-v4-final.tar.gz
cd cloudklone

# 2. Add missing columns (if you want to keep data)
sudo docker-compose up -d postgres
sleep 5
sudo docker-compose exec postgres psql -U postgres cloudklone << EOF
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS schedule_type VARCHAR(20);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS schedule_interval VARCHAR(50);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS last_run TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS next_run TIMESTAMP;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS encrypted_config TEXT;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS group_id INTEGER;
ALTER TABLE remotes ADD COLUMN IF NOT EXISTS is_shared BOOLEAN DEFAULT FALSE;
EOF

# 3. Start app
sudo docker-compose up -d app

# 4. Check logs
sudo docker-compose logs -f app

# 5. Try transfer again - should see better error message if still fails
```

## 📝 What Error Will Show Now

After this update, instead of generic "Server error", you'll see:
- "Failed to create transfer: column 'scheduled_for' does not exist" → Run Option 2 above
- "Failed to create transfer: relation 'groups' does not exist" → Need fresh deployment
- Actual rclone errors if transfer starts but fails

## 🔄 Migration Status

If you deployed v3 before v4:
- ✅ Database has scheduling columns
- ❌ Database missing groups table
- ❌ Database missing encrypted_config column

If you deployed v2 straight to v4:
- ❌ Database missing everything
- ✅ Need full schema migration

## 🚀 After Fix

Your same-bucket transfer will work:
```
backblaze-test:cloudklone → backblaze-test:cloudklone/test
```

B2 will use server-side copy (very fast, no bandwidth used)!

---

## 💡 Pro Tip

Always deploy with `--build` flag when updating:
```bash
sudo docker-compose up -d --build
```

This ensures:
- New dependencies installed (node-cron, crypto)
- Code changes applied
- Database migrations run
- No stale cache issues
