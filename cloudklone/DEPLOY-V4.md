# CloudKlone v4 - Quick Deploy Guide

## 🚀 Deploy v4 Update

### Step 1: Stop Current Version
```bash
cd ~/cloudklone
sudo docker-compose down
```

### Step 2: Backup Current Database (Optional but Recommended)
```bash
sudo docker-compose exec postgres pg_dump -U postgres cloudklone > backup.sql
```

### Step 3: Extract New Version
```bash
cd ~
tar -xzf cloudklone-v4-final.tar.gz
cd cloudklone
```

### Step 4: Set Encryption Key (IMPORTANT!)
```bash
# Generate a secure encryption key
openssl rand -hex 32

# Add to docker-compose.yml under app service environment:
# - ENCRYPTION_KEY=your-generated-key-here
```

**Or edit the .env file:**
```bash
echo "ENCRYPTION_KEY=$(openssl rand -hex 32)" > .env
echo "JWT_SECRET=$(openssl rand -hex 32)" >> .env
```

### Step 5: Deploy with Build
```bash
sudo docker-compose up -d --build
```

### Step 6: Watch Logs
```bash
sudo docker-compose logs -f app
```

**Look for:**
```
✓ CloudKlone server listening on 0.0.0.0:3001
✓ WebSocket ready
✓ Database initialized
```

### Step 7: Cancel Your Stuck Transfer
1. Log into CloudKlone
2. Go to Transfers tab
3. Click "Cancel" on the stuck transfer
4. It will be killed immediately

### Step 8: Re-add SFTP Remote
Your SFTP remote with the base64 error needs to be re-added:
1. Go to Remotes tab
2. Delete the old SFTP remote (10.0.0.13)
3. Add it again with same credentials
4. Password will be auto-obscured this time
5. Test connection - should work now!

---

## ⚠️ Important Notes

### 1. Encryption Key
**This is NEW and CRITICAL:**
- Stores encrypted remote credentials
- Must be set before adding remotes
- If lost, all remotes must be re-added
- Use a secure random 64-char hex string

### 2. Existing Remotes
**Non-SFTP remotes:**
- Will continue to work
- But are NOT encrypted yet
- Delete and re-add to encrypt

**SFTP remotes:**
- Will fail with base64 error
- MUST be deleted and re-added
- New ones will be obscured/encrypted

### 3. Database Migration
The new tables (groups, reset tokens, encrypted_config) are created automatically on startup.

---

## 🔧 Troubleshooting

### "Failed to obscure password"
**Problem:** rclone command not working  
**Solution:**
```bash
# Test rclone
sudo docker-compose exec app rclone version

# If missing, rebuild:
sudo docker-compose build --no-cache
```

### "Failed to decrypt config"
**Problem:** ENCRYPTION_KEY changed or not set  
**Solution:**
1. Set ENCRYPTION_KEY in docker-compose.yml
2. Restart: `sudo docker-compose restart`
3. Re-add all remotes

### SFTP Still Failing
**Problem:** Old remote still in database  
**Solution:**
1. Delete the remote completely
2. Wait 10 seconds
3. Add again with same name
4. Should work now

### Transfer Still Stuck
**Problem:** Cancel didn't work  
**Admin solution:**
```bash
# Force kill all stuck transfers
curl -X POST http://localhost/api/transfers/cancel-all-stuck \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

---

## ✅ Verify Deployment

### 1. Check SFTP Connection
```bash
# Should see "Connected successfully"
# Not "base64 decode error"
```

### 2. Check Encryption
```bash
# Connect to database
sudo docker-compose exec postgres psql -U postgres cloudklone

# Check for encrypted configs
SELECT name, encrypted_config IS NOT NULL as encrypted FROM remotes;

# Should show 'true' for new remotes
```

### 3. Test Same-Remote Transfer
Create a test transfer:
- Source: same-bucket:/folder1/file.txt
- Destination: same-bucket:/folder2/file.txt
- Should work fine!

### 4. Check Cancel Button
- Create a test transfer
- Cancel button should appear
- Click it - transfer stops immediately

---

## 📊 What Changed from v3 to v4

| Feature | v3 | v4 |
|---------|----|----|
| SFTP passwords | ❌ Raw (failed) | ✅ Obscured |
| Credential storage | ❌ Plain JSONB | ✅ AES-256 encrypted |
| User groups | ❌ None | ✅ Full RBAC |
| Password reset | ❌ Manual | ✅ Automated email |
| Cancel transfers | ❌ Delete only | ✅ Kill + cancel |
| Same-remote | ✅ Works | ✅ Works (confirmed) |

---

## 🎯 Post-Deployment Checklist

After deploying v4:

- [ ] Set ENCRYPTION_KEY environment variable
- [ ] Cancel stuck transfer from before
- [ ] Delete old SFTP remote (10.0.0.13)
- [ ] Re-add SFTP remote (will auto-obscure password)
- [ ] Test SFTP connection (should succeed)
- [ ] Delete and re-add other remotes to encrypt them
- [ ] Change default admin password
- [ ] Create a test group (optional)
- [ ] Test same-remote transfer
- [ ] Verify cancel button works

---

## 🚨 If Something Goes Wrong

### Nuclear Option: Fresh Start
```bash
cd ~/cloudklone
sudo docker-compose down -v  # WARNING: Deletes all data!
sudo docker-compose up -d --build

# Re-add all remotes
# Re-create users
```

### Keep Data, Rebuild Container
```bash
cd ~/cloudklone
sudo docker-compose down
sudo docker-compose build --no-cache
sudo docker-compose up -d
```

### Just Restart
```bash
sudo docker-compose restart
```

---

## 📞 Support

**Check logs:**
```bash
sudo docker-compose logs -f app
```

**Common log messages:**
- `[transfer_id] Transfer started` - Good
- `Failed to obscure password` - Rclone missing, rebuild
- `Failed to decrypt config` - Set ENCRYPTION_KEY
- `Killing running transfer` - Cancel working correctly

---

## 🎉 Success!

You should now have:
- ✅ Encrypted remote credentials
- ✅ Working SFTP connections
- ✅ User/group management
- ✅ Password reset via email
- ✅ Cancel button for transfers
- ✅ No stuck transfers
- ✅ Same-remote transfers confirmed working

**Enjoy your secure, feature-complete CloudKlone!** 🚀
