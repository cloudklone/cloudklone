# CloudKlone v5 - Cloudflare R2 Fix

## 🐛 Issue Fixed

**Problem:** Couldn't add Cloudflare R2 remotes - it was combined with S3 and required manual configuration that wasn't obvious.

**Solution:** Added dedicated "Cloudflare R2" provider with proper defaults automatically configured.

---

## ✅ What Changed

### Before (Broken)
- R2 was listed as "Amazon S3 / Cloudflare R2"
- Required manually:
  - Selecting "Cloudflare" from provider dropdown
  - Setting region to "auto"
  - Setting ACL correctly
  - Getting endpoint format right

### After (Fixed)
- **Dedicated "Cloudflare R2" option** in provider list
- Automatically sets:
  - ✅ `provider = Cloudflare`
  - ✅ `region = auto`
  - ✅ `acl = private`
- Only asks for:
  - Access Key ID
  - Secret Access Key
  - Account Endpoint

---

## 🚀 Deploy Fix

```bash
cd ~
tar -xzf cloudklone-v5-r2-fix.tar.gz
cd cloudklone
sudo docker-compose down
sudo docker-compose up -d
```

Hard refresh browser: `Ctrl+Shift+R`

---

## 📋 How to Add Cloudflare R2

### Step 1: Get R2 Credentials

**In Cloudflare Dashboard:**
1. Go to R2 → Overview
2. Click "Manage R2 API Tokens"
3. Create API Token
4. Copy:
   - Access Key ID
   - Secret Access Key
   - Account ID (from URL or dashboard)

### Step 2: Add Remote in CloudKlone

**In CloudKlone:**
1. Go to **Remotes** tab
2. Enter **Remote Name** (e.g., "my-r2")
3. Select **Provider: "Cloudflare R2"**
4. Fill in fields:

**Access Key ID:**
```
<your-access-key-id>
```

**Secret Access Key:**
```
<your-secret-access-key>
```

**Account Endpoint:**
```
https://<account-id>.r2.cloudflarestorage.com
```

Replace `<account-id>` with your Cloudflare account ID.

4. Click **"Add Remote"**
5. Wait for connection test
6. Should see: ✅ Connected successfully

---

## 🎯 Example Configuration

**Real example:**

```
Remote Name: cloudflare-r2
Provider: Cloudflare R2

Access Key ID: a1b2c3d4e5f6g7h8i9j0
Secret Access Key: k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
Account Endpoint: https://abc123def456.r2.cloudflarestorage.com
```

The provider, region, and ACL are set automatically (you won't see these fields).

---

## ✅ What R2 Now Works With

**After adding R2 remote, you can:**

1. **Copy to R2:**
   ```
   Source: backblaze-b2:/my-files
   Dest: cloudflare-r2:/backup
   Operation: Copy
   ```

2. **Copy from R2:**
   ```
   Source: cloudflare-r2:/backup
   Dest: local:/mnt/storage
   Operation: Copy
   ```

3. **Sync between R2 and other clouds:**
   ```
   Source: aws-s3:/bucket
   Dest: cloudflare-r2:/mirror
   Operation: Sync
   ```

---

## 🔍 Finding Your R2 Account Endpoint

**Method 1 - From Dashboard URL:**
```
If your R2 dashboard is at:
https://dash.cloudflare.com/abc123def456/r2

Your endpoint is:
https://abc123def456.r2.cloudflarestorage.com
```

**Method 2 - From R2 Settings:**
1. Go to R2 → Settings
2. Look for "Account ID" 
3. Format: `https://<account-id>.r2.cloudflarestorage.com`

---

## 🆚 R2 vs S3

**When to use each:**

**Use "Cloudflare R2"** (recommended):
- ✅ Easiest setup
- ✅ Automatic configuration
- ✅ Built for R2
- ✅ Best for new R2 users

**Use "Amazon S3":**
- For actual AWS S3 buckets
- For Wasabi
- For other S3-compatible services (not R2)

---

## 🧪 Test Your R2 Connection

**After adding remote:**

1. Go to **Remotes** tab
2. Find your R2 remote
3. Click **"Test"** button
4. Should show: ✅ Connection successful

**Or test with a transfer:**
1. Create a small test file in another remote
2. Copy it to R2
3. Check it appears in your R2 bucket

---

## 📊 Provider List Now

Your provider dropdown now shows:
1. Amazon S3
2. **Cloudflare R2** ← NEW!
3. Backblaze B2 (Native API)
4. Backblaze B2 (S3-Compatible)
5. Google Cloud Storage
6. Azure Blob Storage
7. Dropbox
8. Google Drive
9. SFTP
10. Local Filesystem

---

## 🐛 Troubleshooting R2

### "Invalid endpoint URL format"
- Make sure endpoint starts with `https://`
- Format: `https://<account-id>.r2.cloudflarestorage.com`
- No trailing slash

### "Remote connection failed"
- Check Access Key ID and Secret are correct
- Verify Account ID in endpoint URL
- Ensure API token has R2 read/write permissions

### "Bucket not found"
- Create bucket in Cloudflare R2 dashboard first
- Bucket name goes in path, not endpoint
- Example path: `/my-bucket-name/folder`

---

## ✅ Complete!

Cloudflare R2 now works properly with:
- ✅ Dedicated provider option
- ✅ Automatic configuration
- ✅ Simple 3-field setup
- ✅ Same features as other providers

Enjoy your R2 transfers! 🚀
