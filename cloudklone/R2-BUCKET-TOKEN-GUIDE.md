# CloudKlone - R2 Bucket-Specific Token Support

## 🎯 What This Fixes

If your Cloudflare R2 API token has **Object Read & Write** permissions for a **specific bucket** (not Admin permissions), CloudKlone can now test the connection properly!

---

## ✅ What Changed

### Before (Failed with 403)
- CloudKlone tested by listing ALL buckets: `rclone lsd remote:`
- Bucket-specific tokens don't have permission to list all buckets
- Connection test failed with "Access Denied"

### After (Works!)
- CloudKlone can test against a **specific bucket**: `rclone lsd remote:bucket-name`
- New optional field: **"Bucket Name (for testing)"**
- Only used during connection test, not saved in config

---

## 🚀 Deploy

```bash
cd ~
tar -xzf cloudklone-v5-r2-bucket-support.tar.gz
cd cloudklone
sudo docker-compose down
sudo docker-compose up -d
```

**Hard refresh browser:** `Ctrl+Shift+R`

---

## 📋 How to Use with Bucket-Specific Token

### Your R2 Token Setup
You have a token with:
- ✅ **Object Read & Write**
- ✅ **Access to specific bucket** (e.g., "my-bucket")
- ❌ **No Admin permissions** (cannot list all buckets)

### Add Remote in CloudKlone

1. **Go to Remotes tab**
2. **Fill in fields:**

```
Remote Name: cloudflaretest

Provider: Cloudflare R2

Access Key ID: f109d798fcc1da0ac41f1f5bf2356522

Secret Access Key: ********** (your secret)

Account Endpoint: https://8cea2d4699181fcc7b591d3e9f1ac367.r2.cloudflarestorage.com

Bucket Name (for testing): my-bucket-name  ← YOUR BUCKET NAME HERE
```

3. **Click "Add Remote"**
4. **Should see:** ✅ Connected successfully to bucket 'my-bucket-name'. Found X items. (Cloudflare R2)

---

## 🎯 Two Ways to Use R2

### Option 1: Admin Token (List All Buckets)

**Token Permissions:** Admin Read & Write

**Add Remote:**
```
Remote Name: my-r2
Provider: Cloudflare R2
Access Key ID: abc123...
Secret Access Key: xyz789...
Account Endpoint: https://account-id.r2.cloudflarestorage.com
Bucket Name: (leave blank)
```

**Use in Transfers:**
```
Source: my-r2:/any-bucket/path
Dest: other-remote:/destination
```

**Benefit:** Can access any bucket without specifying

---

### Option 2: Bucket-Specific Token (Your Case!)

**Token Permissions:** Object Read & Write on "my-bucket"

**Add Remote:**
```
Remote Name: my-r2
Provider: Cloudflare R2
Access Key ID: f109d798fcc1da0ac41f1f5bf2356522
Secret Access Key: ********
Account Endpoint: https://8cea2d4699181fcc7b591d3e9f1ac367.r2.cloudflarestorage.com
Bucket Name: my-bucket  ← Bucket your token has access to
```

**Use in Transfers:**
```
Source: my-r2:/my-bucket/path
Dest: other-remote:/destination
```

**Important:** Always specify the bucket name in paths!

---

## ⚠️ Important Notes

### Bucket Name Field is ONLY for Testing

The "Bucket Name (for testing)" field:
- ✅ Used during connection test to verify credentials
- ✅ Removed after testing - NOT saved in config
- ✅ Not used during actual transfers

**Why?** You must specify bucket in transfer paths anyway:
- `remote:/bucket-name/path` ← Always required

### You Must Specify Bucket in Paths

When using bucket-specific tokens, always include bucket name in paths:

**Correct:**
```
Source: my-r2:/my-bucket/folder/file.txt
Dest: local:/backups
```

**Wrong:**
```
Source: my-r2:/folder/file.txt  ← Missing bucket name!
```

---

## 🧪 Test Your Setup

### 1. Add Remote with Bucket Name

Fill in all fields including bucket name, click "Add Remote"

**Expected:**
```
✅ Connected successfully to bucket 'my-bucket'. Found X items. (Cloudflare R2)
```

### 2. Create Test Transfer

```
Operation: Copy
Source Remote: (any remote with a small file)
Source Path: /path/to/test-file.txt
Destination Remote: my-r2
Destination Path: /my-bucket/test/test-file.txt
```

Click "Start Transfer"

**Expected:** File copies successfully to your R2 bucket!

---

## 🔍 Troubleshooting

### Still Getting 403 After Adding Bucket Name?

**Check:**
1. ✅ Bucket name is spelled correctly (case-sensitive!)
2. ✅ Token has permissions for that exact bucket
3. ✅ Account endpoint is correct
4. ✅ Credentials are valid

**Verify in Cloudflare:**
- Go to R2 → Manage R2 API Tokens
- Click on your token
- Check "Permissions" - should show bucket name

### "Remote connection failed" with Different Error?

**Could be:**
- Wrong endpoint URL
- Expired credentials
- Network connectivity issue

**Check logs:**
```bash
sudo docker-compose logs app | tail -50
```

---

## 📊 Permission Comparison

| Token Type | List All Buckets? | Create Buckets? | Read/Write Objects? | CloudKlone Test Method |
|------------|-------------------|-----------------|---------------------|------------------------|
| **Admin R&W** | ✅ Yes | ✅ Yes | ✅ Yes | Lists root: `remote:` |
| **Bucket-Specific** | ❌ No | ❌ No | ✅ Yes (in bucket) | Lists bucket: `remote:bucket` |

---

## ✅ What You Can Do Now

With bucket-specific token setup:

1. ✅ **Copy TO R2:**
   ```
   local:/files → my-r2:/my-bucket/backups
   ```

2. ✅ **Copy FROM R2:**
   ```
   my-r2:/my-bucket/data → local:/restore
   ```

3. ✅ **Sync between clouds:**
   ```
   aws-s3:/source-bucket → my-r2:/my-bucket/mirror
   ```

4. ✅ **Schedule transfers**
5. ✅ **View transfer history**
6. ✅ **Monitor progress**

---

## 🎉 Done!

Your bucket-specific R2 token now works with CloudKlone!

**Remember:**
- Bucket name field is ONLY for testing
- Always include bucket in transfer paths
- Token can only access the specific bucket it's granted access to

Happy transferring! 🚀
