# Backblaze B2 Configuration Guide

## Which B2 Option Should You Use?

CloudKlone now offers TWO ways to connect to Backblaze B2:

### Option 1: Backblaze B2 (Native API) ✅ RECOMMENDED
**Use this if:** You created a "Master Application Key" or "App Key" in B2's "App Keys" section

**Configuration:**
- **Account ID or Application Key ID**: Found in B2 under "App Keys" 
  - Format: `001abc123def456...` (starts with 001, 002, etc.)
- **Application Key**: The secret key shown once when you create it
  - Format: `K001abc...` (starts with K)

**No endpoint needed!** Rclone auto-detects the B2 endpoint.

---

### Option 2: Backblaze B2 (S3-Compatible) 🔧 ADVANCED
**Use this if:** You need S3-compatible access or are getting "authorization forbidden" errors

**Configuration:**
- **Provider**: Select "Other"
- **Application Key ID**: Your B2 Application Key ID
  - Format: `001abc123def456...`
- **Application Key**: Your B2 Application Key
  - Format: `K001abc...`
- **Endpoint URL**: **REQUIRED!** Find this in B2 dashboard
  - Format: `https://s3.us-west-004.backblazeb2.com`
  - Look for "Endpoint" next to your bucket
- **Region**: Optional, matches your endpoint
  - Examples: `us-west-004`, `us-east-005`, `eu-central-003`

---

## How to Find Your B2 Endpoint

1. Log into Backblaze B2
2. Go to **Buckets**
3. Click on your bucket
4. Look for **"Endpoint"** section
5. Copy the URL (e.g., `https://s3.us-west-004.backblazeb2.com`)

**Common B2 Endpoints:**
- US West: `https://s3.us-west-000.backblazeb2.com` through `004`
- US East: `https://s3.us-east-000.backblazeb2.com` through `005`
- EU Central: `https://s3.eu-central-003.backblazeb2.com`

---

## Troubleshooting "Authorization Forbidden"

### Issue 1: Wrong Credentials
❌ **Don't use:** Master Application Key (starts with `00...`)  
✅ **Do use:** Application Key ID (starts with `001...`, `002...`)

### Issue 2: Missing Endpoint (S3-Compatible)
If using B2 (S3-Compatible), you **MUST** specify the endpoint URL.

### Issue 3: Wrong Capability
Make sure your B2 Application Key has these capabilities:
- ✅ `listBuckets`
- ✅ `listFiles`
- ✅ `readFiles`
- ✅ `writeFiles`
- ✅ `deleteFiles` (if you want delete capability)

### Issue 4: Bucket-Specific Key
If you created a key for a **specific bucket**, make sure you're accessing that bucket only.

---

## Quick Test

After adding your B2 remote, click the **Test** button to verify:
- ✅ Credentials are correct
- ✅ Endpoint is reachable
- ✅ Permissions are sufficient

---

## Examples

### Example 1: Native API (Simple)
```
Remote Name: my-b2
Provider: Backblaze B2 (Native API)
Account ID: 001a23b45c67d89e0f12
Application Key: K001abcdefghijklmnopqrstuvwxyz
```

### Example 2: S3-Compatible (Advanced)
```
Remote Name: my-b2-s3
Provider: Backblaze B2 (S3-Compatible)
Provider Type: Other
Application Key ID: 001a23b45c67d89e0f12
Application Key: K001abcdefghijklmnopqrstuvwxyz
Endpoint URL: https://s3.us-west-004.backblazeb2.com
Region: us-west-004
```

---

## Still Having Issues?

1. **Double-check credentials** - Copy/paste directly from B2
2. **Verify endpoint** - Must match your bucket's region
3. **Check capabilities** - Key must have required permissions
4. **Try Native API first** - Simpler and auto-configures endpoint
5. **Test connection** - Use the Test button before creating transfers

---

## Performance Tips

- Native B2 API is generally faster and more reliable
- Use S3-Compatible only if you need S3 tooling compatibility
- B2 has free egress to Cloudflare - great for B2→R2 transfers!
