# CloudKlone - Cloudflare R2 Provider Fix

## 🐛 Bug Found

When selecting "Cloudflare R2" from the provider dropdown, it was showing the wrong fields (AWS/Wasabi/Other instead of R2-specific fields).

### Root Cause
The frontend was using `provider.type` to match providers, but both "Amazon S3" and "Cloudflare R2" have `type='s3'`. When you selected "Cloudflare R2", it found the first provider with type='s3', which was Amazon S3.

---

## ✅ Fix Applied

**Changed provider matching to use unique IDs:**

### Before (Broken):
```javascript
// Dropdown value was the type
select.innerHTML += `<option value="${p.type}">${p.name}</option>`;

// Matched by type (not unique!)
const provider = data.providers.find(p => p.type === e.target.value);

// Sent type to backend
const type = document.getElementById('provider').value;
```

**Problem:** Both S3 and R2 have `type='s3'`, so it matched the wrong one.

### After (Fixed):
```javascript
// Dropdown value is the unique ID
select.innerHTML += `<option value="${p.id}">${p.name}</option>`;

// Match by ID (unique!)
const provider = data.providers.find(p => p.id === e.target.value);

// Look up actual type from provider
const selectedProvider = providersData.find(p => p.id === providerId);
const type = selectedProvider.type;
```

**Solution:** Each provider has a unique ID, so we match by that, then send the correct type to backend.

---

## 🚀 Deploy Fix

```bash
cd ~
tar -xzf cloudklone-v5-r2-working.tar.gz
cd cloudklone
sudo docker-compose down
sudo docker-compose up -d
```

**Hard refresh browser:** `Ctrl+Shift+R` or `Cmd+Shift+R`

---

## ✅ Test Cloudflare R2

After deploying:

1. **Go to Remotes tab**
2. **Enter Remote Name:** `my-r2`
3. **Select Provider:** `Cloudflare R2`
4. **You should now see:**
   - ✅ Access Key ID
   - ✅ Secret Access Key
   - ✅ Account Endpoint (with placeholder)
   - ❌ NO "Provider" dropdown
   - ❌ NO "Region" field

5. **Fill in:**
   ```
   Access Key ID: <your-r2-access-key>
   Secret Access Key: <your-r2-secret>
   Account Endpoint: https://<account-id>.r2.cloudflarestorage.com
   ```

6. **Click "Add Remote"**
7. **Should connect successfully!**

---

## 📋 Provider IDs

Each provider now has a unique ID:

| Provider | ID | Type |
|----------|-----|------|
| Amazon S3 | `s3` | `s3` |
| Cloudflare R2 | `r2` | `s3` |
| Backblaze B2 (Native) | `b2` | `b2` |
| Backblaze B2 (S3) | `b2-s3` | `s3` |
| Google Cloud Storage | `gcs` | `google cloud storage` |
| Azure Blob | `azure` | `azureblob` |
| Dropbox | `dropbox` | `dropbox` |
| Google Drive | `gdrive` | `drive` |
| SFTP | `sftp` | `sftp` |
| Local Filesystem | `local` | `local` |

---

## 🎯 What Works Now

**When you select "Cloudflare R2":**
1. ✅ Shows only R2-specific fields
2. ✅ Hides AWS/Wasabi/Other dropdown
3. ✅ Automatically sets `provider=Cloudflare`
4. ✅ Automatically sets `region=auto`
5. ✅ Automatically sets `acl=private`
6. ✅ Only asks for: Access Key, Secret Key, Endpoint
7. ✅ Sends correct `type=s3` to backend

---

## 🔍 Hidden Fields Working

For Cloudflare R2, these are set automatically:
```javascript
provider: 'Cloudflare'  // Hidden field
region: 'auto'          // Hidden field
acl: 'private'          // Hidden field
```

You won't see these fields in the form, but they're included when you click "Add Remote".

---

## ✅ Complete Fix Summary

**Changes:**
1. ✅ Provider dropdown uses unique IDs
2. ✅ Provider selection matches by ID
3. ✅ Form submission looks up correct type
4. ✅ Hidden fields with defaults work correctly
5. ✅ R2 shows correct fields

**Files Changed:**
- `/backend/index.html` - Frontend provider logic

**No Backend Changes Required** - Backend was already correct!

---

## 🧪 Verify It's Working

**Console test (F12 → Console):**
```javascript
// Should show R2 with id='r2', type='s3'
fetch('/api/providers').then(r => r.json()).then(console.log)
```

**Look for:**
```json
{
  "providers": [
    { "id": "s3", "name": "Amazon S3", "type": "s3", ... },
    { "id": "r2", "name": "Cloudflare R2", "type": "s3", ... }
  ]
}
```

Both have `type='s3'` but different `id` values!

---

## 🎉 Done!

Cloudflare R2 remote creation now works correctly. Each provider shows its correct fields based on unique IDs.

Enjoy your R2 transfers! 🚀
