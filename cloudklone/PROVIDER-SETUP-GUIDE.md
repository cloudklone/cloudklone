# CloudKlone Provider Setup Guide

Complete instructions for configuring each cloud storage provider.

---

## 🎯 Quick Reference

| Provider | Difficulty | Auth Method | Notes |
|----------|-----------|-------------|-------|
| **Local Filesystem** | ⭐ Easy | None | Works immediately |
| **SFTP** | ⭐ Easy | Password/Key | Standard SSH |
| **Amazon S3** | ⭐⭐ Medium | API Keys | IAM user needed |
| **Cloudflare R2** | ⭐⭐ Medium | API Keys | Account endpoint required |
| **Backblaze B2** | ⭐⭐ Medium | API Keys | Two methods available |
| **Azure Blob** | ⭐⭐ Medium | Account Key | From Azure Portal |
| **Dropbox** | ⭐⭐⭐ Medium | OAuth Token | Generate in App Console |
| **Google Cloud Storage** | ⭐⭐⭐ Hard | Service Account | JSON file needed |
| **Google Drive** | ⭐⭐⭐⭐ Hard | OAuth Token | Requires rclone config |

---

## 1. Local Filesystem

**Difficulty:** ⭐ Easy  
**Setup Time:** Instant

### Fields Required
- None!

### How to Use
1. Select "Local Filesystem" as provider
2. Enter remote name (e.g., "local-storage")
3. Click "Add Remote"
4. Use paths in transfers: `/mnt/data`, `/home/user/files`, etc.

### Example Paths
```
/mnt/storage/backups
/home/matthew/documents
/var/www/uploads
```

---

## 2. SFTP

**Difficulty:** ⭐ Easy  
**Setup Time:** 2 minutes

### Fields Required
- **Host:** Hostname or IP address
- **Username:** SSH username
- **Password:** SSH password (optional if using key auth)
- **Port:** Default 22

### Step-by-Step

1. **Get your SSH credentials**
   - Host: `example.com` or `192.168.1.100`
   - Username: Your SSH user
   - Password: Your SSH password

2. **Add in CloudKlone**
   ```
   Remote Name: my-server
   Provider: SFTP
   Host: example.com
   Username: matthew
   Password: your-password
   Port: 22
   ```

3. **Test connection**
   - Click "Add Remote"
   - Should connect and list files

### Auto-Configured
CloudKlone automatically sets:
- `skip_links = true` (skip symbolic links)
- `set_modtime = false` (don't set modification times)
- Password is encrypted with rclone obscure

---

## 3. Amazon S3

**Difficulty:** ⭐⭐ Medium  
**Setup Time:** 10 minutes

### Fields Required
- **Provider:** AWS (or Wasabi/Other)
- **Access Key ID:** From IAM user
- **Secret Access Key:** From IAM user
- **Region:** e.g., `us-east-1` (optional)
- **Endpoint:** Only for custom/Wasabi (optional)

### Step-by-Step

1. **Create IAM User in AWS**
   - Go to AWS Console → IAM → Users
   - Click "Add User"
   - Select "Programmatic access"
   - Attach policy: `AmazonS3FullAccess` (or custom policy)
   - Save Access Key ID and Secret Access Key

2. **Add in CloudKlone**
   ```
   Remote Name: aws-s3
   Provider: AWS
   Access Key ID: <YOUR_AWS_ACCESS_KEY_ID>
   Secret Access Key: <YOUR_AWS_SECRET_ACCESS_KEY>
   Region: us-east-1
   Endpoint: (leave blank for AWS)
   ```

3. **Use in transfers**
   - Path format: `/bucket-name/folder/file.txt`

### For Wasabi
```
Provider: Wasabi
Endpoint: https://s3.wasabisys.com
Region: us-east-1
```

---

## 4. Cloudflare R2

**Difficulty:** ⭐⭐ Medium  
**Setup Time:** 10 minutes

### Fields Required
- **Access Key ID:** From R2 API token
- **Secret Access Key:** From R2 API token
- **Account Endpoint:** Your R2 endpoint URL

### Step-by-Step

1. **Get R2 Credentials**
   - Go to Cloudflare Dashboard
   - Navigate to R2 → Overview
   - Click "Manage R2 API Tokens"
   - Click "Create API Token"
   - Give it a name
   - Set permissions: "Object Read & Write"
   - Click "Create API Token"
   - **Save these immediately:**
     - Access Key ID
     - Secret Access Key

2. **Get Your Account ID**
   - Look at your browser URL: `https://dash.cloudflare.com/YOUR-ACCOUNT-ID/r2`
   - Or find it in R2 → Settings

3. **Add in CloudKlone**
   ```
   Remote Name: cloudflare-r2
   Provider: Cloudflare R2
   Access Key ID: <your-access-key>
   Secret Access Key: <your-secret-key>
   Account Endpoint: https://<account-id>.r2.cloudflarestorage.com
   ```

4. **Use in transfers**
   - Path format: `/bucket-name/folder/file.txt`

### Example
```
Account ID: abc123def456
Endpoint: https://abc123def456.r2.cloudflarestorage.com
```

---

## 5. Backblaze B2 (Native API)

**Difficulty:** ⭐⭐ Medium  
**Setup Time:** 5 minutes

### Fields Required
- **Account ID or Application Key ID:** From B2 console
- **Application Key:** From B2 console
- **Hard Delete:** false (recommended) or true

### Step-by-Step

1. **Get B2 Credentials**
   - Go to Backblaze B2 Console
   - Navigate to "App Keys"
   - Click "Add a New Application Key"
   - Give it a name
   - Select capabilities (read/write)
   - Click "Create New Key"
   - **Save immediately:**
     - Application Key ID (starts with `002` or `003`)
     - Application Key (shows only once!)

2. **Add in CloudKlone**
   ```
   Remote Name: backblaze-b2
   Provider: Backblaze B2 (Native API)
   Account ID or Application Key ID: 002abc123def456
   Application Key: K002...
   Hard Delete: false
   ```

3. **Use in transfers**
   - Path format: `/bucket-name/folder/file.txt`

### Hard Delete Option
- **false (recommended):** Files are hidden, not deleted (recoverable)
- **true:** Files are permanently deleted immediately

---

## 6. Backblaze B2 (S3-Compatible)

**Difficulty:** ⭐⭐ Medium  
**Setup Time:** 5 minutes

### Fields Required
- **Provider:** Other
- **Application Key ID:** From B2 (starts with 001/002/003)
- **Application Key:** From B2
- **Endpoint URL:** Regional S3 endpoint
- **Region:** Matches endpoint region

### Step-by-Step

1. **Get B2 S3 Credentials** (same as native)
   - Follow steps from "Backblaze B2 (Native API)" above

2. **Get S3 Endpoint**
   - In B2 Console → Buckets
   - Click on your bucket
   - Look for "S3 Compatible API"
   - Endpoint format: `https://s3.us-west-004.backblazeb2.com`

3. **Add in CloudKlone**
   ```
   Remote Name: b2-s3
   Provider: Other
   Application Key ID: 001abc123def456
   Application Key: K001...
   Endpoint URL: https://s3.us-west-004.backblazeb2.com
   Region: us-west-004
   ```

---

## 7. Google Cloud Storage

**Difficulty:** ⭐⭐⭐ Hard  
**Setup Time:** 15 minutes

### Fields Required
- **Project Number:** From GCP Console
- **Service Account JSON:** Entire JSON file contents

### Step-by-Step

1. **Create Service Account**
   - Go to Google Cloud Console
   - Navigate to IAM & Admin → Service Accounts
   - Click "Create Service Account"
   - Name it (e.g., "cloudklone")
   - Grant role: "Storage Admin" or "Storage Object Admin"
   - Click "Done"

2. **Create JSON Key**
   - Click on the service account you created
   - Go to "Keys" tab
   - Click "Add Key" → "Create New Key"
   - Select "JSON"
   - Click "Create"
   - JSON file downloads automatically

3. **Get Project Number**
   - In GCP Console → Home Dashboard
   - Project Number is shown at top
   - Or go to IAM & Admin → Settings

4. **Add in CloudKlone**
   ```
   Remote Name: google-cloud
   Provider: Google Cloud Storage
   Project Number: 123456789012
   Service Account JSON: (paste entire JSON file contents)
   ```

### Example Service Account JSON
```json
{
  "type": "service_account",
  "project_id": "my-project",
  "private_key_id": "abc123...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "client_email": "cloudklone@my-project.iam.gserviceaccount.com",
  "client_id": "123456789",
  ...
}
```

---

## 8. Azure Blob Storage

**Difficulty:** ⭐⭐ Medium  
**Setup Time:** 5 minutes

### Fields Required
- **Storage Account:** Account name
- **Storage Account Key:** Access key

### Step-by-Step

1. **Get Credentials from Azure Portal**
   - Go to Azure Portal
   - Navigate to Storage Accounts
   - Click on your storage account
   - In left menu: Settings → Access Keys
   - Click "Show keys"
   - **Copy:**
     - Storage account name (top of page)
     - key1 or key2 value

2. **Add in CloudKlone**
   ```
   Remote Name: azure-storage
   Provider: Azure Blob Storage
   Storage Account: mystorageaccount
   Storage Account Key: abc123def456...
   ```

3. **Use in transfers**
   - Path format: `/container-name/folder/file.txt`

---

## 9. Dropbox

**Difficulty:** ⭐⭐⭐ Medium  
**Setup Time:** 10 minutes

### Fields Required
- **Access Token:** OAuth token from Dropbox

### Step-by-Step

1. **Create Dropbox App**
   - Go to https://www.dropbox.com/developers/apps
   - Click "Create App"
   - Choose "Scoped access"
   - Choose "Full Dropbox" access
   - Name your app
   - Click "Create App"

2. **Generate Access Token**
   - In app settings page
   - Scroll to "OAuth 2"
   - Under "Generated access token"
   - Click "Generate"
   - **Copy the token immediately!**

3. **Set Token to No Expiration** (Important!)
   - In app settings
   - Go to "Permissions" tab
   - Select needed permissions
   - Go back to "Settings"
   - Generated tokens are now long-lived

4. **Add in CloudKlone**
   ```
   Remote Name: my-dropbox
   Provider: Dropbox
   Access Token: sl.A...
   ```

### ⚠️ Important Note
Dropbox tokens CAN expire. If transfers stop working, regenerate token and update remote.

---

## 10. Google Drive

**Difficulty:** ⭐⭐⭐⭐ Hard  
**Setup Time:** 20 minutes

### Fields Required
- **Client ID:** From Google Cloud Console (optional)
- **Client Secret:** From Google Cloud Console (optional)
- **Token:** OAuth token JSON (REQUIRED)
- **Root Folder ID:** Specific folder (optional)

### Step-by-Step (Requires rclone on local machine)

1. **Install rclone locally**
   ```bash
   # Linux/Mac
   curl https://rclone.org/install.sh | sudo bash
   
   # Windows
   # Download from https://rclone.org/downloads/
   ```

2. **Run rclone config locally**
   ```bash
   rclone config
   
   # Follow prompts:
   # n) New remote
   # name> gdrive-temp
   # Storage> drive (select Google Drive)
   # client_id> (press Enter or paste your own)
   # client_secret> (press Enter or paste your own)
   # scope> 1 (Full access)
   # root_folder_id> (press Enter)
   # service_account_file> (press Enter)
   # Configure as team drive> n
   # Auto config> Y
   
   # Browser opens for Google OAuth
   # Allow access
   # Copy success message
   ```

3. **Get the token from config**
   ```bash
   # Linux/Mac
   cat ~/.config/rclone/rclone.conf
   
   # Windows
   notepad %USERPROFILE%\.config\rclone\rclone.conf
   ```

4. **Copy token field**
   Look for your remote section:
   ```ini
   [gdrive-temp]
   type = drive
   client_id = xxx
   client_secret = yyy
   token = {"access_token":"...","token_type":"Bearer",...}  ← COPY THIS
   ```

5. **Add in CloudKlone**
   ```
   Remote Name: google-drive
   Provider: Google Drive
   Client ID: (optional - can leave blank)
   Client Secret: (optional - can leave blank)
   Token: (paste entire JSON token)
   Root Folder ID: (blank for root, or specific folder ID)
   ```

### Why So Complex?
Google Drive requires OAuth which needs interactive browser auth. The easiest way is to use rclone locally to get the token, then paste it into CloudKlone.

---

## 🧪 Testing Your Remotes

After adding any remote:

1. **In CloudKlone:**
   - Go to Remotes tab
   - Find your remote
   - Click "Test" button
   - Should see "✅ Connected successfully"

2. **Test with a transfer:**
   - Go to Transfers tab
   - Select your remote as source or destination
   - Try copying a small test file

---

## 🔒 Security Notes

### What's Encrypted
- ✅ All credentials stored encrypted in database
- ✅ SFTP passwords obscured with rclone
- ✅ Access keys, secret keys, tokens all encrypted

### What You Should Do
- Use dedicated API keys (not root/admin credentials)
- Use minimum required permissions
- Rotate keys periodically
- Don't share your CloudKlone database

---

## ❓ Troubleshooting

### "Remote connection failed"
1. Double-check credentials
2. Verify endpoint URLs
3. Check network connectivity
4. Try "Test" button for specific error

### "Permission denied"
1. Check API key has right permissions
2. For cloud storage, verify IAM policies
3. For SFTP, check SSH user has access

### "Invalid endpoint"
1. Must start with `https://`
2. Check for typos
3. Verify account ID (for R2)
4. Check region matches (for B2/S3)

---

## 📞 Need Help?

**Check logs:**
```bash
sudo docker-compose logs app | tail -100
```

**Test rclone directly:**
```bash
sudo docker-compose exec app rclone lsd remote-name:
```

---

Enjoy your CloudKlone! 🚀
