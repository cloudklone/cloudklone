# Managing Remotes

Remotes are your connections to cloud storage providers. Think of them as bookmarks to your different storage locations.

## What is a Remote?

A remote is a saved connection to a cloud storage service like:
- Amazon S3
- Google Drive
- Dropbox
- Microsoft OneDrive
- SFTP servers
- Local storage
- And 40+ more providers

Once you add a remote, you can use it in transfers without entering credentials every time.

## Adding a New Remote

### Step 1: Open the Remotes Tab
Click **Remotes** in the left sidebar.

### Step 2: Click Add Remote
You'll see a form with these fields:

**Remote Name**
- Choose a memorable name (e.g., "work-s3-bucket" or "personal-drive")
- Use letters, numbers, and hyphens only
- No spaces allowed

**Remote Type**
- Select your storage provider from the dropdown
- Common types: s3, drive, dropbox, sftp, onedrive

**Configuration**
- Paste your JSON configuration
- Format varies by provider (see examples below)

### Step 3: Test Your Remote
**Always test before saving!**

1. Click **Test Remote**
2. Wait for the test to complete
3. Look for a success message
4. If it fails, check your configuration

### Step 4: Save
Click **Add Remote** to save it.

## Configuration Examples

### Amazon S3
```json
{
  "type": "s3",
  "provider": "AWS",
  "access_key_id": "YOUR_ACCESS_KEY",
  "secret_access_key": "YOUR_SECRET_KEY",
  "region": "us-east-1"
}
```

### Google Drive
```json
{
  "type": "drive",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "token": "YOUR_TOKEN",
  "scope": "drive"
}
```

### Dropbox
```json
{
  "type": "dropbox",
  "token": "YOUR_DROPBOX_TOKEN"
}
```

### SFTP Server
```json
{
  "type": "sftp",
  "host": "sftp.example.com",
  "user": "username",
  "pass": "password",
  "port": "22"
}
```

### Local Storage
```json
{
  "type": "local"
}
```

**Need your config?** Most providers require you to create API credentials in their developer console first.

## Managing Existing Remotes

### View All Remotes
The Remotes tab shows all your configured connections with:
- Remote name
- Provider type
- Test status (✓ or ✗)
- Actions (Test, Edit, Delete)

### Test a Remote
Click **Test** next to any remote to verify it's still working.

**Why test?**
- Credentials might expire
- Permissions might change
- Network issues could occur

### Edit a Remote
1. Click **Edit** next to the remote
2. Update the configuration
3. Click **Test Remote** to verify changes
4. Click **Update Remote**

**Warning:** Editing a remote used in scheduled transfers will affect those transfers.

### Delete a Remote
1. Click **Delete** next to the remote
2. Confirm the deletion

**Warning:** You cannot delete a remote that's being used in active or scheduled transfers.

## Common Remote Types

### Cloud Storage
- **s3** - Amazon S3, DigitalOcean Spaces, Wasabi
- **drive** - Google Drive
- **dropbox** - Dropbox
- **onedrive** - Microsoft OneDrive
- **box** - Box.com
- **gcs** - Google Cloud Storage
- **azureblob** - Azure Blob Storage

### File Servers
- **sftp** - SSH/SFTP servers
- **ftp** - FTP servers
- **webdav** - WebDAV servers
- **smb** - Windows shares (SMB/CIFS)

### Local
- **local** - Local filesystem

## Best Practices

### Naming Conventions
✅ **Good names:**
- `aws-production-bucket`
- `personal-gdrive`
- `backup-sftp`

❌ **Bad names:**
- `remote1`
- `test`
- `my remote` (spaces not allowed)

### Security Tips
- **Never share** your remote configurations
- **Rotate credentials** regularly
- **Use read-only** access when possible
- **Test after changes** to credentials
- **Delete unused** remotes

### Organization
- Use descriptive names that indicate purpose
- Group similar remotes with prefixes (e.g., `prod-`, `dev-`)
- Keep personal and work remotes separate
- Document special configurations

## Troubleshooting

### "Test failed" Error
**Possible causes:**
- Wrong credentials
- Expired access tokens
- Network connectivity issue
- Provider service down
- Incorrect region/endpoint

**Solutions:**
1. Double-check credentials
2. Verify network connectivity
3. Check provider status page
4. Re-create API tokens
5. Contact your administrator

### "Cannot delete remote" Error
**Cause:** Remote is being used in transfers

**Solution:**
1. Check active transfers
2. Check scheduled transfers
3. Delete or update those transfers first
4. Then delete the remote

### Configuration Format Error
**Cause:** Invalid JSON format

**Solution:**
- Use a JSON validator
- Check for missing quotes
- Check for missing commas
- Ensure proper bracket matching

## Getting Credentials

### AWS S3
1. Go to AWS IAM Console
2. Create a new user with programmatic access
3. Attach S3 permissions policy
4. Copy access key and secret key

### Google Drive
1. Go to Google Cloud Console
2. Create a new project
3. Enable Google Drive API
4. Create OAuth credentials
5. Copy client ID and secret

### Dropbox
1. Go to Dropbox App Console
2. Create a new app
3. Generate an access token
4. Copy the token

**Need help?** Check your provider's documentation for detailed credential setup instructions.

## Quick Reference

| Task | Steps |
|------|-------|
| Add remote | Remotes → Add Remote → Fill form → Test → Save |
| Test remote | Remotes → Click Test next to remote |
| Edit remote | Remotes → Click Edit → Update → Test → Save |
| Delete remote | Remotes → Click Delete → Confirm |
| View all | Click Remotes tab |

---

**Remember:** Always test your remotes after adding or editing them. A successful test means you're ready to transfer files!
