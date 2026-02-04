# CloudKlone Provider Configuration Review

## 📋 Systematic Review of All Providers

---

## ✅ 1. Amazon S3

**Type:** `s3`  
**Fields:**
- `provider`: select (AWS, Wasabi, Other) ✓
- `access_key_id`: text, required ✓
- `secret_access_key`: password, required ✓
- `region`: text, optional ✓
- `endpoint`: text, optional ✓

**Status:** ✅ **CORRECT**

**Validation:**
- Matches rclone S3 requirements
- provider, access_key_id, secret_access_key are standard
- region and endpoint are correctly optional
- Works for AWS S3, Wasabi, and custom S3 endpoints

---

## ✅ 2. Cloudflare R2

**Type:** `s3`  
**Fields:**
- `provider`: hidden, default='Cloudflare', required ✓
- `access_key_id`: text, required ✓
- `secret_access_key`: password, required ✓
- `endpoint`: text, required ✓
- `region`: hidden, default='auto', optional ✓
- `acl`: hidden, default='private', optional ✓

**Status:** ✅ **CORRECT**

**Validation:**
- R2 uses S3-compatible API
- provider='Cloudflare' tells rclone to use R2 mode
- endpoint is required for R2 (account-specific)
- region='auto' is correct for R2
- acl='private' is safe default

**Example endpoint:** `https://abc123.r2.cloudflarestorage.com`

---

## ✅ 3. Backblaze B2 (Native API)

**Type:** `b2`  
**Fields:**
- `account`: text, required ✓
- `key`: password, required ✓
- `hard_delete`: select (false/true), default='false', optional ✓

**Status:** ✅ **CORRECT**

**Validation:**
- Matches rclone B2 native requirements
- 'account' accepts both Account ID and Application Key ID
- 'key' is the Application Key
- hard_delete is correctly optional (false is safer default)

---

## ✅ 4. Backblaze B2 (S3-Compatible)

**Type:** `s3`  
**Fields:**
- `provider`: select (Other), required ✓
- `access_key_id`: text, required ✓
- `secret_access_key`: password, required ✓
- `endpoint`: text, required ✓
- `region`: text, optional ✓

**Status:** ✅ **CORRECT**

**Validation:**
- Uses S3-compatible API
- provider='Other' is correct
- Endpoint format: `https://s3.us-west-004.backblazeb2.com`
- Region matches endpoint region
- Application Key ID starts with '001' or '002'

---

## ⚠️ 5. Google Cloud Storage

**Type:** `google cloud storage`  
**Fields:**
- `project_number`: text, required ✓
- `service_account_file`: textarea, required ✓

**Status:** ⚠️ **NEEDS IMPROVEMENT**

**Issues:**
1. Field name should be `project_number` but rclone expects `project_number` ✓ (actually correct)
2. `service_account_file` expects JSON content ✓

**Potential improvements:**
- Could add `service_account_credentials` as alternative name
- Could add validation for JSON format
- Could add `location` for default bucket location

**Current Status:** ✅ Works but could be enhanced

**Validation:** Actually this is correct. GCS with service account needs:
- project_number (or project_id)
- service_account_file (JSON content)

---

## ✅ 6. Azure Blob Storage

**Type:** `azureblob`  
**Fields:**
- `account`: text, required ✓
- `key`: password, required ✓

**Status:** ✅ **CORRECT**

**Validation:**
- Matches rclone azureblob requirements
- 'account' is the storage account name
- 'key' is the storage account key
- Could add SAS token as alternative but not essential

---

## ⚠️ 7. Dropbox

**Type:** `dropbox`  
**Fields:**
- `token`: password, required ✓

**Status:** ⚠️ **FUNCTIONAL BUT LIMITED**

**Issues:**
- Dropbox tokens expire and need refresh
- No refresh_token field
- No app_key/app_secret for OAuth flow

**Current Status:** ✅ Works with long-lived tokens

**Recommendation:** Add note to user that token needs to be long-lived or refreshed

---

## ❌ 8. Google Drive

**Type:** `drive`  
**Fields:**
- `client_id`: text, required ✓
- `client_secret`: password, required ✓

**Status:** ❌ **INCOMPLETE - WON'T WORK**

**Critical Issues:**
1. Missing `token` field - this is REQUIRED
2. client_id and client_secret alone don't work
3. Google Drive requires OAuth flow which needs:
   - client_id
   - client_secret
   - **token** (access token from OAuth)
   - **refresh_token** (optional but recommended)

**Why it won't work:**
- rclone needs an access token to connect to Google Drive
- client_id/client_secret are used to GET a token via OAuth
- In a web app, the OAuth flow is interactive
- Without token, connection will fail

**Fix Required:** YES - need to add token field and instructions

---

## ✅ 9. SFTP

**Type:** `sftp`  
**Fields:**
- `host`: text, required ✓
- `user`: text, required ✓
- `pass`: password, optional ✓
- `port`: number, default='22', optional ✓

**Status:** ✅ **CORRECT**

**Additional features in code:**
- Automatically adds: `skip_links=true`
- Automatically adds: `set_modtime=false`
- Password is obscured using rclone obscure
- Works with password or SSH key auth

**Validation:**
- All required fields present
- Sensible defaults
- Port 22 is standard
- Password optional (can use key auth)

---

## ✅ 10. Local Filesystem

**Type:** `local`  
**Fields:** (none)

**Status:** ✅ **CORRECT**

**Validation:**
- Local filesystem needs no authentication
- Paths specified in transfer operation
- Correctly has no configuration fields

---

## 📊 Summary

| Provider | Status | Notes |
|----------|--------|-------|
| Amazon S3 | ✅ Correct | Full functionality |
| Cloudflare R2 | ✅ Correct | Dedicated provider working |
| B2 Native | ✅ Correct | All fields present |
| B2 S3 | ✅ Correct | All fields present |
| Google Cloud Storage | ⚠️ Ok | Works, could add location |
| Azure | ✅ Correct | All fields present |
| Dropbox | ⚠️ Limited | Works but token expires |
| **Google Drive** | ❌ **BROKEN** | Missing token field |
| SFTP | ✅ Correct | Enhanced with auto-config |
| Local | ✅ Correct | No config needed |

---

## 🔧 Required Fixes

### Critical: Google Drive

**Problem:** Won't work without token

**Fix:**
```javascript
{ id: 'gdrive', name: 'Google Drive', type: 'drive', fields: [
  { name: 'client_id', label: 'Client ID', type: 'text', required: true },
  { name: 'client_secret', label: 'Client Secret', type: 'password', required: true },
  { name: 'token', label: 'Access Token (JSON)', type: 'textarea', required: true },
]},
```

**Instructions for users:**
1. Create OAuth app in Google Cloud Console
2. Get client_id and client_secret
3. Run `rclone config` locally to get token
4. Copy token JSON to CloudKlone

**Alternative fix (simpler):**
```javascript
{ id: 'gdrive', name: 'Google Drive', type: 'drive', fields: [
  { name: 'token', label: 'Access Token (from rclone config)', type: 'textarea', required: true },
]},
```

Then add instructions to get token from rclone.

---

## ⚠️ Optional Improvements

### Dropbox
Add note: "Token must be long-lived. Generate from Dropbox App Console."

### Google Cloud Storage
Add optional field:
```javascript
{ name: 'location', label: 'Default Location', type: 'text', placeholder: 'us', required: false }
```

### Azure
Add alternative auth:
```javascript
{ name: 'sas_url', label: 'SAS URL (alternative to key)', type: 'text', required: false }
```

---

## ✅ What's Working Well

1. **S3-based providers** (S3, R2, B2-S3) - All correct
2. **Native B2** - Correct
3. **SFTP** - Enhanced with auto-config
4. **Local** - Simple and correct
5. **Azure** - Basic but functional
6. **GCS** - Works with service accounts

---

## 🎯 Priority Fixes

**Must Fix:**
1. ❌ Google Drive - Add token field

**Should Fix:**
2. ⚠️ Dropbox - Add token expiry note
3. ⚠️ GCS - Add location field (optional)

**Nice to Have:**
4. Azure - Add SAS URL option
5. All providers - Add "Test Connection" feedback

---

## 🧪 Testing Checklist

After fixes, test each:
- [ ] Amazon S3 - Create remote, list buckets
- [ ] Cloudflare R2 - Create remote, list buckets
- [ ] B2 Native - Create remote, list buckets
- [ ] B2 S3 - Create remote, list buckets
- [ ] GCS - Create remote with service account
- [ ] Azure - Create remote, list containers
- [ ] Dropbox - Create remote, list files
- [ ] Google Drive - Create remote (AFTER FIX)
- [ ] SFTP - Connect to server
- [ ] Local - Access filesystem

---

## 📝 Recommendations

1. **Fix Google Drive immediately** - It's currently broken
2. Add user documentation for each provider
3. Add example configurations
4. Consider adding OAuth helper for Google Drive
5. Add token refresh for Dropbox

---

Would you like me to implement the Google Drive fix?
