# CloudKlone v8 - Comprehensive Feature Implementation Plan

## Critical Bugs (Fix Immediately)

### 1. SSH Host Keys Not Showing in Admin Panel
**Status:** Bug - needs fix
**Root Cause:** Query trying to extract `username` from SFTP config which doesn't exist in that field
**Fix:** Update query to extract correct field from JSONB config

### 2. Scheduled Transfers Visibility
**Status:** Bug - needs fix  
**Root Cause:** Transfers are server-side but UI may have caching/filtering issues
**Fix:** Ensure all users can see scheduled transfers regardless of creator

### 3. Credentials Exposed in Files
**Status:** SECURITY - critical
**Root Cause:** SMTP passwords and other credentials may be in plaintext in files
**Fix:** Add .env to .gitignore, remove sensitive data from repository

---

## High Priority Features

### 4. Add Samba/SMB/CIFS Support
**Implementation:** All three are the same protocol (SMB), add single implementation
**Backend:** Add 'smb' type to remotes
**Frontend:** Add SMB option to remote types

###5. Add NFS Support
**Implementation:** Add NFS as remote type
**Backend:** Configure NFS mounts via rclone
**Frontend:** Add NFS option to remote types

### 6. Logo Update
**Implementation:** Replace all logo instances with provided purple wavy logo
**Locations:** index.html favicon, header, login page

---

## Performance & Reliability

### 7. Network Performance (--network=host)
**Investigation Required:** Test if --network=host improves speed
**Compatibility Check:** Ensure works with Docker Compose and Kubernetes
**Implementation:** Add to docker-compose.yml if compatible

### 9. Hash Checking for All Transfers
**Implementation:** Add `--checksum` flag to all rclone transfers
**UI:** Show hash verification status in progress
**Error Handling:** Retry if hashes don't match

---

## Advanced Features

### 8. Bisync (Two-Way Real-Time Sync)
**Implementation:** Use `rclone bisync` command
**UI:** New transfer type "Bisync"
**Monitoring:** Show sync status, last sync time
**Alerts:** Send notification if sync breaks

### 10. Encryption/Decryption
**Implementation:** Use `rclone crypt` remote type
**UI:** Checkbox "Encrypt this transfer" when creating
**Logs:** Mark encrypted transfers clearly
**Workflow:** Allow decrypt transfer from encrypted remote

### 11. Admin Shell
**Security:** Admin-only with confirmation dialog
**Implementation:** Terminal emulator in browser (xterm.js)
**Access:** Top-right icon, opens modal with shell
**Commands:** Full rclone access for troubleshooting

### 12. Egress Cost Warning
**Implementation:** Show modal if transfer > 100MB from cloud provider
**Tracking:** Remember dismissed warnings per schedule
**UI:** "Dismiss and Continue" or "Cancel Transfer"

### 13. Tests & Queries Section
**Implementation:** New tab with two sections
**Section 1:** Dry-run tester (--dry-run flag)
**Section 2:** Read-only query builder (lsd, ls, size, about, etc)
**Security:** Block all write commands

---

## Implementation Phases

**Phase 1 (Immediate - v8.0):**
1. Fix SSH host keys bug
2. Fix scheduled transfers visibility
3. Fix credentials exposure
4. Update logo
5. Add SMB/CIFS support
6. Add NFS support

**Phase 2 (Performance - v8.1):**
7. Implement --network=host optimization
9. Add hash checking for all transfers
12. Add egress cost warning

**Phase 3 (Advanced - v8.2):**
8. Implement bisync feature
10. Add encryption/decryption
13. Add Tests & Queries section

**Phase 4 (Admin Tools - v8.3):**
11. Add admin shell functionality

---

## Technical Notes

### SMB/CIFS/Samba Configuration
All are the same - SMB (Server Message Block) protocol:
```ini
[mysmb]
type = smb
host = server.local
user = username
pass = obscured_password
```

### NFS Configuration
```ini
[mynfs]
type = nfs
host = server.local
path = /export/share
```

### Bisync Requirements
- Requires rclone 1.58+
- Two remotes must support modtime or checksums
- Initial --resync run required
- Cannot run concurrent bisync on same path

### Hash Checking Flags
- `--checksum`: Use checksums instead of modtime
- `--check-first`: Check before transfer
- `--compare hash`: Force hash comparison

### Admin Shell Security
- Admin users only (check isAdmin)
- Warning message on open
- Command history logging to audit_logs
- No sudo/system commands, rclone only

### Egress Warning Providers
Charge egress: AWS S3, Google Cloud, Azure, Wasabi
No egress: Cloudflare R2, Backblaze B2

---

## Database Schema Changes

```sql
-- For bisync feature
ALTER TABLE transfers ADD COLUMN is_bisync BOOLEAN DEFAULT false;
ALTER TABLE transfers ADD COLUMN last_sync_time TIMESTAMP;
ALTER TABLE transfers ADD COLUMN sync_status VARCHAR(50);

-- For encryption feature  
ALTER TABLE transfers ADD COLUMN is_encrypted BOOLEAN DEFAULT false;
ALTER TABLE transfers ADD COLUMN crypt_password VARCHAR(255);

-- For egress warnings
ALTER TABLE transfers ADD COLUMN egress_warning_dismissed BOOLEAN DEFAULT false;

-- For shell commands
CREATE TABLE shell_history (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  command TEXT NOT NULL,
  output TEXT,
  exit_code INTEGER,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Estimated Timeline

- **Phase 1:** 2-3 days (critical bugs + basic features)
- **Phase 2:** 2-3 days (performance improvements)
- **Phase 3:** 3-4 days (complex features)
- **Phase 4:** 2-3 days (admin tools)

**Total:** 9-13 days for complete implementation

---

## Testing Requirements

Each feature requires:
1. Unit testing (backend functions)
2. Integration testing (API endpoints)
3. UI testing (frontend components)
4. Security testing (permissions, escaping)
5. Performance testing (network=host benchmark)

---

## Documentation Updates

For each feature, update:
- DEPLOYMENT-GUIDE.md
- FEATURES.md  
- ENTERPRISE-OVERVIEW.md
- README.md

---

## Priority Decision Matrix

| Feature | Impact | Complexity | Priority |
|---------|--------|------------|----------|
| SSH keys fix | High | Low | CRITICAL |
| Scheduled visibility | High | Low | CRITICAL |
| Credentials security | High | Low | CRITICAL |
| Logo update | Low | Low | Quick Win |
| SMB/NFS support | High | Medium | High |
| Network performance | High | Low | High |
| Hash checking | Medium | Low | Medium |
| Bisync | Medium | High | Medium |
| Encryption | Medium | Medium | Medium |
| Egress warning | Low | Low | Low |
| Tests & Queries | Medium | Medium | Low |
| Admin shell | High | High | Low |

---

## Next Steps

1. Fix critical bugs (items 1-3)
2. Update logo (item 14)
3. Add network share support (items 4-6)
4. Implement performance improvements (items 7, 9)
5. Add advanced features (items 8, 10, 13)
6. Add admin tools (items 11, 12)
