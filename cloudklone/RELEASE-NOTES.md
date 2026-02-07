# CloudKlone v7 - Final Release Notes

## Changes in This Release

### 1. Professional Documentation
- Removed all emojis from code, logs, and documentation
- Consolidated 50+ documentation files into 3 essential guides
- Created professional deployment guide focused on fresh installations

### 2. Comprehensive Audit Logging
- Added audit logging for user creation
- Added audit logging for user updates (email, group, admin status, password)
- Added audit logging for user deletion
- Added audit logging for group deletion
- All user actions in the UI are now logged to the audit_logs table

### 3. Security Enhancements
- HTTPS enabled by default with auto-generated self-signed certificate
- SSH host key verification for SFTP remotes (automatic ssh-keyscan)
- Forced password change on first admin login
- HTTP to HTTPS automatic redirect

## Documentation Structure

**README.md** - Quick start guide and basic information
**DEPLOYMENT-GUIDE.md** - Complete deployment, configuration, and troubleshooting reference
**FEATURES.md** - Detailed feature documentation

All migration guides, historical changelogs, and version-specific documentation have been removed.

## Audit Logging Coverage

The following actions are now logged in the audit_logs table:

**Authentication:**
- login_success
- login_failed
- password_changed

**Users:**
- user_created
- user_updated
- user_deleted

**Groups:**
- group_created
- group_deleted

**Remotes:**
- remote_created
- remote_updated
- remote_deleted

**SSH Host Keys:**
- ssh_host_key_rescanned
- ssh_host_key_cleared

**Transfers:**
- transfer_created
- transfer_deleted
- transfer_delete_denied
- schedule_updated

**Notifications:**
- notifications_configured

**Access Control:**
- permission_denied
- permission_lookup_failed
- operation_denied

## Log Output Changes

Console log messages now use professional prefixes instead of emojis:

- [OK] - Successful operations
- [SUCCESS] - Completed actions
- [ERROR] - Error conditions
- [WARNING] - Warning messages
- [INFO] - Informational messages

## Deployment

```bash
tar -xzf cloudklone-v7-final-professional.tar.gz
cd cloudklone
sudo docker-compose up -d
```

Access at: https://localhost
Default credentials: admin / admin (must be changed on first login)

## Database Schema

No schema changes required. The audit_logs table already captures all necessary fields:

```sql
CREATE TABLE audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  username VARCHAR(255) NOT NULL,
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(50) NOT NULL,
  resource_id INTEGER,
  resource_name VARCHAR(255),
  details JSONB,
  ip_address VARCHAR(45),
  user_agent TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Viewing Audit Logs

### Via Admin Panel
1. Navigate to Admin tab
2. Scroll to Audit Logs section
3. Filter by user, action, or resource type

### Via Database
```bash
sudo docker exec -it cloudklone-database psql -U cloudklone_user cloudklone
```

```sql
-- View recent actions
SELECT timestamp, username, action, resource_type, resource_name 
FROM audit_logs 
ORDER BY timestamp DESC 
LIMIT 20;

-- View specific user's actions
SELECT timestamp, action, resource_type, resource_name, details
FROM audit_logs 
WHERE username = 'admin'
ORDER BY timestamp DESC;

-- View failed login attempts
SELECT timestamp, username, ip_address, details
FROM audit_logs 
WHERE action = 'login_failed'
ORDER BY timestamp DESC;
```

## Complete Feature List

**Transfer Operations:**
- Copy and sync between cloud providers
- Real-time progress monitoring
- Automatic retry on failure (3 attempts)
- Scheduled transfers (one-time and recurring)
- Transfer history and audit logs

**Cloud Provider Support:**
- Amazon S3, Cloudflare R2, Backblaze B2
- Google Cloud Storage, Azure Blob Storage
- Wasabi, Dropbox, Google Drive
- SFTP with host key verification
- 40+ providers via rclone

**Security:**
- HTTPS by default with self-signed certificate
- SSH host key management for SFTP
- Forced password change on first login
- AES-256 credential encryption
- Bcrypt password hashing
- JWT authentication
- Role-based access control
- Comprehensive audit logging

**User Management:**
- Multi-user support
- Group-based permissions
- Four roles: Admin, Power User, Operator, Viewer
- Admin panel for user/group management

**Notifications:**
- Email alerts via SMTP
- Webhook integrations (Slack, Teams, Discord)
- Success/failure notifications
- Daily summary reports

**Administration:**
- SSH host key management panel
- System tools (cancel stuck transfers)
- Audit log viewer
- User and group management

## Support

For deployment issues, see the Troubleshooting section in DEPLOYMENT-GUIDE.md

For questions about features, see FEATURES.md

## Version History

v7 includes all features from v6 plus:
- SSH host key management
- HTTPS by default
- Forced password changes
- Professional documentation
- Comprehensive audit logging
