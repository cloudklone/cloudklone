# CloudKlone v5 - RBAC & Audit Logging

## 🎯 What's New

**4-Role Permission System:**
- **Read-Only:** View only
- **Operator:** Create copy transfers only (your requirement)
- **Power User:** Create sync, manage remotes, delete own transfers
- **Admin:** Full control

**Audit Logging:**
- All actions logged
- Visible to all users (full transparency)
- Immutable records

---

## 📊 Permission Matrix

| Action | Read-Only | Operator | Power User | Admin |
|--------|-----------|----------|------------|-------|
| View transfers | ✅ | ✅ | ✅ | ✅ |
| View remotes | ✅ | ✅ | ✅ | ✅ |
| Create copy | ❌ | ✅ | ✅ | ✅ |
| Create sync | ❌ | ❌ | ✅ | ✅ |
| Edit transfer | ❌ | ❌ | ❌ | ✅ |
| Delete own transfer | ❌ | ❌ | ✅ | ✅ |
| Delete any transfer | ❌ | ❌ | ❌ | ✅ |
| Create/edit remote | ❌ | ❌ | ✅ | ✅ |
| Delete remote | ❌ | ❌ | ❌ | ✅ |
| Configure SMTP | ❌ | ❌ | ❌ | ✅ |
| Manage users | ❌ | ❌ | ❌ | ✅ |
| View logs | ✅ | ✅ | ✅ | ✅ |

---

## 🚀 Migration Steps

### Step 1: Backup

```bash
cd ~/cloudklone
sudo docker-compose exec postgres pg_dump -U rclone_admin rclone_gui > ~/cloudklone-backup-$(date +%Y%m%d-%H%M).sql
ls -lh ~/cloudklone-backup-*.sql
```

### Step 2: Deploy

```bash
sudo docker-compose down
cd ~ && tar -xzf cloudklone-v5-rbac.tar.gz
cd cloudklone
```

### Step 3: Migrate Database

```bash
# Start database
sudo docker-compose up -d postgres
sleep 10

# Run migration
sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui << 'EOF'
-- Add permissions to groups
ALTER TABLE groups ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '{
  "role": "operator",
  "can_create_copy": true,
  "can_create_sync": false,
  "can_edit_transfers": false,
  "can_delete_own_transfers": false,
  "can_delete_any_transfers": false,
  "can_manage_remotes": false,
  "can_manage_settings": false,
  "can_manage_users": false
}';

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
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

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- Verify
\d groups
\d audit_logs
\echo '✅ Migration complete!'
EOF
```

### Step 4: Start CloudKlone

```bash
sudo docker-compose up -d
sudo docker-compose logs -f app
```

---

## ✅ Verification

```bash
# 1. Check tables exist
sudo docker-compose exec postgres psql -U rclone_admin rclone_gui -c "\dt"

# 2. Test permissions endpoint
curl http://localhost/api/auth/permissions \
  -H "Authorization: Bearer YOUR_TOKEN"

# 3. View audit logs
curl http://localhost/api/audit-logs \
  -H "Authorization: Bearer YOUR_TOKEN" | jq
```

---

## 🎭 Assigning Roles to Groups

### Default (All New Groups)
**Role: Operator**
- Can view everything
- Can create copy transfers
- Cannot create sync (destructive operations blocked)
- Cannot delete transfers
- Cannot manage remotes/settings

### Make a Group "Power User"

```bash
sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui << 'EOF'
UPDATE groups 
SET permissions = '{
  "role": "power_user",
  "can_create_copy": true,
  "can_create_sync": true,
  "can_edit_transfers": false,
  "can_delete_own_transfers": true,
  "can_delete_any_transfers": false,
  "can_manage_remotes": true,
  "can_manage_settings": false,
  "can_manage_users": false
}'
WHERE name = 'Your Group Name';

SELECT name, permissions FROM groups;
EOF
```

### Make a Group "Read-Only"

```bash
sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui << 'EOF'
UPDATE groups 
SET permissions = '{
  "role": "read_only",
  "can_create_copy": false,
  "can_create_sync": false,
  "can_edit_transfers": false,
  "can_delete_own_transfers": false,
  "can_delete_any_transfers": false,
  "can_manage_remotes": false,
  "can_manage_settings": false,
  "can_manage_users": false
}'
WHERE name = 'Read-Only Group';
EOF
```

---

## 🔒 What Changed for Users

### Existing Admins (is_admin = true)
- ✅ No change - retain full access
- ✅ All permissions

### Regular Users in Groups
- ✅ Now have "Operator" role by default
- ✅ Can view all transfers/remotes
- ✅ Can create COPY transfers
- ❌ Cannot create SYNC transfers (permission denied)
- ❌ Cannot delete transfers (permission denied)
- ❌ Cannot manage remotes (permission denied)
- ❌ Cannot change SMTP settings (permission denied)

### Users Without Groups
- ✅ Get "Operator" permissions by default
- Same restrictions as above

---

## 🧪 Testing RBAC

### Test 1: Try Creating Sync (Should Fail for Operators)

```bash
curl -X POST http://localhost/api/transfers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer OPERATOR_TOKEN" \
  -d '{
    "sourceRemote": "test",
    "sourcePath": "/data",
    "destRemote": "backup",
    "destPath": "/backup",
    "operation": "sync"
  }'

# Expected: 403 Forbidden
# "Sync operations not permitted for your role"
```

### Test 2: Create Copy (Should Work for Operators)

```bash
curl -X POST http://localhost/api/transfers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer OPERATOR_TOKEN" \
  -d '{
    "sourceRemote": "test",
    "sourcePath": "/data",
    "destRemote": "backup",
    "destPath": "/backup",
    "operation": "copy"
  }'

# Expected: 201 Created
```

### Test 3: View Audit Logs

```bash
curl http://localhost/api/audit-logs?limit=10 \
  -H "Authorization: Bearer ANY_TOKEN" | jq

# Expected: Array of audit log entries
```

---

## 📝 Audit Log Actions

### Authentication
- `login_success` - User logged in
- `login_failed` - Failed login attempt
- `permission_denied` - Attempted unauthorized action

### Transfers
- `transfer_created` - New transfer created
- `transfer_deleted` - Transfer removed
- `operation_denied` - Sync blocked for operator

### Remotes
- `remote_created` - New remote added
- `remote_updated` - Remote modified
- `remote_deleted` - Remote removed

### Settings
- `smtp_configured` - Email settings changed

### Users (Admin only)
- `user_created`
- `user_updated`
- `user_deleted`

---

## 🐛 Troubleshooting

### "Insufficient permissions" Error

**Cause:** User doesn't have required permission  
**Check:** 
```bash
curl http://localhost/api/auth/permissions \
  -H "Authorization: Bearer TOKEN"
```

### "Sync operations not permitted"

**Cause:** User has Operator role  
**Solution:** Upgrade group to Power User or Admin

### Audit logs not showing

**Check table exists:**
```bash
sudo docker-compose exec postgres psql -U rclone_admin rclone_gui -c "\d audit_logs"
```

### Backend errors

**Check logs:**
```bash
sudo docker-compose logs app | grep -i error
```

---

## ↩️ Rollback

```bash
cd ~/cloudklone
sudo docker-compose down

# Restore backup
sudo docker-compose up -d postgres
sleep 10
cat ~/cloudklone-backup-YYYYMMDD-HHMM.sql | \
  sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui

# Use old version
cd ~/cloudklone-v4-backup
sudo docker-compose up -d
```

---

## 🎉 Success Indicators

After migration, you should see:

1. ✅ audit_logs table exists
2. ✅ groups have permissions column
3. ✅ `/api/auth/permissions` returns permissions object
4. ✅ `/api/audit-logs` returns audit entries
5. ✅ Operators can create copy transfers
6. ✅ Operators get "403 Forbidden" for sync transfers
7. ✅ Operators get "403 Forbidden" for creating remotes
8. ✅ Operators get "403 Forbidden" for SMTP settings
9. ✅ Login events appear in audit logs

---

## 📋 Default Behavior Summary

**After Migration:**

| User Type | Role | What They Can Do |
|-----------|------|------------------|
| Admin (is_admin=true) | Admin | Everything |
| In Group | Operator | View all, create copy only |
| No Group | Operator | View all, create copy only |

**Your Requirements Met:**
- ✅ Users can read all transfers/remotes
- ✅ Users can add new copy jobs
- ✅ Users cannot edit jobs
- ✅ Users cannot delete jobs  
- ✅ Users cannot change configuration
- ✅ Users can only make copy jobs (not sync)
- ✅ Full audit logging visible to all

---

## 🚦 Next Steps (Phase 3: Frontend)

**Coming Next:**
1. New "Logs" tab in UI
2. Hide "Delete" buttons for operators
3. Hide "Sync" option for operators
4. Hide "Create Remote" for operators
5. Hide "Settings" tab for operators
6. Show permission errors in UI
7. Group permissions editor for admins

**For Now:**
- Backend RBAC is fully functional
- Users will get API errors if they try unauthorized actions
- Frontend will catch up in Phase 3

---

## 🆘 Need Help?

Send these files:
```bash
sudo docker-compose logs app > logs.txt
sudo docker-compose exec postgres psql -U rclone_admin rclone_gui -c "\d groups" > schema.txt
sudo docker-compose exec postgres psql -U rclone_admin rclone_gui -c "\d audit_logs" >> schema.txt
curl http://localhost/api/auth/permissions -H "Authorization: Bearer TOKEN" > perms.txt
```

Congratulations! CloudKlone v5 with RBAC is ready! 🎉
