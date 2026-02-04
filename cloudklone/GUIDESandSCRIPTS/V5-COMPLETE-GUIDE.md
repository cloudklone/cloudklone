# CloudKlone v5 - Complete RBAC with Frontend UI

## 🎨 What's New in Frontend

**New "Logs" Tab:**
- ✅ Audit log viewer for all users
- ✅ Filter by action, resource type
- ✅ Pagination support
- ✅ Real-time activity tracking

**Permission-Based UI:**
- ✅ Hides "Remotes" tab for operators
- ✅ Hides "Settings" tab for operators
- ✅ Hides "Sync" option for operators
- ✅ Hides delete buttons based on permissions
- ✅ Shows clear permission denied messages

**Group Permissions Editor:**
- ✅ Select role when creating groups
- ✅ Read-Only, Operator, Power User roles
- ✅ Shows role badges in groups list
- ✅ Descriptive permission explanations

---

## 🚀 Deployment

### Step 1: Backup

```bash
cd ~/cloudklone
sudo docker-compose exec postgres pg_dump -U rclone_admin rclone_gui > ~/cloudklone-backup-$(date +%Y%m%d-%H%M).sql
```

### Step 2: Deploy

```bash
sudo docker-compose down
cd ~ && tar -xzf cloudklone-v5-complete.tar.gz
cd cloudklone
```

### Step 3: Database Migration

```bash
# Start database
sudo docker-compose up -d postgres
sleep 10

# Run migration
sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui << 'EOF'
-- Add permissions column
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

\echo '✅ Migration complete!'
EOF
```

### Step 4: Start CloudKlone

```bash
sudo docker-compose up -d
sudo docker-compose logs -f app
```

---

## ✨ New UI Features

### 1. Logs Tab (All Users)

**Location:** Navigation → Logs

**Features:**
- View all system activity
- Filter by:
  - Action (logins, transfers created, permission denied)
  - Resource type (transfer, remote, auth, settings)
- Pagination (50 logs per page)
- Shows:
  - Username
  - Action
  - Resource name
  - Timestamp
  - IP address
  - Details (JSON)

**Example Logs:**
```
✅ Login Success • john • auth • 2/2/2026 10:30 AM
📦 Transfer Created • john • transfer • S3 Backup → R2 Archive
❌ Permission Denied • jane • transfer • Sync operation not permitted
```

### 2. Permission-Based UI Hiding

**For Operators:**
- ❌ **Remotes tab hidden** - Can view but not manage
- ❌ **Settings tab hidden** - Cannot configure SMTP
- ❌ **"Sync" option hidden** - Only "Copy" visible
- ❌ **Delete buttons hidden** - Cannot delete transfers
- ❌ **"Add Remote" section hidden** - Cannot create remotes

**For Power Users:**
- ✅ **Remotes tab visible** - Can create/edit remotes
- ❌ **Settings tab hidden** - Cannot configure SMTP
- ✅ **"Sync" option visible** - Can create sync transfers
- ✅ **Delete buttons visible** - Can delete own transfers
- ✅ **"Add Remote" visible** - Can create remotes

**For Admins:**
- ✅ **Everything visible** - Full access

### 3. Permission Denied Messages

**When operator tries to create sync:**
```
❌ Permission Denied

You do not have permission to create sync transfers. 
Your role only allows copy operations.

Please select "copy" as the operation type or contact 
an administrator to upgrade your permissions.
```

**When user tries unauthorized action:**
```
❌ Permission Denied

You do not have permission to perform this action.
```

### 4. Group Permissions Editor

**When creating a group:**

1. Fill in group name
2. Fill in description (optional)
3. **Select role:**
   - 👁️ **Read-Only** - View only
   - ⚙️ **Operator** - Create copy transfers only (default)
   - ⚡ **Power User** - Create sync, manage remotes

4. See description:
   ```
   Operator: Can view everything and create copy transfers. 
   Cannot create sync transfers or delete transfers.
   ```

5. Click "Create"

**Group display shows role badge:**
```
Engineering
Engineering team members
[⚡ Power User]
```

---

## 🎯 User Experience By Role

### As Read-Only User:

**Can See:**
- Transfers tab (view only)
- History tab (view only)
- Scheduled tab (view only)
- Logs tab (view all activity)

**Cannot See:**
- Remotes tab (hidden)
- Settings tab (hidden)
- Admin tab (hidden)

**Cannot Do:**
- Create any transfers
- Delete anything
- Modify anything

---

### As Operator (Default):

**Can See:**
- Transfers tab
- History tab
- Scheduled tab
- Logs tab

**Cannot See:**
- Remotes tab (hidden)
- Settings tab (hidden)
- "Sync" operation (hidden)
- Delete buttons (hidden)

**Can Do:**
- ✅ Create copy transfers
- ✅ Schedule copy transfers
- ✅ View all remotes
- ✅ View logs

**Cannot Do:**
- ❌ Create sync transfers
- ❌ Delete transfers
- ❌ Create/edit remotes
- ❌ Configure SMTP

---

### As Power User:

**Can See:**
- Transfers tab
- History tab
- Scheduled tab
- Logs tab
- **Remotes tab** (visible)

**Cannot See:**
- Settings tab (hidden)
- Delete buttons on others' transfers

**Can Do:**
- ✅ Create copy transfers
- ✅ Create sync transfers
- ✅ Delete own transfers
- ✅ Create/edit remotes
- ✅ Schedule any transfers

**Cannot Do:**
- ❌ Delete others' transfers
- ❌ Delete remotes
- ❌ Configure SMTP
- ❌ Manage users

---

### As Admin:

**Can See:**
- Everything

**Can Do:**
- Everything
- Manage users
- Manage groups
- Configure SMTP
- Delete anything
- System maintenance

---

## 🧪 Testing New Features

### Test 1: Permission-Based UI Hiding

```bash
# 1. Login as operator
# 2. Check navigation:
#    - Should NOT see "Remotes" tab
#    - Should NOT see "Settings" tab
#    - SHOULD see "Logs" tab

# 3. Go to Transfers tab
#    - Operation dropdown should only show "Copy"
#    - Should NOT show "Sync" option

# 4. View completed/failed transfer
#    - Should NOT see "Delete" button
```

### Test 2: Logs Tab

```bash
# 1. Login as any user
# 2. Click "Logs" tab
# 3. Should see activity log
# 4. Filter by "Logins"
# 5. Should see login entries
# 6. Create a transfer
# 7. Refresh logs
# 8. Should see "Transfer Created" entry
```

### Test 3: Permission Denied Messages

```bash
# 1. Login as operator
# 2. Edit URL manually to go to remotes tab
# 3. Try to create remote via API
# 4. Should get clear permission denied message
```

### Test 4: Group Creation with Roles

```bash
# 1. Login as admin
# 2. Go to Admin tab
# 3. Click "Create Group"
# 4. Enter name: "Test Power Users"
# 5. Select role: "Power User"
# 6. See description update
# 7. Click "Create"
# 8. Should see group with "⚡ Power User" badge
```

---

## 📊 Before vs After

### Before v5:
```
❌ All users could create sync transfers
❌ All users could delete any transfer
❌ All users could manage remotes
❌ All users could configure SMTP
❌ No audit logging
❌ No permission enforcement
```

### After v5:
```
✅ Operators can only create copy
✅ Only power users/admins can delete
✅ Only power users/admins can manage remotes
✅ Only admins can configure SMTP
✅ Full audit logging visible to all
✅ Comprehensive permission system
✅ UI adapts to user role
✅ Clear permission denied messages
```

---

## 🔒 Security Improvements

1. **Backend Enforcement** - All permissions checked server-side
2. **Frontend Hiding** - UI elements hidden to prevent confusion
3. **Clear Messaging** - Users understand why they can't do something
4. **Audit Trail** - All actions logged permanently
5. **Transparency** - Logs visible to all users
6. **Role-Based** - Easy to manage with group roles

---

## 🐛 Troubleshooting

### "Logs tab is empty"

**Check logs exist:**
```bash
sudo docker-compose exec postgres psql -U rclone_admin rclone_gui \
  -c "SELECT COUNT(*) FROM audit_logs;"
```

**If 0, login to generate logs:**
- Logout
- Login again
- Check logs tab

### "Sync option still visible"

**Clear browser cache:**
```
Ctrl+Shift+Delete → Clear cache
Or hard refresh: Ctrl+F5
```

### "Remotes tab still visible for operator"

**Check permissions:**
```bash
# In browser console:
fetch('/api/auth/permissions', {
  headers: {'Authorization': 'Bearer ' + localStorage.getItem('token')}
}).then(r => r.json()).then(console.log)
```

Should show `can_manage_remotes: false`

### "Group doesn't show role badge"

**Refresh groups:**
```bash
# Re-create group with role
# OR
# Update existing group in database:
sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui << 'EOF'
UPDATE groups 
SET permissions = '{
  "role": "operator",
  "can_create_copy": true,
  "can_create_sync": false,
  "can_delete_own_transfers": false,
  "can_manage_remotes": false,
  "can_manage_settings": false
}'
WHERE name = 'Your Group Name';
EOF
```

---

## ✅ Complete Feature Checklist

- [x] Backend RBAC with 4 roles
- [x] Audit logging system
- [x] Logs tab in UI
- [x] Permission-based UI hiding
- [x] Sync option hidden for operators
- [x] Delete buttons hidden by role
- [x] Remotes/Settings tabs hidden by role
- [x] Permission denied messages
- [x] Group permissions editor
- [x] Role selection when creating groups
- [x] Role badges in groups list
- [x] WebSocket integration for logs
- [x] Database migration scripts
- [x] Comprehensive documentation

---

## 🎉 Success!

You now have a complete RBAC system with:
- ✅ 4 distinct roles (Read-Only, Operator, Power User, Admin)
- ✅ Full audit logging visible to all
- ✅ Permission-based UI that adapts to user role
- ✅ Clear permission denied messages
- ✅ Easy group management with role selection
- ✅ Backend + Frontend enforcement
- ✅ Production-ready security

**CloudKlone v5 is complete!** 🚀

All requirements met:
- ✅ Users can read all
- ✅ Users can add copy jobs only
- ✅ Users cannot edit jobs
- ✅ Users cannot delete jobs
- ✅ Users cannot change configuration
- ✅ Sync operations blocked for operators
- ✅ Audit logs visible to all users
