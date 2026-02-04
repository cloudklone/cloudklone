# CloudKlone Access Control - Current vs Proposed

## 📊 CURRENT STATE (As Implemented)

### 🔴 ADMIN ONLY:
- ✅ Create users (`POST /api/auth/register`)
- ✅ View all users (`GET /api/users`)
- ✅ Delete users (`DELETE /api/users/:id`)
- ✅ Edit users (`PUT /api/users/:id`)
- ✅ View groups (`GET /api/groups`)
- ✅ Create groups (`POST /api/groups`)
- ✅ Delete groups (`DELETE /api/groups/:id`)
- ✅ Assign users to groups (`PUT /api/users/:id/group`)
- ✅ Cancel all stuck transfers (system maintenance)

### 🟢 ALL AUTHENTICATED USERS:
- ✅ Create remotes (all types: S3, B2, SFTP, etc.)
- ✅ Edit remotes
- ✅ Delete remotes
- ✅ Test remotes
- ✅ Create transfers (copy AND sync)
- ✅ Delete transfers
- ✅ Cancel transfers
- ✅ View all transfers
- ✅ View transfer history
- ✅ View scheduled jobs
- ✅ Toggle scheduled jobs (enable/disable)
- ✅ Configure SMTP settings
- ✅ Configure email notifications
- ✅ Change own password

### ⚠️ SECURITY ISSUES:
1. **Regular users can create/edit/delete remotes** (should be admin only)
2. **Regular users can create sync jobs** (destructive!)
3. **Regular users can delete any transfer** (including others')
4. **Regular users can configure SMTP** (potential abuse)
5. **No audit logging** (no accountability)
6. **No group-based permissions** (groups are labels only)

---

## 🎯 PROPOSED RBAC SYSTEM

### Permission Levels (Group-Based)

#### 1. **Read-Only** (Viewer)
- ✅ View transfers (all)
- ✅ View transfer history
- ✅ View scheduled jobs
- ✅ View remotes (read-only)
- ❌ Create anything
- ❌ Edit anything
- ❌ Delete anything

#### 2. **Operator** (Regular User - Your Requirement)
- ✅ View all transfers/remotes/history
- ✅ Create copy transfers ONLY
- ✅ View scheduled jobs
- ❌ Create sync transfers (destructive)
- ❌ Edit transfers
- ❌ Delete transfers
- ❌ Create/edit/delete remotes
- ❌ Configure SMTP
- ❌ Manage users/groups

#### 3. **Power User**
- ✅ Everything Operator can do
- ✅ Create sync transfers
- ✅ Delete own transfers
- ✅ Create remotes (approved types)
- ❌ Delete others' transfers
- ❌ Configure SMTP
- ❌ Manage users/groups

#### 4. **Administrator**
- ✅ Everything
- ✅ Manage users/groups
- ✅ Configure SMTP
- ✅ Delete any transfer
- ✅ Create/edit/delete remotes
- ✅ System maintenance tools

---

## 🗃️ Database Schema Changes

### Add Permissions Column to Groups

```sql
ALTER TABLE groups ADD COLUMN permissions JSONB DEFAULT '{"role": "operator"}';

-- Example permissions:
{
  "role": "operator",           -- read_only, operator, power_user, admin
  "can_create_copy": true,
  "can_create_sync": false,
  "can_edit_transfers": false,
  "can_delete_transfers": false,
  "can_manage_remotes": false,
  "can_manage_settings": false
}
```

### Create Audit Logs Table

```sql
CREATE TABLE audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  username VARCHAR(255),
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(50) NOT NULL,
  resource_id INTEGER,
  resource_name VARCHAR(255),
  details JSONB,
  ip_address VARCHAR(45),
  user_agent TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
```

---

## 🔐 Permission Checks (Middleware)

### New Middleware Functions

```javascript
// Check if user has specific permission
function requirePermission(permission) {
  return async (req, res, next) => {
    const user = req.user;
    
    // Admins bypass all checks
    if (user.isAdmin) return next();
    
    // Get user's group permissions
    const group = await getGroupPermissions(user.group_id);
    
    if (!group || !group.permissions[permission]) {
      await logAudit({
        user_id: user.id,
        action: 'permission_denied',
        resource_type: permission,
        details: { reason: 'insufficient_permissions' }
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// Check operation type (copy vs sync)
function validateTransferType(req, res, next) {
  const { operation } = req.body;
  const user = req.user;
  
  // Admins can do anything
  if (user.isAdmin) return next();
  
  // Get user's group permissions
  const group = await getGroupPermissions(user.group_id);
  
  // Check if sync is allowed
  if (operation === 'sync' && !group.permissions.can_create_sync) {
    return res.status(403).json({ 
      error: 'Sync operations not permitted. Only copy operations allowed.' 
    });
  }
  
  next();
}
```

---

## 📝 Audit Logging

### Actions to Log:

**User Management:**
- `user_created`
- `user_updated`
- `user_deleted`
- `user_password_changed`
- `user_group_changed`
- `user_role_changed`

**Remote Management:**
- `remote_created`
- `remote_updated`
- `remote_deleted`
- `remote_tested`

**Transfer Management:**
- `transfer_created`
- `transfer_deleted`
- `transfer_cancelled`
- `transfer_scheduled`
- `transfer_enabled`
- `transfer_disabled`

**Settings:**
- `smtp_configured`
- `notifications_configured`

**Authentication:**
- `login_success`
- `login_failed`
- `logout`

**System:**
- `permission_denied`

### Log Format:

```json
{
  "id": 1234,
  "user_id": 5,
  "username": "john",
  "action": "transfer_created",
  "resource_type": "transfer",
  "resource_id": 89,
  "resource_name": "S3 to B2 backup",
  "details": {
    "operation": "copy",
    "source": "s3-prod:data",
    "destination": "b2-backup:daily"
  },
  "ip_address": "10.0.0.15",
  "user_agent": "Mozilla/5.0...",
  "timestamp": "2026-02-02T21:45:00Z"
}
```

---

## 🎨 UI Changes

### 1. New "Logs" Tab (All Users)
- Shows audit trail of all actions
- Filters: User, Action, Resource Type, Date Range
- Real-time updates
- Cannot be edited/deleted (immutable)
- Admins see all logs
- Users see only their own logs (optional: see all for transparency)

### 2. Group Management Enhancement
- Add "Permissions" section when creating/editing groups
- Checkboxes for each permission
- Role presets: Read-Only, Operator, Power User, Admin

### 3. UI Permission Hiding
- Hide "Delete" buttons from users without permission
- Hide "Sync" option from users without permission
- Hide "Remotes" tab from users without permission
- Hide "Settings" tab from users without permission
- Hide "Admin" tab from non-admins (already done)

### 4. Operation Restriction
- Transfer form: Show only "Copy" for operators
- Show warning: "Sync operations require admin approval"

---

## 🚀 Implementation Steps

### Phase 1: Database Schema
1. Add `permissions` column to `groups` table
2. Create `audit_logs` table
3. Add indexes for performance

### Phase 2: Backend Middleware
1. Create permission check middleware
2. Add audit logging helper functions
3. Apply middleware to routes

### Phase 3: Route Protection
1. Protect remote routes (admin only)
2. Protect settings routes (admin only)
3. Add operation type validation (copy vs sync)
4. Add ownership checks (delete own transfers only)

### Phase 4: Audit Logging
1. Log all user actions
2. Create audit log API endpoint
3. Add real-time WebSocket updates

### Phase 5: Frontend
1. Add Logs tab
2. Update group management UI
3. Hide UI elements based on permissions
4. Restrict form options (copy only)
5. Add permission-denied error messages

### Phase 6: Testing
1. Test each permission level
2. Verify audit logging
3. Test permission escalation prevention

---

## 📋 Your Specific Requirements

✅ **Users can read all** → Implemented
✅ **Users can add new jobs** → Only COPY jobs
✅ **Users cannot edit jobs** → Blocked at API level
✅ **Users cannot delete jobs** → Blocked at API level
✅ **Users cannot change configuration** → Blocked at API level
✅ **Users can only make copy jobs** → Sync operations blocked
✅ **Logs visible to all users** → New Logs tab with transparency

---

## 🎯 Default Group Permissions

### Operators (Default for new users):
```json
{
  "role": "operator",
  "can_create_copy": true,
  "can_create_sync": false,
  "can_edit_transfers": false,
  "can_delete_transfers": false,
  "can_manage_remotes": false,
  "can_manage_settings": false
}
```

### Network Operations (Your existing group):
```json
{
  "role": "operator",
  "can_create_copy": true,
  "can_create_sync": false,
  "can_edit_transfers": false,
  "can_delete_transfers": false,
  "can_manage_remotes": false,
  "can_manage_settings": false
}
```

### Administrators:
```json
{
  "role": "admin",
  "can_create_copy": true,
  "can_create_sync": true,
  "can_edit_transfers": true,
  "can_delete_transfers": true,
  "can_manage_remotes": true,
  "can_manage_settings": true
}
```

---

## ⚠️ Migration Path

### For Existing Installations:

1. **Add permissions to existing groups:**
   ```sql
   UPDATE groups SET permissions = '{"role": "operator", "can_create_copy": true, "can_create_sync": false}';
   ```

2. **Create audit_logs table:**
   ```sql
   -- See schema above
   ```

3. **Restart application**

4. **Existing users in groups:** Inherit group permissions
5. **Existing users without groups:** Default to operator permissions
6. **Existing admins:** Retain full admin access

---

## 🔒 Security Benefits

1. **Principle of Least Privilege** → Users only get what they need
2. **Accountability** → All actions logged and auditable
3. **Transparency** → All users can see activity log
4. **Data Protection** → Sync operations restricted (prevents data loss)
5. **Configuration Protection** → Only admins can change SMTP/settings
6. **Audit Trail** → Compliance and troubleshooting

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
| Create remote | ❌ | ❌ | ✅ | ✅ |
| Edit remote | ❌ | ❌ | ✅ | ✅ |
| Delete remote | ❌ | ❌ | ❌ | ✅ |
| Configure SMTP | ❌ | ❌ | ❌ | ✅ |
| Manage users | ❌ | ❌ | ❌ | ✅ |
| View logs | ✅ | ✅ | ✅ | ✅ |

---

**Ready to implement?** This is a comprehensive RBAC + audit logging system that gives you:
- ✅ Group-based permissions
- ✅ Read-only users with copy-only capability
- ✅ Full audit trail visible to all
- ✅ Protection against destructive operations
- ✅ Configuration security

Should I proceed with implementation?
