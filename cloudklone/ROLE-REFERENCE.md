# CloudKlone v5 - Role Reference Card

## 🎭 Four Roles

### 1. Read-Only
**View Only - No Actions**
```json
{
  "role": "read_only",
  "can_create_copy": false,
  "can_create_sync": false,
  "can_delete_own_transfers": false,
  "can_manage_remotes": false,
  "can_manage_settings": false
}
```
✅ View transfers, remotes, history, logs  
❌ Cannot create, edit, or delete anything

---

### 2. Operator (Default)
**Create Copy Transfers Only**
```json
{
  "role": "operator",
  "can_create_copy": true,
  "can_create_sync": false,
  "can_delete_own_transfers": false,
  "can_manage_remotes": false,
  "can_manage_settings": false
}
```
✅ View everything  
✅ Create copy transfers  
❌ Cannot create sync (destructive)  
❌ Cannot delete transfers  
❌ Cannot manage remotes/settings

---

### 3. Power User
**Advanced Operations**
```json
{
  "role": "power_user",
  "can_create_copy": true,
  "can_create_sync": true,
  "can_delete_own_transfers": true,
  "can_manage_remotes": true,
  "can_manage_settings": false
}
```
✅ Create copy AND sync transfers  
✅ Delete own transfers (not others')  
✅ Create/edit remotes  
❌ Cannot delete remotes (admin only)  
❌ Cannot manage SMTP settings  
❌ Cannot manage users

---

### 4. Admin
**Full Control**
```json
{
  "role": "admin",
  "can_create_copy": true,
  "can_create_sync": true,
  "can_edit_transfers": true,
  "can_delete_own_transfers": true,
  "can_delete_any_transfers": true,
  "can_manage_remotes": true,
  "can_manage_settings": true,
  "can_manage_users": true
}
```
✅ Everything

---

## 🔄 Quick Role Changes

**View Current Roles:**
```bash
sudo docker-compose exec postgres psql -U rclone_admin rclone_gui \
  -c "SELECT id, name, permissions->>'role' as role FROM groups;"
```

**Make Group Operator:**
```sql
UPDATE groups 
SET permissions = '{"role":"operator","can_create_copy":true,"can_create_sync":false,"can_delete_own_transfers":false,"can_manage_remotes":false,"can_manage_settings":false}'
WHERE name = 'Your Group';
```

**Make Group Power User:**
```sql
UPDATE groups 
SET permissions = '{"role":"power_user","can_create_copy":true,"can_create_sync":true,"can_delete_own_transfers":true,"can_manage_remotes":true,"can_manage_settings":false}'
WHERE name = 'Your Group';
```

**Make Group Read-Only:**
```sql
UPDATE groups 
SET permissions = '{"role":"read_only","can_create_copy":false,"can_create_sync":false,"can_delete_own_transfers":false,"can_manage_remotes":false,"can_manage_settings":false}'
WHERE name = 'Your Group';
```

---

## 📊 Permission Matrix

| Action | Read-Only | Operator | Power User | Admin |
|--------|:---------:|:--------:|:----------:|:-----:|
| View transfers | ✅ | ✅ | ✅ | ✅ |
| View remotes | ✅ | ✅ | ✅ | ✅ |
| View logs | ✅ | ✅ | ✅ | ✅ |
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

---

## 🎯 Role Selection Guide

**Choose Read-Only for:**
- Auditors
- Viewers
- Management oversight
- External stakeholders

**Choose Operator for:**
- Regular backup operators
- Staff who run routine transfers
- Users who shouldn't delete or modify

**Choose Power User for:**
- Technical staff
- Advanced users
- Those who need sync operations
- Users managing their own remotes

**Choose Admin for:**
- System administrators
- IT management
- Those configuring the system
