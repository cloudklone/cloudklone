# CloudKlone Admin Panel Guide

## 📍 Where to Find It

The **Admin** tab appears in the sidebar **only for admin users**.

**Default admin account:**
- Username: `admin`
- Password: `admin`
- **Change this immediately after first login!**

**If you don't see the Admin tab:**
- You're not logged in as an admin
- Only users with `is_admin = true` can see it

---

## 👥 User Management

### Create a New User
1. Go to **Admin** tab
2. Click **"Create User"** button
3. Fill in:
   - Username (required)
   - Email (required)
   - Password (required)
   - Group (optional)
   - Admin privileges checkbox
4. Click **"Create"**

**Example:**
```
Username: john
Email: john@example.com
Password: SecurePass123!
Group: Engineering
Admin: ☐ (unchecked)
```

### Delete a User
1. Go to **Admin** tab → Users section
2. Find the user in the list
3. Click **"Delete"** button
4. Confirm deletion

**Note:** You cannot delete yourself!

### Change User's Group
1. Go to **Admin** tab → Users section
2. Click **"Change Group"** on a user
3. Select group from list (or blank for no group)
4. User is immediately reassigned

---

## 👥 Group Management

### Create a Group
1. Go to **Admin** tab → Groups section
2. Click **"Create Group"** button
3. Fill in:
   - Group Name (required) - e.g., "Engineering"
   - Description (optional) - e.g., "Engineering team members"
4. Click **"Create"**

### Delete a Group
1. Go to **Admin** tab → Groups section
2. Click **"Delete"** on the group
3. Confirm deletion

**Note:** Users in the deleted group will be unassigned (group_id set to NULL)

---

## 🔧 System Tools

### Cancel All Stuck Transfers
**What it does:**
- Finds transfers stuck in "running" state for 10+ minutes
- With 0% progress or no progress data
- Kills their rclone processes
- Marks them as "failed"

**How to use:**
1. Go to **Admin** tab → System Tools section
2. Click **"Cancel All Stuck Transfers"**
3. Confirm action
4. See how many were cancelled

**Use this for:**
- Cleaning up old hung transfers
- Fixing transfers from before v4
- Resolving stuck "running" states

---

## 🎯 Common Admin Tasks

### Task 1: Add a New Team Member
```
1. Admin → Create User
2. Fill in details
3. Assign to appropriate group
4. Send them login credentials (out of band)
5. Tell them to change password on first login
```

### Task 2: Organize Users by Department
```
1. Admin → Create Group ("Sales")
2. Admin → Create Group ("Engineering")
3. For each user → Change Group
4. Assign to appropriate department
```

### Task 3: Clean Up Stuck Transfers
```
1. Admin → System Tools
2. Cancel All Stuck Transfers
3. Check Transfers tab - should be clear
4. Check History tab - see cancelled transfers
```

### Task 4: Promote User to Admin
**Currently requires database access:**
```sql
UPDATE users SET is_admin = true WHERE username = 'john';
```

**Coming soon:** Promote/demote button in UI

---

## 📊 What You'll See

### User List View
```
┌─────────────────────────────────────────────┐
│ john [ADMIN]                                │
│ john@example.com • Created 2/2/2026     [Delete]│
├─────────────────────────────────────────────┤
│ alice                                       │
│ alice@example.com • Created 2/2/2026    [Delete]│
└─────────────────────────────────────────────┘
```

### Group List View
```
┌─────────────────────────────────────────────┐
│ Engineering                                 │
│ Engineering team members             [Delete]│
├─────────────────────────────────────────────┤
│ Sales                                       │
│ Sales department                     [Delete]│
└─────────────────────────────────────────────┘
```

---

## 🔒 Security Notes

### Admin Privileges
Admins can:
- ✅ View all users
- ✅ Create/delete users
- ✅ Create/delete groups
- ✅ Assign users to groups
- ✅ Cancel all stuck transfers
- ✅ View all transfers (coming soon)
- ✅ View system logs (coming soon)

Admins cannot (yet):
- ❌ View other users' remotes
- ❌ Access other users' transfers
- ❌ Force password reset
- ❌ View audit logs

### Regular Users
Can:
- ✅ Manage their own remotes
- ✅ Create/cancel their own transfers
- ✅ View their own history
- ✅ Change their own password
- ❌ Cannot see Admin tab
- ❌ Cannot see other users

---

## 🐛 Troubleshooting

### "Admin tab not showing"
**Check:**
1. Are you logged in as admin?
2. Check browser console for JWT decode errors
3. Try logging out and back in

**Verify admin status:**
```sql
-- Connect to database
sudo docker-compose exec postgres psql -U postgres cloudklone

-- Check your user
SELECT username, is_admin FROM users WHERE username = 'admin';
```

Should show `is_admin = true`

### "Failed to load users/groups"
**Check:**
1. Are you actually an admin?
2. Check backend logs: `sudo docker-compose logs app`
3. Look for 403 Forbidden errors

### "Cannot delete user"
**Possible reasons:**
1. Trying to delete yourself (not allowed)
2. User has active transfers (coming soon: cascade delete)
3. Database constraint violation

---

## 🎨 UI Features

### Admin Tab Styling
- Orange accent for [ADMIN] badges
- Clean card-based layout
- Collapsible create forms
- Responsive buttons
- Inline actions (delete, change group)

### Admin Navigation
- Only visible to admin users
- Loads users/groups on tab switch
- Auto-updates after changes

---

## 📝 Permissions Matrix

| Action | Admin | User |
|--------|-------|------|
| View own transfers | ✅ | ✅ |
| View all transfers | ❌* | ❌ |
| Create user | ✅ | ❌ |
| Delete user | ✅ | ❌ |
| Create group | ✅ | ❌ |
| Delete group | ✅ | ❌ |
| Change user group | ✅ | ❌ |
| Cancel stuck transfers | ✅ | ❌ |
| Change own password | ✅ | ✅ |
| Access admin tab | ✅ | ❌ |

*Coming in future update

---

## 🚀 Quick Start

### First Time Setup
1. Log in as `admin` / `admin`
2. Go to **Settings** → Change admin password
3. Go to **Admin** → Create groups for your org
4. Go to **Admin** → Create users
5. Assign users to groups
6. Send credentials to users

### Daily Use
- **User Management**: Add/remove team members
- **Group Organization**: Keep departments organized
- **Maintenance**: Cancel stuck transfers periodically

---

## 🎯 Real-World Example

**Scenario:** Setting up CloudKlone for a company with 3 departments

```
Step 1: Create Groups
- Engineering
- Sales
- Marketing

Step 2: Create Users
- john@company.com → Engineering
- alice@company.com → Sales
- bob@company.com → Marketing
- admin@company.com → (no group, is admin)

Step 3: Configure Access
- Each user logs in, changes password
- Each user adds their cloud remotes
- Each user creates transfers

Step 4: Maintenance
- Admin checks for stuck transfers weekly
- Admin adds new users as needed
- Admin manages groups as org changes
```

---

## 📈 Coming Soon

**Planned admin features:**
- [ ] View all users' transfers (admin dashboard)
- [ ] Force password reset for any user
- [ ] Promote/demote admin status in UI
- [ ] Audit log (who did what, when)
- [ ] Group-level remote sharing
- [ ] Transfer quotas per user/group
- [ ] Usage statistics and reports
- [ ] Bulk user import (CSV)
- [ ] LDAP/SSO integration

---

## ✅ You Now Have

- ✅ Complete user management
- ✅ Complete group management
- ✅ System maintenance tools
- ✅ Clean admin interface
- ✅ Role-based access control

**The admin panel is fully functional!** 🎉
