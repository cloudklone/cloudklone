# Troubleshooting: User Edit "Server error"

## 🔍 Debug Steps

### Step 1: Deploy Fixed Version
```bash
cd ~/cloudklone
sudo docker-compose down

cd ~ && tar -xzf cloudklone-v4-final.tar.gz
cd cloudklone

sudo docker-compose up -d
```

### Step 2: Try Editing User Again
1. Go to Admin tab
2. Click Edit on a user
3. Open browser console (F12)
4. Click "Save Changes"

### Step 3: Check Browser Console
Look for these log messages:
```javascript
Sending update: {email: "...", groupId: 3, isAdmin: true}
```

If you see an error, send me the full error message.

### Step 4: Check Backend Logs
```bash
sudo docker-compose logs app | tail -100
```

Look for:
```
Update user request: { userId: '2', email: '...', groupId: 3, isAdmin: true }
Executing query: UPDATE users SET ...
User updated successfully: { id: 2, username: '...', ... }
```

Or look for errors like:
```
Update user error: Error: ...
Error stack: ...
```

---

## 🎯 Common Issues

### Issue 1: Missing group_id Column
**Error:** `column "group_id" of relation "users" does not exist`

**Fix:**
```bash
sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui << 'EOF'
ALTER TABLE users ADD COLUMN IF NOT EXISTS group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user';
EOF

sudo docker-compose restart app
```

### Issue 2: Not Admin
**Error:** `Admin access required`

**Fix:** Make sure you're logged in as admin, not a regular user.

### Issue 3: User Not Found
**Error:** `User not found`

**Fix:** The user ID might be wrong. Check the users list.

### Issue 4: Empty Update
**Error:** `No updates provided`

**Fix:** Make sure at least one field is different from current value.

---

## 📝 What The Logs Should Show

### Successful Update:
```
Update user request: { 
  userId: '2', 
  email: 'cooperb5555@gmail.com', 
  groupId: 1, 
  isAdmin: true,
  hasPassword: false 
}
Executing query: UPDATE users SET email = $1, group_id = $2, is_admin = $3 WHERE id = $4 RETURNING id, username, email, is_admin, group_id
With values: [ 'cooperb5555@gmail.com', 1, true, '2' ]
User updated successfully: { 
  id: 2, 
  username: 'matthew', 
  email: 'cooperb5555@gmail.com',
  is_admin: true,
  group_id: 1 
}
```

### Failed Update (Example):
```
Update user request: { userId: '2', ... }
Executing query: UPDATE users SET ...
Update user error: error: column "group_id" does not exist
Error stack: ...
```

---

## 🐛 Step-by-Step Debug

### 1. Clear Browser Cache
```
Ctrl+Shift+Delete → Clear cache and reload
Or
Hard refresh: Ctrl+F5
```

### 2. Check Network Tab
1. Open DevTools (F12)
2. Go to Network tab
3. Try editing user
4. Look for `PUT /api/users/2` request
5. Click on it
6. Check **Response** tab for error details

### 3. Verify Database Schema
```bash
sudo docker exec -it cloudklone-database psql -U rclone_admin rclone_gui

# Check users table
\d users

# Should show:
#   email
#   is_admin
#   group_id  ← Must exist!
#   role      ← Must exist!

\q
```

### 4. Test with curl
```bash
# Get your token from browser console:
# localStorage.getItem('token')

curl -X PUT http://localhost/api/users/2 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"email":"test@example.com","groupId":1,"isAdmin":true}'
```

---

## 🔧 Quick Fix Script

If nothing else works:

```bash
#!/bin/bash
# Fix user management issues

cd ~/cloudklone

# Stop services
sudo docker-compose down

# Backup database
sudo docker-compose up -d postgres
sleep 5
sudo docker-compose exec postgres pg_dump -U rclone_admin rclone_gui > ~/cloudklone-backup.sql

# Add missing columns
sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui << 'EOF'
-- Add user management columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user';
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMP;

-- Create groups table if missing
CREATE TABLE IF NOT EXISTS groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

\echo 'Schema updated successfully'
EOF

# Restart everything
sudo docker-compose up -d

echo "✅ Fix applied! Try editing users again."
```

---

## 📊 What To Send Me

If it still doesn't work, send me:

1. **Browser console output** (F12 → Console tab)
2. **Backend logs:**
   ```bash
   sudo docker-compose logs app | grep -A 10 "Update user"
   ```
3. **Database schema:**
   ```bash
   sudo docker exec -it cloudklone-database psql -U rclone_admin rclone_gui -c "\d users"
   ```
4. **Network response:**
   - F12 → Network tab
   - Find the PUT request
   - Screenshot of Response tab

---

## ✅ Expected Behavior

After fix, when you edit a user:

1. **Browser console shows:**
   ```
   Sending update: {email: "...", groupId: 1, isAdmin: true}
   ```

2. **Alert shows:**
   ```
   ✅ User updated successfully!
   ```

3. **User list refreshes** with updated info

4. **Backend logs show:**
   ```
   User updated successfully: { id: 2, username: '...', ... }
   ```

---

## 🚀 Test After Fix

```bash
# 1. Deploy fixed version
cd ~/cloudklone && sudo docker-compose down
cd ~ && tar -xzf cloudklone-v4-final.tar.gz
cd cloudklone && sudo docker-compose up -d

# 2. Test edit
# - Go to Admin tab
# - Edit a user
# - Change group/role
# - Save

# 3. Verify in logs
sudo docker-compose logs -f app
```

Should see "User updated successfully" in logs!
