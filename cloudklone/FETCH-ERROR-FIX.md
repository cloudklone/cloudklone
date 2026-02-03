# CloudKlone - Fix "Failed to Fetch" Error

## 🐛 Issue

When clicking "Add Remote", you get:
```
Connection error: Failed to fetch
```

---

## 🔍 Immediate Checks

### 1. Check if Containers are Running

```bash
sudo docker-compose ps
```

**Expected:**
```
NAME                  STATUS
cloudklone-app        Up
cloudklone-database   Up
```

**If cloudklone-app is "Exited":**
```bash
# View logs to see why it crashed
sudo docker-compose logs app --tail 50

# Restart it
sudo docker-compose restart app
```

---

### 2. Check Your User Role

**Open browser console (F12) and run:**
```javascript
fetch('/api/auth/permissions', {
  headers: {'Authorization': 'Bearer ' + localStorage.getItem('token')}
}).then(r => r.json()).then(console.log)
```

**Look for:**
```json
{
  "permissions": {
    "can_manage_remotes": false  ← This is your problem!
  }
}
```

**If `can_manage_remotes: false`:**
- You're logged in as an Operator
- Operators **cannot** add remotes
- The Remotes tab should be hidden

**Solution:**
1. Login as admin (username: admin, password: admin)
2. Go to Admin tab → Groups
3. Change your group to "Power User" role
4. OR check "Admin privileges" when creating your user

---

### 3. Check Backend Accessibility

**In browser console:**
```javascript
fetch('/api/providers').then(r => r.json()).then(console.log)
```

**Expected:** List of cloud providers

**If you see error:** Backend isn't responding

---

## 🚀 Deploy Better Error Messages

This version will tell you **exactly** what's wrong:

```bash
cd ~
tar -xzf cloudklone-v5-better-errors.tar.gz
cd cloudklone
sudo docker-compose down
sudo docker-compose up -d
```

---

## 🎯 New Error Messages

After deploying, you'll see clearer errors:

### Permission Denied (403)
```
❌ Failed to add remote

Permission Denied: You do not have permission to manage remotes.

Contact an administrator to upgrade your role to Power User or Admin.
```

### Backend Not Running
```
❌ Connection Error

Cannot connect to server. Possible causes:

• Backend container not running
• Network connection interrupted  
• Browser blocked the request

Check: sudo docker-compose ps
```

### Validation Failed (400)
```
❌ Failed to add remote

Remote connection failed. Please check your credentials and endpoint.

Details: [specific rclone error]
```

---

## 📋 Debug Mode

### Enable Console Logging

The new version logs everything to browser console:

```
[addRemote] Creating remote: {name: "cloudflare", type: "s3"}
[addRemote] Response status: 200
[addRemote] Response data: {success: true, ...}
```

### Check Logs:
1. Open browser (F12)
2. Go to Console tab
3. Try adding remote
4. Watch for `[addRemote]` messages

---

## ✅ Most Common Solutions

### Solution 1: Wrong User Role

**Problem:** Logged in as Operator  
**Fix:** Login as admin or upgrade to Power User

```bash
# Login as admin
Username: admin
Password: admin (change this!)

# Go to Admin → Create new user with "Power User" role
# Or check "Admin privileges" checkbox
```

### Solution 2: Backend Crashed

**Problem:** Container exited  
**Fix:**

```bash
# Check why it crashed
sudo docker-compose logs app --tail 100

# Common causes:
# - Syntax error in code
# - Database connection issue
# - Port already in use

# Restart
sudo docker-compose restart app
```

### Solution 3: Browser Cache

**Problem:** Old JavaScript cached  
**Fix:**

```
Hard refresh: Ctrl+Shift+R (or Cmd+Shift+R on Mac)
```

---

## 🧪 Test After Fix

1. **Login as admin**
2. **Go to Remotes tab**
3. **Try adding a remote**
4. **Open console (F12)**
5. **Watch for specific error message**

The new error messages will guide you to the exact problem!

---

## 📞 Still Not Working?

Share these with me:

```bash
# 1. Container status
sudo docker-compose ps

# 2. Recent logs
sudo docker-compose logs app --tail 50

# 3. Browser console output
# (Screenshot of F12 → Console after trying to add remote)
```

---

## 🎉 After It Works

Remember:
- **Operators** cannot add remotes (by design)
- **Power Users** can add remotes
- **Admins** can add and delete remotes

This is your RBAC system working correctly! 🔒
