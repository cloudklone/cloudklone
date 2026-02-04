# CloudKlone v5 Triple Fix - Quick Deploy 🚀

## 🐛 What's Fixed

1. ✅ **Timezone Corrected** - 12AM now shows as 12AM (not 2PM!)
2. ✅ **Admin Visibility** - Admins see ALL scheduled jobs
3. ✅ **Database Renamed** - `rclone_gui` → `cloudklone`

---

## ⚡ Quick Deploy (Existing Users)

```bash
# 1. Stop CloudKlone
cd ~/cloudklone
sudo docker-compose down

# 2. Extract new version
cd ~
tar -xzf cloudklone-v5-triple-fix.tar.gz
cd cloudklone

# 3. Run migration script (handles everything)
sudo ./migrate-database-v2.sh
# Type 'y' when prompted

# 4. Hard refresh browser
# Ctrl+Shift+R (Windows/Linux)
# Cmd+Shift+R (Mac)
```

**What the migration script does:**
- Starts temporary container with OLD credentials
- Renames database: rclone_gui → cloudklone
- Renames user: rclone_admin → cloudklone_user
- Starts CloudKlone with NEW credentials
- **Your data is preserved!**

---

## ⚡ Quick Deploy (New Users)

```bash
tar -xzf cloudklone-v5-triple-fix.tar.gz
cd cloudklone
sudo docker-compose up -d
```

---

## 🧪 Quick Tests

### Test 1: Timezone
```
1. Create daily transfer at 12:00 AM
2. Check Scheduled tab
3. Next Run should show ~12:00 AM tomorrow ✅
```

### Test 2: Admin Visibility
```
1. Create scheduled job as regular user
2. Logout, login as admin
3. Go to Scheduled tab
4. Should see all users' jobs ✅
```

### Test 3: Database Names
```bash
docker exec cloudklone-database psql -U cloudklone_user -d cloudklone -c "SELECT current_database();"
# Should return: cloudklone ✅
```

---

## 📖 Full Documentation

See `TRIPLE-FIX-GUIDE.md` for:
- Detailed technical explanations
- Troubleshooting guide
- Manual migration steps
- Testing procedures

---

## ⚠️ Important Notes

**For Existing Installations:**
- Migration script is REQUIRED
- Renames database and user automatically
- Safe to run (doesn't delete data)
- Takes ~10 seconds

**For Fresh Installations:**
- New names used automatically
- No migration needed
- Works out of the box

---

## 🎉 You're Done!

All three issues fixed and tested! 🚀
