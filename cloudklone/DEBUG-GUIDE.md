# CloudKlone v5 - Debug Progress Tracking

## 🔍 What This Does

This version adds **comprehensive logging** to see EXACTLY what rclone is outputting so we can fix the progress tracking.

It will log:
- Every single line rclone outputs (no truncation)
- Which regex patterns match (or don't match)
- Raw output from both stderr and stdout
- Line-by-line parsing attempts

---

## 🚀 Deploy Debug Version

```bash
cd ~
tar -xzf cloudklone-v5-debug.tar.gz
cd cloudklone
sudo docker-compose down
sudo docker-compose up -d
```

---

## 🧪 Test and Capture Logs

### 1. Start watching logs in one terminal

```bash
sudo docker-compose logs -f app > /tmp/transfer-debug.log
```

### 2. Start a transfer

- Open CloudKlone in browser
- Create a transfer with a **medium-large file** (100MB - 1GB is ideal)
- Let it run for at least 30 seconds

### 3. Stop logging

Press `Ctrl+C` in the log terminal after 30-60 seconds

### 4. Review the logs

```bash
cat /tmp/transfer-debug.log | grep -A 2 -B 2 "STDERR RAW"
```

---

## 📋 What to Look For

The logs will show lines like:

**If rclone is outputting to stderr:**
```
[abc-123] STDERR RAW: Transferred:   50.123 MiB / 500 MiB, 10%, 25.5 MiB/s, ETA 18s
[abc-123] PARSING LINE: Transferred:   50.123 MiB / 500 MiB, 10%, 25.5 MiB/s, ETA 18s
[abc-123] ✓✓✓ MATCHED PATTERN 1: 10% @ 25.5 MiB/s, ETA 18s
```

**If patterns don't match:**
```
[abc-123] STDERR RAW: <some output>
[abc-123] PARSING LINE: <some output>
[abc-123] ⚠️ Has 'Transferred:' but no patterns matched: <the line>
```

**If nothing from rclone:**
```
[abc-123] Still scanning...
(No STDERR RAW or STDOUT RAW lines)
```

---

## 🎯 Three Possible Outcomes

### Outcome 1: Logs show "MATCHED PATTERN X"

✅ **Good!** Progress tracking is working.
- The UI should now update
- Hard refresh your browser (Ctrl+Shift+R)

### Outcome 2: Logs show "Has 'Transferred:' but no patterns matched"

📋 **We see rclone output but regex doesn't match**
- Copy the exact line that says "but no patterns matched"
- Share it with me
- I'll create a regex that matches your specific format

### Outcome 3: No "STDERR RAW" or "STDOUT RAW" at all

⚠️ **Rclone isn't outputting anything**
- Possible reasons:
  - Transfer too fast (file too small)
  - Output buffering issue
  - Rclone version incompatibility
  
**Try with a larger file (500MB+)**

---

## 📤 Share Results With Me

Send me the output of:

```bash
# Get just the relevant lines
cat /tmp/transfer-debug.log | grep -E "STDERR RAW|PARSING LINE|MATCHED|Has 'Transferred'" | head -50
```

This will show me:
1. What rclone is actually outputting
2. Whether our patterns are matching
3. The exact format to fix

---

## 🔄 After Debugging

Once we fix the pattern, I'll give you a final version with:
- Correct regex for your rclone version
- Reduced logging (not every line)
- Working progress tracking

---

## 💡 Quick Test

**Fastest way to test:**

```bash
# Terminal 1: Watch logs
sudo docker-compose logs -f app | grep -E "STDERR|MATCHED|Transferred"

# Terminal 2: Start a transfer in browser

# Watch Terminal 1 for output
```

You should see lines appearing every second if it's working!

---

## ❓ Common Issues

**"Transfer completes too fast"**
- Use a file that's 500MB+
- Or transfer many files (1000+)

**"No output at all"**
- Check rclone is actually running: `sudo docker-compose exec app which rclone`
- Check transfer is actually happening in UI

**"UI still says Initializing"**
- Even if backend is working, frontend might be cached
- Hard refresh: Ctrl+Shift+R

---

Let's find out what rclone is actually saying! 🔍
