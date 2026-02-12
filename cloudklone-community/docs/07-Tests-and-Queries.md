# Tests & Queries

Browse files, test connections, and explore your cloud storage before transferring.

## What is Tests & Queries?

This tab lets you:
- **Browse** files in your remotes
- **Test** connections before transfers
- **Verify** paths exist
- **Check** file sizes
- **Preview** file contents

Think of it as a file browser for all your cloud storage.

## Why Use Tests & Queries?

✅ **Verify Before Transfer** - Make sure paths are correct  
✅ **Estimate Size** - See how much data you'll transfer  
✅ **Test Credentials** - Confirm remotes work  
✅ **Find Files** - Locate specific files or folders  
✅ **Troubleshoot** - Debug transfer issues  

## Available Commands

### ls - List Files and Folders
**What it does:** Lists everything in a directory

**Use when:**
- Browsing a remote
- Finding folders
- Seeing what's available
- Verifying paths

**Example:**
```
Remote: aws-s3
Path: /photos
Result: Shows all folders and files in /photos
```

### lsf - List Files Only
**What it does:** Lists only files (no folders)

**Use when:**
- Counting files
- Finding specific files
- Getting file list
- Estimating file count

**Example:**
```
Remote: gdrive
Path: /documents
Result: Lists only files, not subdirectories
```

### size - Calculate Size
**What it does:** Shows total size of path

**Use when:**
- Planning transfers
- Checking storage usage
- Estimating transfer time
- Verifying quotas

**Example:**
```
Remote: dropbox
Path: /backups
Result: Total size: 150 GB, 1,234 files
```

### cat - View File Contents
**What it does:** Displays text file contents

**Use when:**
- Reading small text files
- Viewing logs
- Checking config files
- Verifying file contents

**Example:**
```
Remote: sftp-server
Path: /logs
Filename: error.log
Result: Shows file contents
```

**Note:** Only works with text files!

### tree - Directory Structure
**What it does:** Shows folder hierarchy

**Use when:**
- Understanding organization
- Planning sync operations
- Documenting structure
- Finding nested folders

**Example:**
```
Remote: local
Path: /home/user
Result: Tree view of all folders and subfolders
```

## Running Queries

### Basic Query (4 Steps)

**Step 1: Go to Tests & Queries Tab**
Click **Tests & Queries** in sidebar

**Step 2: Select Remote**
Choose from dropdown (must be already configured)

**Step 3: Choose Command**
Select ls, lsf, size, cat, or tree

**Step 4: Enter Path**
- Type the path (e.g., `/photos`)
- Or leave blank for root (`/`)

**Step 5: Run**
Click **Run Query** button

**Step 6: View Results**
Results appear below in a scrollable box

### Quick Examples

**List everything in root:**
```
Remote: aws-s3
Command: ls
Path: /
Run → See all top-level folders/files
```

**Check folder size:**
```
Remote: gdrive
Command: size
Path: /backups/2024
Run → See total GB and file count
```

**Find files in subfolder:**
```
Remote: dropbox
Command: lsf
Path: /work/reports
Run → List all report files
```

**Read a log file:**
```
Remote: sftp-server
Command: cat
Path: /var/log
Filename: access.log
Run → Display file contents
```

## Understanding Results

### ls Output
```
drwxr-xr-x    - folder1/
drwxr-xr-x    - folder2/
-rw-r--r-- 1.5M file1.pdf
-rw-r--r-- 500K file2.jpg
```

**Reading:**
- Lines starting with `d` = directories (folders)
- Lines starting with `-` = files
- Size shown (1.5M = 1.5 megabytes)
- Name at end

### lsf Output
```
file1.pdf
file2.jpg
report.docx
data.csv
```

**Reading:**
- Just filenames (no folders)
- No size info
- Simple list

### size Output
```
Total objects: 1,234
Total size: 150.5 GB (161,579,841,536 bytes)
```

**Reading:**
- Number of files
- Human-readable size
- Exact bytes

### cat Output
```
2024-02-09 10:15:23 [INFO] Transfer started
2024-02-09 10:15:45 [INFO] Transferred 100 MB
2024-02-09 10:16:12 [INFO] Transfer complete
```

**Reading:**
- Actual file contents
- Formatted as plain text
- Scrollable for long files

### tree Output
```
/
├── folder1/
│   ├── subfolder1/
│   └── file1.txt
├── folder2/
│   └── subfolder2/
│       └── file2.pdf
└── file3.jpg
```

**Reading:**
- Visual hierarchy
- Shows nesting
- Indentation = depth

## Common Use Cases

### Before Transfer: Verify Path
**Scenario:** Planning to transfer `/backups/daily`

**Steps:**
1. Command: `ls`
2. Path: `/backups`
3. Run Query
4. Verify `daily/` folder exists

**Why:** Prevents "path not found" errors

### Planning: Estimate Transfer Time
**Scenario:** Want to know how long transfer will take

**Steps:**
1. Command: `size`
2. Path: `/photos/2024`
3. Run Query
4. See total GB

**Calculation:**
```
Size: 100 GB
Speed: 50 MB/s
Time: 100 GB ÷ 50 MB/s ≈ 35 minutes
```

### Troubleshooting: Find Missing Files
**Scenario:** Transfer completed but files missing

**Steps:**
1. Command: `lsf`
2. Path: destination path
3. Run Query
4. Count files
5. Compare to source

**Result:** Identify if files actually transferred

### Debugging: Read Error Logs
**Scenario:** Transfer failed, need details

**Steps:**
1. Command: `cat`
2. Path: `/logs`
3. Filename: `transfer.log`
4. Run Query
5. Read error messages

**Result:** Understand what went wrong

### Documentation: Map Structure
**Scenario:** Need to document folder organization

**Steps:**
1. Command: `tree`
2. Path: `/`
3. Run Query
4. Copy output
5. Paste into documentation

**Result:** Complete directory map

## Tips and Tricks

### Tip 1: Test Paths Before Scheduling
Before creating scheduled transfers:
```
1. ls the source path
2. Verify folders exist
3. Check file counts
4. Then schedule
```

### Tip 2: Use lsf for File Counts
Need to count files?
```
1. Run lsf command
2. Look at result line count
3. Matches file count
```

### Tip 3: Size for Quota Management
Monitor storage usage:
```
Weekly: Run size on each remote
Track: Total GB over time
Alert: When approaching quota
```

### Tip 4: cat for Quick Checks
Before downloading large logs:
```
1. cat first 100 lines
2. See if it has what you need
3. Then decide to download
```

### Tip 5: Tree for Planning Syncs
Before sync operations:
```
1. Tree the source
2. Tree the destination
3. Compare structures
4. Plan sync strategy
```

## Limitations

### cat Command
❌ **Won't work on:**
- Binary files (images, videos, PDFs)
- Very large files (>1 MB)
- Encrypted files

✅ **Works on:**
- Text files (.txt, .log, .csv)
- Config files (.conf, .json, .yaml)
- Code files (.py, .js, .html)

### size Command
- May be slow on huge directories
- Counts all nested files
- Can timeout on extremely large paths

### tree Command
- Limited depth on some remotes
- Very large trees may truncate
- Slow on deep hierarchies

## Permissions

Some remotes may restrict:
- Listing certain paths
- Reading file contents
- Accessing system folders

**If you get "Access Denied":**
- Check remote permissions
- Verify path is accessible
- Try parent directory
- Contact admin if needed

## Query Performance

### Fast Operations
✅ ls on small directories (< 1000 files)  
✅ lsf on single folder  
✅ cat on small files (< 100 KB)  

### Slow Operations
⏳ size on huge directories (takes time to scan)  
⏳ tree on deep hierarchies  
⏳ ls on folders with 10,000+ files  

**Tip:** Be patient with large operations!

## Best Practices

### Before Queries
✅ Test remote first  
✅ Start with root path  
✅ Narrow down gradually  
✅ Use specific paths  

### During Queries
✅ Wait for completion  
✅ Don't run multiple simultaneously  
✅ Check for errors  
✅ Copy results if needed  

### After Queries
✅ Verify path accuracy  
✅ Note file counts  
✅ Document findings  
✅ Plan transfers accordingly  

## Troubleshooting

### Query Timeout
**Symptom:** Query runs forever

**Causes:**
- Path too large
- Slow remote
- Network issues

**Solutions:**
- Use more specific path
- Try smaller subdirectory
- Check network connection
- Wait and retry

### No Results
**Symptom:** Query returns empty

**Causes:**
- Path doesn't exist
- No files in directory
- Wrong path format

**Solutions:**
- Try parent directory
- Check path spelling
- Use ls on root first
- Verify with file manager

### Permission Denied
**Symptom:** "Access denied" error

**Causes:**
- Insufficient permissions
- Protected system path
- Expired credentials

**Solutions:**
- Check remote permissions
- Update credentials
- Try different path
- Contact administrator

## Quick Reference

| Command | Purpose | Example |
|---------|---------|---------|
| ls | List all items | Browse folders |
| lsf | List files only | Count files |
| size | Calculate size | Plan transfer |
| cat | Read text file | View logs |
| tree | Show structure | Map folders |

| Task | Command to Use |
|------|----------------|
| Verify path exists | ls |
| Count files | lsf |
| Estimate transfer time | size |
| Read log file | cat |
| Document structure | tree |
| Find subfolder | ls |
| Check permissions | ls |

---

**Remember:** Always test and explore with queries before running large transfers. A few minutes of testing saves hours of troubleshooting!
