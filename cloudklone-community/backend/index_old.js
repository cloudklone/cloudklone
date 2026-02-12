const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(cors());
app.use(express.json());

// Serve index.html for all non-API routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve logo
app.get('/logo.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'logo.png'));
});

// ==================== AUTH ROUTES ====================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query(
      'SELECT id, username, email, password_hash, is_admin FROM users WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, username: user.username, isAdmin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({
      token,
      user: { id: user.id, username: user.username, email: user.email, isAdmin: user.is_admin },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/register', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const { username, email, password, isAdmin = false } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Missing required fields' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, username, email, is_admin',
      [username, email, hash, isAdmin]
    );
    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Username or email already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== USER ROUTES ====================

app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const result = await pool.query('SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC');
    res.json({ users: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/users/:id/password', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { currentPassword, newPassword } = req.body;
    if (parseInt(id) !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: 'Access denied' });
    if (parseInt(id) === req.user.id) {
      const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [id]);
      const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
      if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    }
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== REMOTE ROUTES ====================

app.get('/api/remotes', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, type, config, created_at FROM remotes WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ remotes: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/remotes', authenticateToken, async (req, res) => {
  try {
    const { name, type, config } = req.body;
    if (!name || !type || !config) return res.status(400).json({ error: 'Missing required fields' });
    
    // Validate endpoint for S3-compatible services
    if (type === 's3' && config.endpoint) {
      try {
        new URL(config.endpoint);
      } catch (e) {
        return res.status(400).json({ error: 'Invalid endpoint URL format' });
      }
    }
    
    // First, create temporary rclone config to test
    const fs = require('fs').promises;
    const tempConfigPath = `/tmp/rclone_test_${Date.now()}.conf`;
    let configContent = `[${name}]\ntype = ${type}\n`;
    for (const [key, value] of Object.entries(config)) {
      configContent += `${key} = ${value}\n`;
    }
    await fs.writeFile(tempConfigPath, configContent);
    
    // Build test args with SFTP host key skip if needed
    const testArgs = ['lsd', `${name}:`, '--config', tempConfigPath, '--max-depth', '1'];
    if (type === 'sftp') {
      testArgs.push('--sftp-skip-links');
    }
    
    // Test the remote connection
    const testResult = await new Promise((resolve) => {
      const rclone = spawn('rclone', testArgs);
      let errorOutput = '';
      let stdOutput = '';
      
      rclone.stderr.on('data', (data) => { errorOutput += data.toString(); });
      rclone.stdout.on('data', (data) => { stdOutput += data.toString(); });
      
      rclone.on('close', (code) => {
        fs.unlink(tempConfigPath).catch(() => {}); // Clean up temp file
        
        // Extract endpoint info from success
        let detectedRegion = config.region || 'unknown';
        let detectedEndpoint = config.endpoint || 'default';
        
        if (type === 's3' && stdOutput) {
          // Successfully connected, extract any region info
          if (config.endpoint && config.endpoint.includes('r2.cloudflarestorage.com')) {
            detectedRegion = 'Cloudflare R2';
          } else if (config.endpoint && config.endpoint.includes('s3.wasabisys.com')) {
            detectedRegion = 'Wasabi';
          } else if (config.region) {
            detectedRegion = config.region;
          }
        }
        
        resolve({ 
          success: code === 0, 
          error: errorOutput,
          region: detectedRegion,
          endpoint: detectedEndpoint
        });
      });
      
      // Timeout after 15 seconds
      setTimeout(() => {
        rclone.kill();
        fs.unlink(tempConfigPath).catch(() => {});
        resolve({ success: false, error: 'Connection timeout (15s)' });
      }, 15000);
    });
    
    if (!testResult.success) {
      return res.status(400).json({ 
        error: 'Remote connection failed. Please check your credentials and endpoint.', 
        details: testResult.error.substring(0, 500)
      });
    }
    
    // Connection successful, save to database with metadata
    const metadata = {
      verified_at: new Date().toISOString(),
      region: testResult.region,
      endpoint: testResult.endpoint
    };
    
    const result = await pool.query(
      'INSERT INTO remotes (user_id, name, type, config) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.id, name, type, { ...config, _metadata: metadata }]
    );
    await updateRcloneConfig(req.user.id);
    
    res.status(201).json({ 
      remote: result.rows[0],
      message: `✅ Connected to ${testResult.region}${testResult.endpoint !== 'default' ? ' at ' + testResult.endpoint : ''}`
    });
  } catch (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Remote name already exists' });
    console.error('Create remote error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/remotes/:id', authenticateToken, async (req, res) => {
  try {
    const { name, type, config } = req.body;
    const result = await pool.query(
      'UPDATE remotes SET name = $1, type = $2, config = $3 WHERE id = $4 AND user_id = $5 RETURNING *',
      [name, type, config, req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Remote not found' });
    await updateRcloneConfig(req.user.id);
    res.json({ remote: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/remotes/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM remotes WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    await updateRcloneConfig(req.user.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/remotes/:id/test', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT name FROM remotes WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Remote not found' });
    const remoteName = result.rows[0].name;
    const rclone = spawn('rclone', ['lsd', `${remoteName}:`, '--config', `/root/.config/rclone/user_${req.user.id}.conf`]);
    let errorOutput = '';
    rclone.stderr.on('data', (data) => { errorOutput += data.toString(); });
    rclone.on('close', (code) => {
      if (code === 0) res.json({ success: true, message: 'Connection successful' });
      else res.status(400).json({ success: false, error: errorOutput || 'Connection failed' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== TRANSFER ROUTES ====================

app.get('/api/transfers', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM transfers WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100',
      [req.user.id]
    );
    res.json({ transfers: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/transfers', authenticateToken, async (req, res) => {
  try {
    const { sourceRemote, sourcePath, destRemote, destPath, operation } = req.body;
    if (!sourceRemote || !sourcePath || !destRemote || !destPath || !operation)
      return res.status(400).json({ error: 'Missing required fields' });
    const transferId = uuidv4();
    const result = await pool.query(
      'INSERT INTO transfers (user_id, transfer_id, source_remote, source_path, dest_remote, dest_path, operation, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [req.user.id, transferId, sourceRemote, sourcePath, destRemote, destPath, operation, 'queued']
    );
    startTransfer(result.rows[0], req.user.id);
    res.status(201).json({ transfer: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/transfers/:id', authenticateToken, async (req, res) => {
  try {
    const transfer = activeTransfers.get(req.params.id);
    if (transfer && transfer.process) { transfer.process.kill(); activeTransfers.delete(req.params.id); }
    await pool.query('DELETE FROM transfers WHERE transfer_id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== PROVIDER METADATA ====================

app.get('/api/providers', (req, res) => {
  res.json({
    providers: [
      { id: 's3', name: 'Amazon S3 / Cloudflare R2', type: 's3', fields: [
        { name: 'provider', label: 'Provider', type: 'select', options: ['AWS', 'Cloudflare R2', 'Wasabi', 'Other'], required: true },
        { name: 'access_key_id', label: 'Access Key ID', type: 'text', required: true },
        { name: 'secret_access_key', label: 'Secret Access Key', type: 'password', required: true },
        { name: 'region', label: 'Region', type: 'text', required: false },
        { name: 'endpoint', label: 'Endpoint URL', type: 'text', required: false },
      ]},
      { id: 'b2', name: 'Backblaze B2', type: 'b2', fields: [
        { name: 'account', label: 'Account ID', type: 'text', required: true },
        { name: 'key', label: 'Application Key', type: 'password', required: true },
      ]},
      { id: 'gcs', name: 'Google Cloud Storage', type: 'google cloud storage', fields: [
        { name: 'project_number', label: 'Project Number', type: 'text', required: true },
        { name: 'service_account_file', label: 'Service Account JSON', type: 'textarea', required: true },
      ]},
      { id: 'azure', name: 'Azure Blob Storage', type: 'azureblob', fields: [
        { name: 'account', label: 'Storage Account', type: 'text', required: true },
        { name: 'key', label: 'Storage Account Key', type: 'password', required: true },
      ]},
      { id: 'dropbox', name: 'Dropbox', type: 'dropbox', fields: [
        { name: 'token', label: 'Access Token', type: 'password', required: true },
      ]},
      { id: 'gdrive', name: 'Google Drive', type: 'drive', fields: [
        { name: 'client_id', label: 'Client ID', type: 'text', required: true },
        { name: 'client_secret', label: 'Client Secret', type: 'password', required: true },
      ]},
      { id: 'sftp', name: 'SFTP', type: 'sftp', fields: [
        { name: 'host', label: 'Host', type: 'text', required: true },
        { name: 'user', label: 'Username', type: 'text', required: true },
        { name: 'pass', label: 'Password', type: 'password', required: false },
        { name: 'port', label: 'Port', type: 'number', default: '22', required: false },
      ]},
      { id: 'local', name: 'Local Filesystem', type: 'local', fields: [] },
    ],
  });
});

// ==================== MIDDLEWARE & HELPERS ====================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

const activeTransfers = new Map();

function broadcast(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify(data));
  });
}

wss.on('connection', (ws) => {
  console.log('WebSocket client connected');
  ws.on('close', () => console.log('WebSocket client disconnected'));
});

async function updateRcloneConfig(userId) {
  const result = await pool.query('SELECT name, type, config FROM remotes WHERE user_id = $1', [userId]);
  const configPath = `/root/.config/rclone/user_${userId}.conf`;
  await fs.mkdir(path.dirname(configPath), { recursive: true });
  let content = '';
  for (const remote of result.rows) {
    content += `[${remote.name}]\ntype = ${remote.type}\n`;
    for (const [key, value] of Object.entries(remote.config)) content += `${key} = ${value}\n`;
    content += '\n';
  }
  await fs.writeFile(configPath, content);
}

async function startTransfer(transfer, userId) {
  const configFile = `/root/.config/rclone/user_${userId}.conf`;
  const command = transfer.operation === 'copy' ? 'copy' : 'sync';
  
  // Build rclone args with proper flags
  const args = [
    command,
    `${transfer.source_remote}:${transfer.source_path}`,
    `${transfer.dest_remote}:${transfer.dest_path}`,
    '--config', configFile,
    '--progress',
    '--stats', '1s',
    '--stats-one-line',
    '--retries', '3',
    '--low-level-retries', '10',
    '--transfers', '4',
    '--checkers', '8',
    '--buffer-size', '16M',
  ];
  
  // Get remote types to add type-specific flags
  const remotes = await pool.query(
    'SELECT name, type FROM remotes WHERE user_id = $1 AND (name = $2 OR name = $3)',
    [userId, transfer.source_remote, transfer.dest_remote]
  );
  
  // Add SFTP-specific flags if either remote is SFTP
  const hasSftp = remotes.rows.some(r => r.type === 'sftp');
  if (hasSftp) {
    args.push('--sftp-skip-links');
    args.push('--sftp-set-modtime=false');
    args.push('--ignore-checksum');
  }
  
  const rclone = spawn('rclone', args);
  activeTransfers.set(transfer.transfer_id, { process: rclone, transfer });
  await pool.query('UPDATE transfers SET status = $1 WHERE transfer_id = $2', ['running', transfer.transfer_id]);
  broadcast({ type: 'transfer_update', transfer: { ...transfer, status: 'running' } });
  
  let lastProgress = {};
  let lastUpdateTime = Date.now();
  let errorOutput = '';
  
  // Timeout after 2 hours of no progress
  const timeoutCheck = setInterval(() => {
    const timeSinceUpdate = Date.now() - lastUpdateTime;
    if (timeSinceUpdate > 7200000) { // 2 hours
      console.log(`Transfer ${transfer.transfer_id} timed out after 2 hours of inactivity`);
      rclone.kill();
      clearInterval(timeoutCheck);
    }
  }, 60000); // Check every minute
  
  rclone.stderr.on('data', (data) => {
    const output = data.toString();
    errorOutput += output;
    lastUpdateTime = Date.now();
    
    const transferredMatch = output.match(/Transferred:\s+([^,]+),\s+(\d+)%/);
    const speedMatch = output.match(/(\d+\.?\d*\s*\w+\/s)/);
    const etaMatch = output.match(/ETA\s+(\S+)/);
    
    if (transferredMatch || speedMatch || etaMatch) {
      const progress = {
        transferred: transferredMatch ? transferredMatch[1].trim() : lastProgress.transferred,
        percentage: transferredMatch ? parseInt(transferredMatch[2]) : lastProgress.percentage,
        speed: speedMatch ? speedMatch[1] : lastProgress.speed,
        eta: etaMatch ? etaMatch[1] : lastProgress.eta,
      };
      lastProgress = progress;
      pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [progress, transfer.transfer_id]);
      broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress });
    }
    
    // Log errors for debugging
    if (output.includes('ERROR') || output.includes('NOTICE') || output.includes('Failed')) {
      console.log(`Transfer ${transfer.transfer_id} error:`, output.substring(0, 200));
    }
  });
  
  rclone.stdout.on('data', (data) => {
    lastUpdateTime = Date.now();
  });
  
  rclone.on('close', async (code) => {
    clearInterval(timeoutCheck);
    activeTransfers.delete(transfer.transfer_id);
    
    if (code === 0) {
      await pool.query('UPDATE transfers SET status = $1, completed_at = CURRENT_TIMESTAMP WHERE transfer_id = $2', ['completed', transfer.transfer_id]);
      broadcast({ type: 'transfer_complete', transferId: transfer.transfer_id });
    } else {
      // Extract meaningful error from output
      let errorMessage = `Transfer failed (exit code ${code})`;
      const errorLines = errorOutput.split('\n').filter(line => 
        line.includes('ERROR') || line.includes('Failed') || line.includes('NOTICE')
      );
      if (errorLines.length > 0) {
        errorMessage = errorLines[0].substring(0, 200); // First error, max 200 chars
      }
      
      await pool.query('UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3', ['failed', errorMessage, transfer.transfer_id]);
      broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: errorMessage });
    }
  });
  
  rclone.on('error', async (err) => {
    clearInterval(timeoutCheck);
    activeTransfers.delete(transfer.transfer_id);
    const errorMessage = `Failed to start transfer: ${err.message}`;
    await pool.query('UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3', ['failed', errorMessage, transfer.transfer_id]);
    broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: errorMessage });
  });
}

// ==================== DATABASE INIT & SERVER START ====================

async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS remotes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        config JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, name)
      );
      CREATE TABLE IF NOT EXISTS transfers (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        transfer_id VARCHAR(255) UNIQUE NOT NULL,
        source_remote VARCHAR(255) NOT NULL,
        source_path TEXT NOT NULL,
        dest_remote VARCHAR(255) NOT NULL,
        dest_path TEXT NOT NULL,
        operation VARCHAR(20) NOT NULL,
        status VARCHAR(20) DEFAULT 'queued',
        progress JSONB,
        error TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      );
    `);
    const userCheck = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const hash = await bcrypt.hash('admin', 10);
      await client.query(
        'INSERT INTO users (username, email, password_hash, is_admin) VALUES ($1, $2, $3, $4)',
        ['admin', 'admin@localhost', hash, true]
      );
      console.log('✓ Default admin user created (admin / admin)');
    }
  } finally {
    client.release();
  }
}

const PORT = process.env.PORT || 3001;

initDatabase()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`✓ Server listening on 0.0.0.0:${PORT}`);
      console.log(`✓ WebSocket ready on ws://0.0.0.0:${PORT}/ws`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
