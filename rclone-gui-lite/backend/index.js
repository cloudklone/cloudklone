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

require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Middleware
app.use(cors());
app.use(express.json());

// Serve static HTML file
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database
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

    // Create default admin user if none exists
    const userCheck = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const hash = await bcrypt.hash('admin', 10);
      await client.query(
        'INSERT INTO users (username, email, password_hash, is_admin) VALUES ($1, $2, $3, $4)',
        ['admin', 'admin@localhost', hash, true]
      );
      console.log('✓ Default admin user created (username: admin, password: admin)');
      console.log('⚠ Please change the default password immediately!');
    }
  } finally {
    client.release();
  }
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Store active transfers
const activeTransfers = new Map();

// Broadcast to all connected clients
function broadcast(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

// WebSocket connection handler
wss.on('connection', (ws) => {
  console.log('Client connected to WebSocket');

  ws.on('close', () => {
    console.log('Client disconnected from WebSocket');
  });
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
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        isAdmin: user.is_admin,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/register', authenticateToken, async (req, res) => {
  try {
    // Only admins can create new users
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { username, email, password, isAdmin = false } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, username, email, is_admin',
      [username, email, hash, isAdmin]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== USER ROUTES ====================

app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const result = await pool.query(
      'SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC'
    );

    res.json({ users: result.rows });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;

    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/users/:id/password', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { currentPassword, newPassword } = req.body;

    // Users can only change their own password unless they're admin
    if (parseInt(id) !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // If changing own password, verify current password
    if (parseInt(id) === req.user.id) {
      const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [id]);
      const validPassword = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
      
      if (!validPassword) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, id]);

    res.json({ success: true });
  } catch (error) {
    console.error('Change password error:', error);
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
    console.error('Get remotes error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/remotes', authenticateToken, async (req, res) => {
  try {
    const { name, type, config } = req.body;

    if (!name || !type || !config) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const result = await pool.query(
      'INSERT INTO remotes (user_id, name, type, config) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.id, name, type, config]
    );

    // Generate rclone config
    await updateRcloneConfig(req.user.id);

    res.status(201).json({ remote: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Remote name already exists' });
    }
    console.error('Create remote error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/remotes/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, config } = req.body;

    const result = await pool.query(
      'UPDATE remotes SET name = $1, type = $2, config = $3 WHERE id = $4 AND user_id = $5 RETURNING *',
      [name, type, config, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Remote not found' });
    }

    await updateRcloneConfig(req.user.id);

    res.json({ remote: result.rows[0] });
  } catch (error) {
    console.error('Update remote error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/remotes/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query('DELETE FROM remotes WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    await updateRcloneConfig(req.user.id);

    res.json({ success: true });
  } catch (error) {
    console.error('Delete remote error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/remotes/:id/test', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT name FROM remotes WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Remote not found' });
    }

    const remoteName = result.rows[0].name;

    // Test connection using rclone
    const rclone = spawn('rclone', ['lsd', `${remoteName}:`, '--config', `/root/.config/rclone/user_${req.user.id}.conf`]);

    let output = '';
    let errorOutput = '';

    rclone.stdout.on('data', (data) => {
      output += data.toString();
    });

    rclone.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    rclone.on('close', (code) => {
      if (code === 0) {
        res.json({ success: true, message: 'Connection successful' });
      } else {
        res.status(400).json({ success: false, error: errorOutput || 'Connection failed' });
      }
    });
  } catch (error) {
    console.error('Test remote error:', error);
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
    console.error('Get transfers error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/transfers', authenticateToken, async (req, res) => {
  try {
    const { sourceRemote, sourcePath, destRemote, destPath, operation } = req.body;

    if (!sourceRemote || !sourcePath || !destRemote || !destPath || !operation) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const transferId = uuidv4();

    const result = await pool.query(
      'INSERT INTO transfers (user_id, transfer_id, source_remote, source_path, dest_remote, dest_path, operation, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [req.user.id, transferId, sourceRemote, sourcePath, destRemote, destPath, operation, 'queued']
    );

    // Start transfer
    startTransfer(result.rows[0], req.user.id);

    res.status(201).json({ transfer: result.rows[0] });
  } catch (error) {
    console.error('Create transfer error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/transfers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Cancel if active
    const transfer = activeTransfers.get(id);
    if (transfer && transfer.process) {
      transfer.process.kill();
      activeTransfers.delete(id);
    }

    await pool.query('DELETE FROM transfers WHERE transfer_id = $1 AND user_id = $2', [id, req.user.id]);

    res.json({ success: true });
  } catch (error) {
    console.error('Delete transfer error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== HELPER FUNCTIONS ====================

async function updateRcloneConfig(userId) {
  const result = await pool.query('SELECT name, type, config FROM remotes WHERE user_id = $1', [userId]);

  const fs = require('fs').promises;
  const path = require('path');

  const configPath = `/root/.config/rclone/user_${userId}.conf`;
  const configDir = path.dirname(configPath);

  await fs.mkdir(configDir, { recursive: true });

  let configContent = '';

  for (const remote of result.rows) {
    configContent += `[${remote.name}]\n`;
    configContent += `type = ${remote.type}\n`;

    for (const [key, value] of Object.entries(remote.config)) {
      configContent += `${key} = ${value}\n`;
    }

    configContent += '\n';
  }

  await fs.writeFile(configPath, configContent);
}

async function startTransfer(transfer, userId) {
  const configFile = `/root/.config/rclone/user_${userId}.conf`;
  const command = transfer.operation === 'copy' ? 'copy' : 'sync';

  const args = [
    command,
    `${transfer.source_remote}:${transfer.source_path}`,
    `${transfer.dest_remote}:${transfer.dest_path}`,
    '--config', configFile,
    '--progress',
    '--stats', '1s',
    '--stats-one-line',
  ];

  const rclone = spawn('rclone', args);

  activeTransfers.set(transfer.transfer_id, { process: rclone, transfer });

  // Update status
  await pool.query('UPDATE transfers SET status = $1 WHERE transfer_id = $2', ['running', transfer.transfer_id]);

  broadcast({
    type: 'transfer_update',
    transfer: { ...transfer, status: 'running' },
  });

  let lastProgress = {};

  rclone.stderr.on('data', (data) => {
    const output = data.toString();
    
    // Parse rclone stats
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

      // Update database
      pool.query(
        'UPDATE transfers SET progress = $1 WHERE transfer_id = $2',
        [progress, transfer.transfer_id]
      );

      // Broadcast to WebSocket clients
      broadcast({
        type: 'transfer_progress',
        transferId: transfer.transfer_id,
        progress,
      });
    }
  });

  rclone.on('close', async (code) => {
    activeTransfers.delete(transfer.transfer_id);

    if (code === 0) {
      await pool.query(
        'UPDATE transfers SET status = $1, completed_at = CURRENT_TIMESTAMP WHERE transfer_id = $2',
        ['completed', transfer.transfer_id]
      );

      broadcast({
        type: 'transfer_complete',
        transferId: transfer.transfer_id,
      });
    } else {
      await pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        ['failed', `Process exited with code ${code}`, transfer.transfer_id]
      );

      broadcast({
        type: 'transfer_failed',
        transferId: transfer.transfer_id,
        error: `Process exited with code ${code}`,
      });
    }
  });
}

// ==================== PROVIDER METADATA ====================

app.get('/api/providers', (req, res) => {
  res.json({
    providers: [
      {
        id: 's3',
        name: 'Amazon S3',
        type: 's3',
        fields: [
          { name: 'provider', label: 'Provider', type: 'select', options: ['AWS', 'Cloudflare R2', 'Wasabi', 'Other'], required: true },
          { name: 'access_key_id', label: 'Access Key ID', type: 'text', required: true },
          { name: 'secret_access_key', label: 'Secret Access Key', type: 'password', required: true },
          { name: 'region', label: 'Region', type: 'text', required: false },
          { name: 'endpoint', label: 'Endpoint', type: 'text', required: false },
        ],
      },
      {
        id: 'b2',
        name: 'Backblaze B2',
        type: 'b2',
        fields: [
          { name: 'account', label: 'Account ID', type: 'text', required: true },
          { name: 'key', label: 'Application Key', type: 'password', required: true },
        ],
      },
      {
        id: 'gcs',
        name: 'Google Cloud Storage',
        type: 'google cloud storage',
        fields: [
          { name: 'project_number', label: 'Project Number', type: 'text', required: true },
          { name: 'service_account_file', label: 'Service Account JSON', type: 'textarea', required: true },
        ],
      },
      {
        id: 'azure',
        name: 'Azure Blob Storage',
        type: 'azureblob',
        fields: [
          { name: 'account', label: 'Storage Account', type: 'text', required: true },
          { name: 'key', label: 'Storage Account Key', type: 'password', required: true },
        ],
      },
      {
        id: 'dropbox',
        name: 'Dropbox',
        type: 'dropbox',
        fields: [
          { name: 'token', label: 'Access Token', type: 'password', required: true },
        ],
      },
      {
        id: 'gdrive',
        name: 'Google Drive',
        type: 'drive',
        fields: [
          { name: 'client_id', label: 'Client ID', type: 'text', required: true },
          { name: 'client_secret', label: 'Client Secret', type: 'password', required: true },
          { name: 'token', label: 'Access Token', type: 'textarea', required: false },
        ],
      },
      {
        id: 'sftp',
        name: 'SFTP',
        type: 'sftp',
        fields: [
          { name: 'host', label: 'Host', type: 'text', required: true },
          { name: 'user', label: 'Username', type: 'text', required: true },
          { name: 'pass', label: 'Password', type: 'password', required: false },
          { name: 'key_file', label: 'SSH Key Path', type: 'text', required: false },
          { name: 'port', label: 'Port', type: 'number', default: 22, required: false },
        ],
      },
      {
        id: 'local',
        name: 'Local Filesystem',
        type: 'local',
        fields: [],
      },
    ],
  });
});

// Start server
const PORT = process.env.PORT || 3001;

initDatabase()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`✓ Backend server running on port ${PORT}`);
      console.log(`✓ WebSocket server ready at ws://localhost:${PORT}/ws`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
