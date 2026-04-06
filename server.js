/**
 * KEY AUTH SYSTEM — Backend Server
 * Run: node server.js
 * Requires: npm install express cors uuid
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const KEYS_FILE = path.join(__dirname, 'keys.json');
const ADMIN_SECRET = '1'; // Change this!

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Helpers ─────────────────────────────────────────────
function loadKeys() {
  if (!fs.existsSync(KEYS_FILE)) return {};
  return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
}

function saveKeys(keys) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

function generateKey(prefix = 'SK') {
  const rand = crypto.randomBytes(16).toString('hex').toUpperCase();
  return `${prefix}-${rand.slice(0,4)}-${rand.slice(4,8)}-${rand.slice(8,12)}-${rand.slice(12,16)}`;
}

function isExpired(key_data) {
  if (!key_data.expires_at) return false;
  return new Date() > new Date(key_data.expires_at);
}

// ─── Middleware: Admin Auth ───────────────────────────────
function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (secret !== ADMIN_SECRET) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  next();
}

// ─── USER ROUTES ─────────────────────────────────────────

// POST /api/validate — Validate a key
app.post('/api/validate', (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, error: 'Key required' });

  const keys = loadKeys();
  const keyData = keys[key];

  if (!keyData) {
    return res.json({ success: false, error: 'Invalid key' });
  }

  if (!keyData.active) {
    return res.json({ success: false, error: 'Key has been revoked' });
  }

  if (isExpired(keyData)) {
    return res.json({ success: false, error: 'Key has expired' });
  }

  // Update last used
  keys[key].last_used = new Date().toISOString();
  keys[key].use_count = (keys[key].use_count || 0) + 1;
  saveKeys(keys);

  return res.json({
    success: true,
    message: 'Access granted',
    user: keyData.label || 'User',
    expires_at: keyData.expires_at || null,
  });
});

// ─── ADMIN ROUTES ─────────────────────────────────────────

// POST /api/admin/generate — Create a new key
app.post('/api/admin/generate', adminAuth, (req, res) => {
  const { label, expires_days, prefix } = req.body;
  const keys = loadKeys();

  const newKey = generateKey(prefix || 'SK');
  const now = new Date();
  let expires_at = null;

  if (expires_days && parseInt(expires_days) > 0) {
    const exp = new Date(now);
    exp.setDate(exp.getDate() + parseInt(expires_days));
    expires_at = exp.toISOString();
  }

  keys[newKey] = {
    label: label || 'User',
    active: true,
    created_at: now.toISOString(),
    expires_at,
    last_used: null,
    use_count: 0,
  };

  saveKeys(keys);
  res.json({ success: true, key: newKey, expires_at });
});

// GET /api/admin/keys — List all keys
app.get('/api/admin/keys', adminAuth, (req, res) => {
  const keys = loadKeys();
  const result = Object.entries(keys).map(([key, data]) => ({
    key,
    ...data,
    is_expired: isExpired(data),
  }));
  res.json({ success: true, keys: result });
});

// POST /api/admin/revoke — Revoke a key
app.post('/api/admin/revoke', adminAuth, (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();

  if (!keys[key]) return res.status(404).json({ success: false, error: 'Key not found' });

  keys[key].active = false;
  saveKeys(keys);
  res.json({ success: true, message: 'Key revoked' });
});

// POST /api/admin/delete — Delete a key permanently
app.post('/api/admin/delete', adminAuth, (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();

  if (!keys[key]) return res.status(404).json({ success: false, error: 'Key not found' });

  delete keys[key];
  saveKeys(keys);
  res.json({ success: true, message: 'Key deleted' });
});

// ─── Start ────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ Key Auth Server running → http://localhost:${PORT}`);
  console.log(`📁 Keys stored in: ${KEYS_FILE}`);
  console.log(`🔐 Admin secret: ${ADMIN_SECRET}\n`);
});
