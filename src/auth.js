const crypto = require('crypto');
const db = require('./db');

// ⚡ Bolt: Pre-compile frequently used statements to eliminate parsing overhead on every request
const getSessionStmt = db.prepare('SELECT expires_at FROM sessions WHERE token = ?');
const deleteSessionStmt = db.prepare('DELETE FROM sessions WHERE token = ?');
const getFirstUserStmt = db.prepare('SELECT id FROM users WHERE id = 1');
const sessionStreams = new Map();

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function isSessionValid(token) {
  if (!token) return false;
  const session = getSessionStmt.get(token);
  if (!session) return false;
  if (Date.now() < session.expires_at) return true;
  deleteSessionStmt.run(token);
  return false;
}

function subscribeSessionRevocation(token, close) {
  if (!sessionStreams.has(token)) sessionStreams.set(token, new Set());
  const streams = sessionStreams.get(token);
  streams.add(close);
  return () => {
    streams.delete(close);
    if (streams.size === 0) sessionStreams.delete(token);
  };
}

function revokeSessionStreams(token) {
  const streams = token ? [sessionStreams.get(token)] : [...sessionStreams.values()];
  for (const listeners of streams) {
    for (const close of [...(listeners || [])]) close();
  }
}

function authMiddleware(req, res, next) {
  const allowList = ['/login', '/login.html', '/setup.html', '/i18n.js', '/theme.css'];
  if (allowList.includes(req.path) || req.path.startsWith('/assets/') || req.path.startsWith('/vendor/')) {
    return next();
  }

  const token = req.cookies.session;
  if (!isSessionValid(token)) {
    if (req.path.toLowerCase().startsWith('/api/')) {
      return res.status(401).send('Unauthorized');
    } else {
      return res.redirect('/login.html');
    }
  }

  // Enforce setup if trying to access main app but users table is empty
  if (req.path === '/' || req.path === '/index.html') {
    const userRow = getFirstUserStmt.get();
    if (!userRow) {
      return res.redirect('/setup.html');
    }
  }

  next();
}

function csrfMiddleware(req, res, next) {
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (!safeMethods.includes(req.method) && req.path.toLowerCase().startsWith('/api/')) {
    if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
      return res.status(403).send('CSRF check failed: missing X-Requested-With header');
    }
  }
  next();
}

module.exports = {
  generateSessionToken,
  authMiddleware,
  csrfMiddleware,
  isSessionValid,
  subscribeSessionRevocation,
  revokeSessionStreams,
};
