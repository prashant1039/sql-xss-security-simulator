const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const useragent = require('express-useragent');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const app = express();
const port = 3000;

const db = new sqlite3.Database('users.db');
const blockedIPs = new Set();
const blockedMACs = new Set();
const suspiciousCounter = {};
const failedLoginCounter = {};
const tokenStore = {}; // email => { token, timestamp }

app.use(bodyParser.json());
app.use(useragent.express());
app.use(express.static(__dirname));

// Utility
const getMAC = ip => 00:1A:2B:${ip.split('.').join(':')};
const generateToken = () => crypto.randomBytes(16).toString('hex');

// Login Route (with SQLite auth + device checks)
app.post('/login', (req, res) => {
  const { username, password, token } = req.body;
  const ip = req.ip;
  const mac = getMAC(ip);
  const isRemote = req.useragent?.isRemote || false;
  const fingerprint = req.headers['user-agent'] + ip;

  const key = ${ip}-${mac};
  suspiciousCounter[key] = (suspiciousCounter[key] || 0) + 1;

  if (isRemote || blockedIPs.has(ip) || blockedMACs.has(mac)) {
    blockedIPs.add(ip);
    blockedMACs.add(mac);
    return res.json({ result: 'Blocked due to suspicious device or remote access.', ip, mac, isRemote });
  }

  if (suspiciousCounter[key] >= 3) {
    blockedIPs.add(ip);
    blockedMACs.add(mac);
  }

  db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, row) => {
    if (err) return res.status(500).json({ result: 'DB error', ip, mac });
    
    if (!row) {
      failedLoginCounter[username] = (failedLoginCounter[username] || 0) + 1;
      if (failedLoginCounter[username] >= 5) {
        return res.json({ result: 'Too many failed attempts. Use /reset-password', ip, mac });
      }
      return res.json({ result: 'Invalid Credentials', ip, mac });
    }

    // Simulated 2FA token check
    if (!token || token !== '123456') {
      return res.json({ result: '2FA token required or invalid. Try 123456.', ip, mac });
    }

    failedLoginCounter[username] = 0;

    const log = [${new Date().toISOString()}] IP: ${ip}, MAC: ${mac}, USER: ${username}, OK\n;
    fs.appendFileSync('logs.txt', log);

    res.json({ result: '✅ Login Successful', ip, mac });
  });
});

// XSS Simulation
app.post('/comment', (req, res) => {
  const comment = req.body.comment || '';
  fs.appendFileSync('comments.txt', [${new Date().toISOString()}] ${comment}\n);
  res.send(comment); // XSS-intentional
});

// Request Reset Token
app.post('/request-reset', (req, res) => {
  const { email } = req.body;
  db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
    if (err || !row) return res.json({ result: 'Email not found' });

    const token = generateToken();
    tokenStore[email] = { token, timestamp: Date.now() };
    console.log([TOKEN] For ${email}: ${token});

    res.json({ result: 'Reset token sent (check console in this demo)' });
  });
});

// Reset Password
app.post('/reset-password', (req, res) => {
  const { email, token, newpass } = req.body;
  const entry = tokenStore[email];

  if (!entry || entry.token !== token || Date.now() - entry.timestamp > 15 * 60 * 1000) {
    return res.json({ result: 'Invalid or expired token' });
  }

  db.run("UPDATE users SET password = ? WHERE email = ?", [newpass, email], (err) => {
    if (err) return res.json({ result: 'Error updating password' });
    delete tokenStore[email];
    res.json({ result: '✅ Password updated successfully' });
  });
});

// Admin Dashboard
app.get('/admin', (req, res) => {
  const auth = req.headers.authorization || '';
  const valid = auth === 'Basic ' + Buffer.from('admin:adminpass').toString('base64');
  if (!valid) {
    res.set('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Unauthorized');
  }

  const logs = fs.existsSync('logs.txt') ? fs.readFileSync('logs.txt', 'utf-8') : 'No logs.';
  const comments = fs.existsSync('comments.txt') ? fs.readFileSync('comments.txt', 'utf-8') : 'No comments.';

  res.send(`
    <html><body>
      <h2>🛠 Admin Panel</h2>
      <h3>Login Logs</h3><pre>${logs}</pre>
      <form action="/admin/clear-logs" method="POST"><button>Clear Logs</button></form>
      <h3>Comments</h3><pre>${comments}</pre>
      <form action="/admin/clear-comments" method="POST"><button>Clear Comments</button></form>
    </body></html>
  `);
});

app.post('/admin/clear-logs', (req, res) => {
  fs.writeFileSync('logs.txt', '');
  res.redirect('/admin');
});

app.post('/admin/clear-comments', (req, res) => {
  fs.writeFileSync('comments.txt', '');
  res.redirect('/admin');
});

app.listen(port, () => {
  console.log(🚀 Server running at http://localhost:${port});
});
