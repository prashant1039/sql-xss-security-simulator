const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const os = require('os');
const cors = require('cors');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { networkInterfaces } = require('os');

const PORT = 3000;

let failedLoginMap = new Map(); // IP -> { count, mac }

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

function getIPAddress(req) {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress;
}

function getMacAddress() {
  const nets = networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (!net.internal && net.mac !== '00:00:00:00:00:00') {
        return net.mac;
      }
    }
  }
  return 'unknown';
}

function isRemoteSession() {
  return process.env.SESSIONNAME && process.env.SESSIONNAME.toLowerCase().includes('rdp');
}

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ip = getIPAddress(req);
  const mac = getMacAddress();
  const remote = isRemoteSession();

  const previous = failedLoginMap.get(ip);
  const oldMac = previous?.mac;

  if (previous && previous.count >= 5) {
    return res.json({ result: '❌ Too many failed attempts. Access blocked.' });
  }

  if (remote) {
    return res.json({ result: '⚠️ Remote sessions not allowed.' });
  }

  if (oldMac && oldMac !== mac) {
    return res.json({ result: '⚠️ MAC address changed. Access suspicious.' });
  }

  if (
    username === 'admin' &&
    (password === 'admin' || password === `' OR '1'='1` || password === `' OR 1=1 --`)
  ) {
    failedLoginMap.delete(ip);
    return res.json({ result: `✅ Welcome, admin! SQL Injection success.` });
  } else {
    const currentTime = new Date().toISOString();
    const logEntry = `[${currentTime}] Failed login from IP: ${ip}, MAC: ${mac}\n`;
    fs.appendFileSync('log.txt', logEntry);

    if (!failedLoginMap.has(ip)) {
      failedLoginMap.set(ip, { count: 1, mac });
    } else {
      failedLoginMap.set(ip, {
        count: failedLoginMap.get(ip).count + 1,
        mac
      });
    }
    return res.json({ result: '❌ Invalid credentials.' });
  }
});

app.post('/comment', (req, res) => {
  const { comment } = req.body;
  const timestamp = new Date().toISOString();
  const entry = `[${timestamp}] ${comment}\n`;
  fs.appendFileSync('comments.txt', entry);

  res.send(comment); // still simulate XSS
});

app.get('/reset-password', (req, res) => {
  res.send(`
    <h2>Reset Password</h2>
    <form action="/reset-password" method="POST">
      <input type="email" name="email" placeholder="Enter your email" required />
      <button type="submit">Reset</button>
    </form>
  `);
});

app.post('/reset-password', (req, res) => {
  const { email } = req.body;

  console.log(`📧 Reset link sent to ${email}`);
  res.send(`A reset link has been sent to ${email}. (simulated)`);
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
