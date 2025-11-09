const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));

// open sqlite DB
const dbFile = path.join(__dirname, 'data', 'data.db');
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Failed to open DB:', err);
    process.exit(1);
  }
  console.log('Opened DB:', dbFile);
});

// in-memory attack log 
let attackLog = [];

// append log to memory + DB
function pushLog(entry) {
  const time = new Date().toISOString();
  attackLog.unshift({ time, ...entry }); // newest first
  if (attackLog.length > 200) attackLog.length = 200;
  // persist to DB
  const sql = `INSERT INTO logs (time, kind, details) VALUES (?, ?, ?)`;
  db.run(sql, [time, entry.kind || '', JSON.stringify(entry.details || {})], (err) => {
    if (err) console.warn('Failed to write log to DB', err);
  });
}

app.get('/health', (req, res) => res.json({ ok: true }));

// read recent logs
app.get('/log', (req, res) => {
  res.json({ ok: true, logs: attackLog.slice(0, 100) });
});

// SQL injection
app.post('/search/query', (req, res) => {
  const msg = req.body.msg || '';
  const mode = String(req.body.mode || 'vuln'); // vuln or safe
  pushLog({ kind: 'search_attempt', details: { msg: String(msg).slice(0,200), mode } });

  if (mode === 'vuln') {
    const sql = `SELECT id, content FROM messages WHERE content = '${msg}'`;
    db.all(sql, (err, rows) => {
      if (err) {
        console.error('SQL error (vuln):', err);
        return res.status(500).json({ ok: false, error: 'SQL error' });
      }
      return res.json({ ok: true, mode: 'vuln', sql, rows });
    });
  } else {
    // safe parameterized query
    const sql = `SELECT id, content FROM messages WHERE content = ?`;
    db.all(sql, [msg], (err, rows) => {
      if (err) {
        console.error('SQL error (safe):', err);
        return res.status(500).json({ ok: false, error: 'SQL error' });
      }
      return res.json({ ok: true, mode: 'safe', sql: 'SELECT ... WHERE content = ?', rows });
    });
  }
});

// AUTH 
app.post('/auth/login', (req, res) => {
  const username = req.body.username || '';
  const password = req.body.password || '';
  const mode = String(req.body.mode || 'vuln'); 
  pushLog({ kind: 'login_attempt', details: { username: String(username).slice(0,100), mode } });

  // fetch user row
  db.get('SELECT id, username, password_plain, password_hash FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error('DB error', err);
      return res.status(500).json({ ok: false, error: 'DB error' });
    }
    if (!user) {
      return res.status(401).json({ ok: false, message: 'Invalid credentials' });
    }

    if (mode === 'vuln') {
      // plain-text compare, cookie NOT HttpOnly 
      if (password === user.password_plain) {
        // create simple session id 
        const sessionId = `vuln-${user.id}-${Date.now()}`;
        res.cookie('SESSIONID', sessionId, { httpOnly: false, sameSite: 'Lax', path: '/' }); 
        pushLog({ kind: 'login_success_vuln', details: { username } });
        return res.json({ ok: true, mode: 'vuln', message: `VULN LOGIN OK. Dobrodošao ${username}`, sessionId });
      } else {
        return res.status(401).json({ ok: false, message: 'Invalid credentials (vuln)' });
      }
    } else {
      // check bcrypt hash, set HttpOnly cookie
      try {
        const match = await bcrypt.compare(password, user.password_hash || '');
        if (match) {
          const sessionId = `safe-${user.id}-${Date.now()}-${Math.random().toString(36).slice(2,8)}`;
          // set cookie
          res.cookie('SESSIONID', sessionId, { httpOnly: true, sameSite: 'Lax', secure: false, path: '/' });
          pushLog({ kind: 'login_success_safe', details: { username } });
          return res.json({ ok: true, mode: 'safe', message: `SAFE LOGIN OK. Dobrodošao ${username}` });
        } else {
          return res.status(401).json({ ok: false, message: 'Invalid credentials' });
        }
      } catch (e) {
        console.error('bcrypt error', e);
        return res.status(500).json({ ok: false, error: 'Server error' });
      }
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});