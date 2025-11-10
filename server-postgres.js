const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const { Client } = require('pg');
const bcrypt = require('bcryptjs');
const failedAttempts = {}; // username -> { count, lockedUntil }
const LOCK_THRESHOLD = 3;
const LOCK_DURATION_MS = 5 * 60 * 1000; // 5 min

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

let lastLog = null;

function pushLog(kind, details) {
  lastLog = {
    time: new Date().toISOString(),
    kind,
    details
  };
}

// PostgreSQL client
const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});
client.connect().then(() => console.log('Connected to Postgres.')).catch(console.error);

// SQL injection
app.post('/search/query', async (req, res) => {
    const msg = String(req.body.msg || '');
    const mode = String(req.body.mode || 'vuln');
    const pin = String(req.body.pin || '');

    try {
        let sql, rows;
        if (mode === 'vuln') {
        sql = `SELECT id, content FROM messages WHERE content = '${msg}'`;
        pushLog('search_attempt_vuln', { sql, msg });
        rows = await client.query(sql);
        return res.json({ ok: true, mode, sql, rows: rows.rows });
        } else if (pin == "1234") {
            // safe parameterized query
            sql = 'SELECT id, content FROM messages WHERE content = $1';
            pushLog('search_attempt_safe', { sql, msg });
            rows = await client.query(sql, [msg]);
            const sanitized = (rows.rows || []).map(r => {
            // basic sanitization
            const safeContent = String(r.content || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            // mask words
            const masked = safeContent.replace(/(admin|tajna|privatna)/ig, '****');
            return { id: r.id, content: masked };
        });
        return res.json({ ok: true, mode: 'safe', rows: sanitized });
        }
    } catch (err) {
        console.error('SQL error:', err);
        return res.status(500).json({ ok: false, error: 'SQL error' });
    }
});

// Auth
app.post('/auth/login', async (req, res) => {

    const username = String(req.body.username || '');
    const password = String(req.body.password || '');
    const mode = String(req.body.mode || 'vuln');

    pushLog('login_attempt', { username, mode });

    const now = Date.now();

    try {
        const userRes = await client.query('SELECT * FROM users WHERE username = $1', [username]);
        if (userRes.rows.length === 0) {
            if (mode == 'vuln') {
                return res.status(401).json({ ok: false, message: 'User not found' });
            } else {
                return res.status(401).json({ ok: false, message: 'Invalid credentials' });
            }
        }
        const user = userRes.rows[0];
        const info = failedAttempts[username] || { count: 0, lockedUntil: 0 };

        if (mode == 'vuln') {
            if (password === user.password_plain) {
                res.cookie('SESSIONID', `vuln-${user.id}234`, { httpOnly: false });
                pushLog('login_success_vuln', { username });
                if (failedAttempts[username]) delete failedAttempts[username];
                return res.json({ ok: true, mode, message: `VULN LOGIN OK for ${username}` });
            } else {
                return res.status(401).json({ ok: false, message: 'Wrong password' });
            }
        } else {
            const storedHash = user.password_hash || '';
            const match = await bcrypt.compare(password, storedHash);
            if (match) {
                if (failedAttempts[username]) delete failedAttempts[username];
                // set HttpOnly cookie
                res.cookie('SESSIONID', `safe-${user.id}-${Date.now()}`, { httpOnly: true, sameSite: 'Lax', secure: false, path: '/' });
                pushLog('login_success_safe', { username });
                return res.json({ ok: true, mode: 'safe', message: `SAFE LOGIN OK for ${username}` });
            } else {
                info.count = (info.count || 0) + 1;
                if (info.count >= LOCK_THRESHOLD) {
                    info.lockedUntil = now + LOCK_DURATION_MS;
                    info.count = 0;
                }
                failedAttempts[username] = info;
                return res.status(401).json({ ok: false, message: 'Invalid credentials' });
            }
        }
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).json({ ok: false, message: 'Server error' });
    }
});

app.get('/log', (req, res) => {
  if (!lastLog) return res.json({ ok: true, log: null, message: 'Nema zapisa' });
  return res.json({ ok: true, log: lastLog });
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));