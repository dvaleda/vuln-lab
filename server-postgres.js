const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const { Client } = require('pg');
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

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

    try {
        let sql, rows;

        if (mode === 'vuln') {
        sql = `SELECT id, content FROM messages WHERE content = '${msg}'`;
        pushLog('search_attempt_vuln', { sql, msg });
        rows = await client.query(sql);
        return res.json({ ok: true, mode, sql, rows: rows.rows });
        } else {
        // safe parameterized query
        sql = 'SELECT id, content FROM messages WHERE content = $1';
        pushLog('search_attempt_safe', { sql, msg });
        rows = await client.query(sql, [msg]);
        return res.json({ ok: true, mode, sql, rows: rows.rows });
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

    try {
        const userRes = await client.query('SELECT * FROM users WHERE username = $1', [username]);
        if (userRes.rows.length === 0) {
        return res.status(401).json({ ok: false, message: 'Invalid credentials' });
        }
        const user = userRes.rows[0];

        if (mode === 'vuln') {
        if (password === user.password_plain) {
            res.cookie('SESSIONID', 'vuln-session-1234', { httpOnly: false });
            pushLog('login_success_vuln', { username });
            return res.json({ ok: true, mode, message: `VULN LOGIN OK for ${username}` });
        } else {
            return res.status(401).json({ ok: false, message: 'Invalid credentials (vuln)' });
        }
        } else {
            const storedHash = user.password_hash || '';
            const match = await bcrypt.compare(password, storedHash);
            if (match) {
                // set HttpOnly cookie
                res.cookie('SESSIONID', `safe-${user.id}-${Date.now()}`, { httpOnly: true, sameSite: 'Lax', secure: false, path: '/' });
                pushLog('login_success_safe', { username });
                return res.json({ ok: true, mode: 'safe', message: `SAFE LOGIN OK for ${username}` });
            } else {
                return res.status(401).json({ ok: false, message: 'Wrong password' });
            }
        }
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).json({ ok: false, message: 'Server error' });
    }
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));