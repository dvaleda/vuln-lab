const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const dbFile = path.join(dataDir, 'data.db');
if (fs.existsSync(dbFile)) {
  console.log('Using existing DB at', dbFile);
} else {
  console.log('Creating new DB at', dbFile);
}

const db = new sqlite3.Database(dbFile);

db.serialize(() => {
  // messages
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL
  );`);

  // users
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_plain TEXT,
    password_hash TEXT
  );`);

  // logs
  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    kind TEXT,
    details TEXT
  );`);

  // seed messages 
  db.run('DELETE FROM messages;');
  const stm = db.prepare('INSERT INTO messages (content) VALUES (?)');
  ['Hello world', 'Secret message 1', 'admin message', 'Confidential note'].forEach(m => stm.run(m));
  stm.finalize();

  // seed user admin (plain + bcrypt hash)
  db.run('DELETE FROM users;');
  const plain = 'admin123';
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(plain, salt);
  db.run('INSERT OR REPLACE INTO users (username, password_plain, password_hash) VALUES (?, ?, ?)', ['admin', plain, hash]);

  console.log('DB initialized and seeded (messages + admin user).');
});

db.close();