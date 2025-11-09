const { Client } = require('pg');
const bcrypt = require('bcryptjs');

async function init() {
    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false } // render
    });

    await client.connect();
    console.log('Connected to Postgres.');

    // drop old tables
    await client.query(`DROP TABLE IF EXISTS messages;`);
    await client.query(`DROP TABLE IF EXISTS users;`);

    // create tables
    await client.query(`
        CREATE TABLE messages (
        id SERIAL PRIMARY KEY,
        content TEXT
        );
    `);

    await client.query(`
        CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_plain TEXT
        password_hash TEXT
        );
    `);

    // seed data
    const messages = [
        'Pozdrav',
        'Privatna poruka 1',
        'Ovo je poruka admina',
        'Ovo je tajna poruka'
    ];
    for (const msg of messages) {
        await client.query('INSERT INTO messages (content) VALUES ($1)', [msg]);
    }

    // Seed user: admin / admin123
    const plainPassword = 'admin123';
    const hash = await bcrypt.hash(plainPassword, 10); // async hash
    await client.query(
        'INSERT INTO users (username, password_plain, password_hash) VALUES ($1, $2, $3)',
        ['admin', plainPassword, hash]
    );

    console.log('Postgres DB initialized and seeded successfully.');
    await client.end();
}

init().catch(err => {
    console.error('Error initializing DB:', err);
    process.exit(1);
});