const Database = require('better-sqlite3');
const db = new Database('grader.db');

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        unique_id TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        unique_id TEXT,
        lab_id TEXT,
        score INTEGER,
        max_score INTEGER,
        details TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        type TEXT DEFAULT 'lab',
        status TEXT DEFAULT 'completed',
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS active_locks (
        lock_key TEXT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

try { db.prepare('SELECT lab_id FROM submissions LIMIT 1').get(); } 
catch (e) { db.prepare('ALTER TABLE submissions ADD COLUMN lab_id TEXT').run(); }

try { db.prepare('SELECT type FROM submissions LIMIT 1').get(); } 
catch (e) { db.prepare("ALTER TABLE submissions ADD COLUMN type TEXT DEFAULT 'lab'").run(); }

try { db.prepare('SELECT status FROM submissions LIMIT 1').get(); } 
catch (e) { 
    console.log("Migrating DB: Adding 'status' column...");
    db.prepare("ALTER TABLE submissions ADD COLUMN status TEXT DEFAULT 'completed'").run(); 
}

db.acquireLock = function(key) {
    try {
        db.prepare("INSERT INTO active_locks (lock_key) VALUES (?)").run(key);
        return true;
    } catch (e) {
        return false;
    }
};

db.releaseLock = function(key) {
    try {
        db.prepare("DELETE FROM active_locks WHERE lock_key = ?").run(key);
    } catch (e) {}
};

module.exports = db;