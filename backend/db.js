const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'database.sqlite');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        
        // Initialize the logs table
        db.run(`
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                message TEXT,
                threat_type TEXT,
                severity TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                hour_of_day INTEGER DEFAULT (CAST(strftime('%H', CURRENT_TIMESTAMP) AS INTEGER)),
                region TEXT DEFAULT 'GLOBAL',
                language TEXT DEFAULT 'EN'
            )
        `, (err) => {
            if (err) {
                console.error('Error creating logs table:', err.message);
            } else {
                console.log('Logs table ready.');
            }
        });
    }
});

module.exports = db;
