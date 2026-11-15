const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

// መረጃዎችን ለመቀበል እና HTML ፋይሉን ለማሳየት
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 1. ዳታቤዝ መፍጠር (selam_chat.db የሚል ፋይል ኮምፒውተርህ ላይ ይፈጥራል)
const db = new sqlite3.Database('./selam_chat.db', (err) => {
    if (err) console.error(err.message);
    console.log('ከዳታቤዝ ጋር በተሳካ ሁኔታ ተገናኝቷል!');
});

// 2. የተጠቃሚዎችን (Users) እና የመልዕክቶችን (Messages) ሰንጠረዥ (Table) መፍጠር
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// 3. አዲስ ተጠቃሚ መመዝገቢያ (Register API)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'እባክዎ ዩዘርኔም እና ፓስዎርድ ያስገቡ' });
    }

    // ፓስዎርዱን ደህንነቱ በተጠበቀ መልኩ መቀየር (Hash)
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(sql, [username, hashedPassword], function(err) {
        if (err) {
            return res.status(400).json({ error: 'ይህ ዩዘርኔም ቀድሞ ተይዟል!' });
        }
        res.json({ message: 'ምዝገባው ተሳክቷል! አሁን መግባት ይችላሉ።' });
    });
});

// 4. መግቢያ (Login API)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = `SELECT * FROM users WHERE username = ?`;

    db.get(sql, [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'ዩዘርኔም ወይም ፓስዎርድ ተሳስቷል' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'ዩዘርኔም ወይም ፓስዎርድ ተሳስቷል' });
        }

        res.json({ message: 'እንኳን ደህና መጡ!', username: user.username });
    });
});

// 5. መልዕክት መላኪያ እና ማንበቢያ (Chat APIs)
app.post('/messages', (req, res) => {
    const { username, message } = req.body;
    db.run(`INSERT INTO messages (username, message) VALUES (?, ?)`, [username, message], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, username, message });
    });
});

app.get('/messages', (req, res) => {
    db.all(`SELECT * FROM messages ORDER BY timestamp ASC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// ሰርቨሩን ማስጀመር
app.listen(PORT, () => {
    console.log(`ሰላም ቻት ሰርቨር በዚህ አድራሻ ተከፍቷል: http://localhost:${PORT}`);
});