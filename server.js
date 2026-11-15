const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 1. ዳታቤዝ መፍጠር
const db = new sqlite3.Database('./selam_chat.db', (err) => {
    if (err) console.error(err.message);
    console.log('ከዳታቤዝ ጋር በተሳካ ሁኔታ ተገናኝቷል!');
});

// 2. የተጠቃሚዎች እና የግል መልዕክቶች ሰንጠረዥ መፍጠር
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    // ለግል ቻት (Private Chat) እንዲሆን sender እና receiver ተጨምረዋል
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// 3. አዲስ ተጠቃሚ መመዝገቢያ (Register API)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'እባክዎ ኢሜል እና ፓስዎርድ ያስገቡ' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(username)) {
        return res.status(400).json({ error: 'እባክዎ ትክክለኛ የኢሜል አድራሻ ያስገቡ!' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'ፓስዎርዱ ቢያንስ 6 ፊደላት/ቁጥሮች መሆን አለበት!' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(sql, [username.toLowerCase(), hashedPassword], function(err) {
        if (err) {
            return res.status(400).json({ error: 'ይህ ኢሜል ቀድሞ ተመዝግቧል!' });
        }
        res.json({ message: 'ምዝገባው ተሳክቷል! አሁን መግባት ይችላሉ።' });
    });
});

// 4. መግቢያ (Login API)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = `SELECT * FROM users WHERE username = ?`;

    db.get(sql, [username.toLowerCase()], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'ኢሜል ወይም ፓስዎርድ ተሳስቷል' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'ኢሜል ወይም ፓስዎርድ ተሳስቷል' });
        }

        res.json({ message: 'እንኳን ደህና መጡ!', username: user.username });
    });
});

// 5. የተመዘገቡ ተጠቃሚዎችን ዝርዝር ማምጫ (Users List API)
app.get('/users', (req, res) => {
    const currentUser = req.query.currentUser;
    db.all(`SELECT username FROM users WHERE username != ? ORDER BY username ASC`, [currentUser], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 6. የግል መልዕክት መላኪያ (Send Private Message API)
app.post('/messages', (req, res) => {
    const { sender, receiver, message } = req.body;
    if (!sender || !receiver || !message) {
        return res.status(400).json({ error: 'ያልተሟላ መረጃ' });
    }
    db.run(`INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)`, [sender, receiver, message], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, sender, receiver, message });
    });
});

// 7. በሁለት ሰዎች መካከል ያሉ መልዕክቶችን ብቻ ማንበቢያ (Get Private Messages API)
app.get('/messages', (req, res) => {
    const { user1, user2 } = req.query;
    const sql = `
        SELECT * FROM messages 
        WHERE (sender = ? AND receiver = ?) 
           OR (sender = ? AND receiver = ?) 
        ORDER BY timestamp ASC
    `;
    db.all(sql, [user1, user2, user2, user1], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// ሰርቨሩን ማስጀመር
app.listen(PORT, () => {
    console.log(`ሰላም ቻት ሰርቨር በዚህ አድራሻ ተከፍቷል: http://localhost:${PORT}`);
});