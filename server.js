const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./mak_chat.db', (err) => {
    if (err) console.error(err.message);
    console.log('Mak Chat Database connected successfully!');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        phone TEXT,
        profile_pic TEXT,
        role TEXT DEFAULT 'user'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        message TEXT,
        media_type TEXT DEFAULT 'text',
        media_data TEXT,
        file_name TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const allowedDomains = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 
    'icloud.com', 'live.com', 'aol.com', 'protonmail.com', 
    'yandex.com', 'zoho.com', 'edu.et', 'gov.et'
];

function verifyEmailDomain(email) {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/;
    const match = email.toLowerCase().match(emailRegex);
    if (!match) return false;
    return allowedDomains.includes(match[1]) || match[1].endsWith('.edu') || match[1].endsWith('.gov');
}

// Register (첫 번째로 가입하는 사람은 자동으로 Admin ሊሆን ይችላል ወይም እንደ ፍላጎት)
app.post('/register', async (req, res) => {
    const { username, password, phone } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Please enter email and password' });
    if (!verifyEmailDomain(username)) return res.status(400).json({ error: 'Invalid email domain!' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters!' });

    // Check if user table is empty, if so make the first user an Admin
    db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
        const role = (row && row.count === 0) ? 'admin' : 'user';
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(`INSERT INTO users (username, password, phone, profile_pic, role) VALUES (?, ?, ?, ?, ?)`, 
            [username.toLowerCase(), hashedPassword, phone || '', '', role], function(err) {
            if (err) return res.status(400).json({ error: 'This email is already registered!' });
            res.json({ message: 'Registration successful!' });
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username.toLowerCase()], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Incorrect email or password' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Incorrect email or password' });
        res.json({ 
            message: 'Welcome!', 
            username: user.username, 
            phone: user.phone, 
            profile_pic: user.profile_pic,
            role: user.role 
        });
    });
});

app.post('/update-profile', async (req, res) => {
    const { username, phone, profile_pic, newPassword } = req.body;
    let sql, params;
    if (newPassword) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        sql = `UPDATE users SET phone = ?, profile_pic = ?, password = ? WHERE username = ?`;
        params = [phone, profile_pic, hashedPassword, username];
    } else {
        sql = `UPDATE users SET phone = ?, profile_pic = ? WHERE username = ?`;
        params = [phone, profile_pic, username];
    }
    db.run(sql, params, function(err) {
        if (err) return res.status(500).json({ error: 'Failed to update profile' });
        res.json({ message: 'Profile updated successfully!', phone, profile_pic });
    });
});

// Admin API: Delete any user
app.post('/admin/delete-user', (req, res) => {
    const { adminUser, targetUser } = req.body;
    db.get(`SELECT role FROM users WHERE username = ?`, [adminUser], (err, row) => {
        if (!row || row.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized access! Admin only.' });
        }
        db.run(`DELETE FROM users WHERE username = ?`, [targetUser], () => {
            db.run(`DELETE FROM messages WHERE sender = ? OR receiver = ?`, [targetUser, targetUser]);
            res.json({ message: 'User deleted successfully by Admin' });
        });
    });
});

app.post('/delete-account', (req, res) => {
    const { username } = req.body;
    db.run(`DELETE FROM users WHERE username = ?`, [username], () => {
        db.run(`DELETE FROM messages WHERE sender = ? OR receiver = ?`, [username, username]);
        res.json({ message: 'Account deleted' });
    });
});

app.get('/users', (req, res) => {
    const currentUser = req.query.currentUser;
    db.all(`SELECT username, phone, profile_pic, role FROM users WHERE username != ? ORDER BY username ASC`, [currentUser], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/messages', (req, res) => {
    const { sender, receiver, message, media_type, media_data, file_name } = req.body;
    if (!sender || !receiver || (!message && !media_data)) return res.status(400).json({ error: 'Incomplete data' });
    
    db.run(
        `INSERT INTO messages (sender, receiver, message, media_type, media_data, file_name) VALUES (?, ?, ?, ?, ?, ?)`,
        [sender, receiver, message || '', media_type || 'text', media_data || null, file_name || null],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        }
    );
});

app.get('/messages', (req, res) => {
    const { user1, user2 } = req.query;
    if (user2 === 'PUBLIC_ROOM') {
        db.all(`SELECT * FROM messages WHERE receiver = 'PUBLIC_ROOM' ORDER BY timestamp ASC`, [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    } else {
        db.all(`SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY timestamp ASC`, 
            [user1, user2, user2, user1], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    }
});

app.listen(PORT, () => {
    console.log(`Mak Chat Server started on port ${PORT}`);
});