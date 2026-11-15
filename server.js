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

    // Table for Likes on messages/posts
    db.run(`CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER,
        username TEXT,
        UNIQUE(message_id, username)
    )`);

    // Table for Comments on messages/posts
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER,
        username TEXT,
        comment_text TEXT,
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

app.post('/register', async (req, res) => {
    const { username, password, phone } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Please enter email and password' });
    if (!verifyEmailDomain(username)) return res.status(400).json({ error: 'Invalid email domain!' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters!' });

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

app.post('/admin/delete-user', (req, res) => {
    const { adminUser, targetUser } = req.body;
    db.get(`SELECT role FROM users WHERE username = ?`, [adminUser], (err, row) => {
        if (!row || row.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized access! Admin only.' });
        }
        db.run(`DELETE FROM users WHERE username = ?`, [targetUser], () => {
            db.run(`DELETE FROM messages WHERE sender = ? OR receiver = ?`, [targetUser, targetUser]);
            db.run(`DELETE FROM likes WHERE username = ?`, [targetUser]);
            db.run(`DELETE FROM comments WHERE username = ?`, [targetUser]);
            res.json({ message: 'User deleted successfully by Admin' });
        });
    });
});

app.post('/delete-message', (req, res) => {
    const { username, messageId } = req.body;
    
    db.get(`SELECT sender FROM messages WHERE id = ?`, [messageId], (err, msgRow) => {
        if (!msgRow) return res.status(404).json({ error: 'Message not found' });

        db.get(`SELECT role FROM users WHERE username = ?`, [username], (err, userRow) => {
            const isAdmin = userRow && userRow.role === 'admin';
            const isOwner = msgRow.sender === username;

            if (isAdmin || isOwner) {
                db.run(`DELETE FROM messages WHERE id = ?`, [messageId], () => {
                    db.run(`DELETE FROM likes WHERE message_id = ?`, [messageId]);
                    db.run(`DELETE FROM comments WHERE message_id = ?`, [messageId]);
                    res.json({ message: 'Message deleted successfully' });
                });
            } else {
                res.status(403).json({ error: 'Unauthorized to delete this message' });
            }
        });
    });
});

// Toggle Like on a Message/Post
app.post('/messages/like', (req, res) => {
    const { messageId, username } = req.body;
    if (!messageId || !username) return res.status(400).json({ error: 'Missing data' });

    db.get(`SELECT id FROM likes WHERE message_id = ? AND username = ?`, [messageId, username], (err, row) => {
        if (row) {
            db.run(`DELETE FROM likes WHERE id = ?`, [row.id], () => {
                res.json({ liked: false });
            });
        } else {
            db.run(`INSERT INTO likes (message_id, username) VALUES (?, ?)`, [messageId, username], () => {
                res.json({ liked: true });
            });
        }
    });
});

// Add Comment to a Message/Post
app.post('/messages/comment', (req, res) => {
    const { messageId, username, commentText } = req.body;
    if (!messageId || !username || !commentText) return res.status(400).json({ error: 'Missing data' });

    db.run(`INSERT INTO comments (message_id, username, comment_text) VALUES (?, ?, ?)`, 
        [messageId, username, commentText], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID });
    });
});

// Delete Comment (Owner or Admin)
app.post('/messages/delete-comment', (req, res) => {
    const { username, commentId } = req.body;
    db.get(`SELECT username FROM comments WHERE id = ?`, [commentId], (err, commentRow) => {
        if (!commentRow) return res.status(404).json({ error: 'Comment not found' });

        db.get(`SELECT role FROM users WHERE username = ?`, [username], (err, userRow) => {
            const isAdmin = userRow && userRow.role === 'admin';
            const isOwner = commentRow.username === username;

            if (isAdmin || isOwner) {
                db.run(`DELETE FROM comments WHERE id = ?`, [commentId], () => {
                    res.json({ message: 'Comment deleted' });
                });
            } else {
                res.status(403).json({ error: 'Unauthorized' });
            }
        });
    });
});

app.post('/delete-account', (req, res) => {
    const { username } = req.body;
    db.run(`DELETE FROM users WHERE username = ?`, [username], () => {
        db.run(`DELETE FROM messages WHERE sender = ? OR receiver = ?`, [username, username]);
        db.run(`DELETE FROM likes WHERE username = ?`, [username]);
        db.run(`DELETE FROM comments WHERE username = ?`, [username]);
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

// Get Messages along with their Likes and Comments
app.get('/messages', (req, res) => {
    const { user1, user2 } = req.query;
    let query, params;

    if (user2 === 'PUBLIC_ROOM') {
        query = `SELECT * FROM messages WHERE receiver = 'PUBLIC_ROOM' ORDER BY timestamp ASC`;
        params = [];
    } else {
        query = `SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY timestamp ASC`;
        params = [user1, user2, user2, user1];
    }

    db.all(query, params, (err, messages) => {
        if (err) return res.status(500).json({ error: err.message });
        if (messages.length === 0) return res.json([]);

        db.all(`SELECT * FROM likes`, [], (err, likes) => {
            db.all(`SELECT * FROM comments ORDER BY timestamp ASC`, [], (err, comments) => {
                const enriched = messages.map(msg => {
                    const msgLikes = (likes || []).filter(l => l.message_id === msg.id).map(l => l.username);
                    const msgComments = (comments || []).filter(c => c.message_id === msg.id);
                    return {
                        ...msg,
                        likes: msgLikes,
                        comments: msgComments
                    };
                });
                res.json(enriched);
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Mak Chat Server started on port ${PORT}`);
});