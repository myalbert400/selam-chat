const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// --- የ AfroMessage መረጃዎችዎ ---
const AFROMESSAGE_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJpZGVudGlmaWVyIjoieG5MdjE1WDFsVUNid2YzSnI1emRIQUxWbkcwcWVkWXIiLCJleHAiOjE5NTI3MDU5NTgsImlhdCI6MTc5NDkzOTU1OCwianRpIjoiYWE4MDRkNGItNjFjMi00NGU3LTg5YjItZDVjYjM5Njg3OTE5In0.1XJzO7ueM-2rsS4tlb0t896kPq34mQNLg4azDTvkqFI';
const AFROMESSAGE_SENDER_ID = 'e80ad9d8-adf3-463f-80f4-7c4b39f7f164';

const db = new sqlite3.Database('./mak_chat.db', (err) => {
    if (err) console.error(err.message);
    console.log('Mak Chat Database connected successfully!');
});

const otpStore = {}; 

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        phone TEXT,
        profile_pic TEXT,
        role TEXT DEFAULT 'user',
        is_verified INTEGER DEFAULT 0
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

    db.run(`CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER,
        username TEXT,
        UNIQUE(message_id, username)
    )`);

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

// 1. REGISTER ENDPOINT (በተስተካከለ የ AfroMessage POST ጥያቄ)
app.post('/register', async (req, res) => {
    const { username, password, phone } = req.body;
    if (!username || !password || !phone) return res.status(400).json({ error: 'እባክዎ ኢሜይል፣ ፓስወርድ እና ስልክ ቁጥር ያስገቡ!' });
    if (!verifyEmailDomain(username)) return res.status(400).json({ error: 'Invalid email domain!' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters!' });

    db.get(`SELECT * FROM users WHERE username = ?`, [username.toLowerCase()], async (err, existingUser) => {
        if (existingUser) return res.status(400).json({ error: 'ይህ ኢሜይል ቀደም ሲል ተመዝግቧል!' });

        db.get(`SELECT * FROM users WHERE phone = ?`, [phone], async (err, existingPhoneUser) => {
            if (existingPhoneUser) return res.status(400).json({ error: 'ይህ ስልክ ቁጥር አስቀድሞ በሌላ አካውንት ተመዝግቧል!' });

            db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
                const role = (row && row.count === 0) ? 'admin' : 'user';
                const hashedPassword = await bcrypt.hash(password, 10);
                
                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
                otpStore[username.toLowerCase()] = verificationCode;

                try {
                    // አፍሮሜሴጅን በትክክለኛው የ POST ዘዴ መጥራት
                    await axios.post('https://api.afromessage.com/api/send', {
                        from: AFROMESSAGE_SENDER_ID,
                        to: phone,
                        message: `የMak Chat ማረጋገጫ ኮድዎ (OTP): ${verificationCode}`
                    }, {
                        headers: {
                            'Authorization': `Bearer ${AFROMESSAGE_TOKEN}`,
                            'Content-Type': 'application/json'
                        }
                    });

                    db.run(`INSERT INTO users (username, password, phone, profile_pic, role, is_verified) VALUES (?, ?, ?, ?, ?, 0)`, 
                        [username.toLowerCase(), hashedPassword, phone, '', role], function(err) {
                        if (err) return res.status(400).json({ error: 'Registration failed!' });
                        res.json({ message: `የማረጋገጫ ኮድ በኤስኤምኤስ ወደ ስልክ ቁጥርዎ (${phone}) ተልኳል።` });
                    });

                } catch (smsError) {
                    console.error('AfroMessage Error:', smsError.response ? smsError.response.data : smsError.message);
                    res.status(500).json({ error: 'ኤስኤምኤስ መላክ አልተቻለም። እባክዎ ትክክለኛ ስልክ ቁጥር ያስገቡ!' });
                }
            });
        });
    });
});

// 2. VERIFY OTP ENDPOINT
app.post('/verify-otp', (req, res) => {
    const { username, otp } = req.body;
    if (!username || !otp) return res.status(400).json({ error: 'Incomplete data' });

    const cleanUsername = username.toLowerCase();
    if (otpStore[cleanUsername] && otpStore[cleanUsername] === otp) {
        db.run(`UPDATE users SET is_verified = 1 WHERE username = ?`, [cleanUsername], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            delete otpStore[cleanUsername];
            res.json({ message: 'አካውንቱ በተሳካ ሁኔታ አፕሩቭ ሆኗል!' });
        });
    } else {
        res.status(400).json({ error: 'ያስገቡት ኮድ ትክክል አይደለም!' });
    }
});

// 3. LOGIN ENDPOINT
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username.toLowerCase()], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Incorrect email or password' });
        
        if (user.is_verified === 0) {
            return res.status(403).json({ error: 'እባክዎ መጀመሪያ ስልክ ቁጥርዎን በኮድ ያረጋግጡ (Account not verified via SMS)!' });
        }

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

// 4. UPDATE PROFILE
app.post('/update-profile', async (req, res) => {
    const { username, profile_pic, newPassword } = req.body;
    if (!username) return res.status(400).json({ error: 'Incomplete data' });

    const cleanUsername = username.toLowerCase();

    if (newPassword && newPassword.length > 0) {
        bcrypt.hash(newPassword, 10).then(hashedPassword => {
            const sql = `UPDATE users SET profile_pic = ?, password = ? WHERE username = ?`;
            db.run(sql, [profile_pic || '', hashedPassword, cleanUsername], function(err) {
                if (err) return res.status(500).json({ error: 'Failed to update profile' });
                res.json({ message: 'Profile updated successfully!', profile_pic });
            });
        });
    } else {
        const sql = `UPDATE users SET profile_pic = ? WHERE username = ?`;
        db.run(sql, [profile_pic || '', cleanUsername], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to update profile' });
            res.json({ message: 'Profile updated successfully!', profile_pic });
        });
    }
});

// 5. MESSAGES & OTHER ENDPOINTS
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
        res.json(messages);
    });
});

app.listen(PORT, () => {
    console.log(`Mak Chat Server started on port ${PORT}`);
});