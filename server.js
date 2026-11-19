const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configure Email Transporter (Nodemailer) with your App Password
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'myalbert400@gmail.com',       
        pass: 'ohlm botv avpr tmf'          
    }
});

const db = new sqlite3.Database('./mak_chat.db', (err) => {
    if (err) console.error(err.message);
    console.log('Mak Chat Database connected successfully!');
});

const otpStore = {}; 
const resetOtpStore = {}; 

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

// 1. REGISTER ENDPOINT (Sends OTP via email)
app.post('/register', async (req, res) => {
    const { username, password, phone } = req.body;
    if (!username || !password || !phone) return res.status(400).json({ error: 'Please enter email, password, and phone number!' });
    if (!verifyEmailDomain(username)) return res.status(400).json({ error: 'Invalid email domain!' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters!' });

    db.get(`SELECT * FROM users WHERE username = ?`, [username.toLowerCase()], async (err, existingUser) => {
        if (existingUser) return res.status(400).json({ error: 'This email is already registered!' });

        db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
            const role = (row && row.count === 0) ? 'admin' : 'user';
            const hashedPassword = await bcrypt.hash(password, 10);
            
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            otpStore[username.toLowerCase()] = verificationCode;

            try {
                await transporter.sendMail({
                    from: 'myalbert400@gmail.com',
                    to: username,
                    subject: 'Mak Chat - Verification Code (OTP)',
                    text: `Your Mak Chat verification code (OTP) is: ${verificationCode}`
                });

                db.run(`INSERT INTO users (username, password, phone, profile_pic, role, is_verified) VALUES (?, ?, ?, ?, ?, 0)`, 
                    [username.toLowerCase(), hashedPassword, phone, '', role], function(err) {
                    if (err) return res.status(400).json({ error: 'Registration failed!' });
                    res.json({ message: `Verification code sent to email (${username}).` });
                });

            } catch (emailError) {
                console.error('Email Error:', emailError);
                res.status(500).json({ error: 'Failed to send email. Please enter a valid email address!' });
            }
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
            res.json({ message: 'Account approved successfully!' });
        });
    } else {
        res.status(400).json({ error: 'The verification code you entered is incorrect!' });
    }
});

// 3. LOGIN ENDPOINT
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username.toLowerCase()], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Incorrect email or password' });
        
        if (user.is_verified === 0) {
            return res.status(403).json({ error: 'Please verify your email with the OTP code first (Account not verified)!' });
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

// 4. FORGOT PASSWORD - REQUEST OTP
app.post('/forgot-password', (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Please enter your email!' });

    db.get(`SELECT * FROM users WHERE username = ?`, [username.toLowerCase()], async (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Email not found in our system!' });

        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        resetOtpStore[username.toLowerCase()] = resetCode;

        try {
            await transporter.sendMail({
                from: 'myalbert400@gmail.com',
                to: username,
                subject: 'Mak Chat - Password Reset Code',
                text: `Your password reset verification code is: ${resetCode}`
            });
            res.json({ message: 'Password reset code sent to your email.' });
        } catch (error) {
            console.error('Email Error:', error);
            res.status(500).json({ error: 'Failed to send reset email.' });
        }
    });
});

// 5. FORGOT PASSWORD - RESET PASSWORD
app.post('/reset-password', async (req, res) => {
    const { username, otp, newPassword } = req.body;
    if (!username || !otp || !newPassword) return res.status(400).json({ error: 'Incomplete data!' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters!' });

    const cleanUsername = username.toLowerCase();
    if (resetOtpStore[cleanUsername] && resetOtpStore[cleanUsername] === otp) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run(`UPDATE users SET password = ? WHERE username = ?`, [hashedPassword, cleanUsername], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            delete resetOtpStore[cleanUsername];
            res.json({ message: 'Password reset successfully! You can now login.' });
        });
    } else {
        res.status(400).json({ error: 'Invalid verification code!' });
    }
});

// 6. UPDATE PROFILE ENDPOINT
app.post('/update-profile', async (req, res) => {
    const { username, newPassword } = req.body;
    if (!username) return res.status(400).json({ error: 'Incomplete data' });

    if (newPassword && newPassword.length > 0) {
        if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters!' });
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run(`UPDATE users SET password = ? WHERE username = ?`, [hashedPassword, username.toLowerCase()], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ message: 'Profile updated successfully!' });
        });
    } else {
        res.json({ message: 'No changes made.' });
    }
});

// 7. MESSAGES ENDPOINTS
app.post('/messages', (req, res) => {
    const { sender, receiver, message } = req.body;
    if (!sender || !receiver || !message) return res.status(400).json({ error: 'Incomplete data' });
    
    db.run(
        `INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)`,
        [sender, receiver, message],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        }
    );
});

app.get('/messages', (req, res) => {
    db.all(`SELECT * FROM messages WHERE receiver = 'PUBLIC_ROOM' ORDER BY timestamp ASC`, [], (err, messages) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(messages);
    });
});

app.listen(PORT, () => {
    console.log(`Mak Chat Server started on port ${PORT}`);
});