const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// በ Hosting Environment Variables ውስጥ RESEND_API_KEY ካለ እሱን ይጠቀማል፣ ከሌለ የእርስዎን API Key ይጠቀማል
const RESEND_API_KEY = process.env.RESEND_API_KEY || 'rnd_9yoEoKu1AuPlAnW4jmfgOPkbltKx';
const resend = new Resend(RESEND_API_KEY);

// የራስዎ የተረጋገጠ ዶሜይን ካለ በ FROM_EMAIL ያስገቡ (ለምሳሌ: 'Mak Chat <noreply@yourdomain.com>')
// ዶሜይን ገና ካላረጋገጡ 'onboarding@resend.dev' ይጠቀሙ
const FROM_EMAIL = process.env.FROM_EMAIL || 'onboarding@resend.dev';

const db = new sqlite3.Database('./mak_chat.db', (err) => {
    if (err) console.error('Database connection error:', err.message);
    else console.log('Mak Chat Database connected successfully!');
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

function isValidEmailFormat(email) {
    if (!email || typeof email !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
}

async function sendOtpEmail(toEmail, subject, code) {
    const { data, error } = await resend.emails.send({
        from: FROM_EMAIL,
        to: [toEmail],
        subject: subject,
        text: `Your Mak Chat verification code is: ${code}`
    });

    if (error) {
        throw new Error(error.message || 'Resend API error');
    }
    return data;
}

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// 1. REGISTER ENDPOINT
app.post('/register', (req, res) => {
    const username = (req.body.username || '').trim().toLowerCase();
    const phone = (req.body.phone || '').trim();
    const password = req.body.password || '';

    if (!username || !password || !phone) {
        return res.status(400).json({ error: 'Please enter email, password, and phone number!' });
    }
    if (!isValidEmailFormat(username)) {
        return res.status(400).json({ error: 'Please enter a valid email address!' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters!' });
    }

    db.get(`SELECT id FROM users WHERE username = ?`, [username], (err, existingUser) => {
        if (err) return res.status(500).json({ error: 'Database error!' });
        if (existingUser) return res.status(400).json({ error: 'This email is already registered!' });

        db.get(`SELECT COUNT(*) as count FROM users`, async (countErr, row) => {
            if (countErr) return res.status(500).json({ error: 'Database error!' });

            try {
                const role = (row && row.count === 0) ? 'admin' : 'user';
                const hashedPassword = await bcrypt.hash(password, 8);
                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

                await sendOtpEmail(
                    username,
                    'Mak Chat - Verification Code (OTP)',
                    verificationCode
                );

                otpStore[username] = {
                    code: verificationCode,
                    expiresAt: Date.now() + 10 * 60 * 1000
                };

                db.run(
                    `INSERT INTO users (username, password, phone, profile_pic, role, is_verified) VALUES (?, ?, ?, ?, ?, 0)`,
                    [username, hashedPassword, phone, '', role],
                    function (insertErr) {
                        if (insertErr) return res.status(400).json({ error: 'Registration failed!' });
                        return res.json({ message: `Verification code sent to email (${username}).` });
                    }
                );
            } catch (emailError) {
                console.error('Resend Error:', emailError.message);
                return res.status(500).json({ error: `Failed to send email: ${emailError.message}` });
            }
        });
    });
});

// 2. VERIFY OTP ENDPOINT
app.post('/verify-otp', (req, res) => {
    const cleanUsername = (req.body.username || '').trim().toLowerCase();
    const otp = (req.body.otp || '').trim();

    if (!cleanUsername || !otp) {
        return res.status(400).json({ error: 'Incomplete data' });
    }

    const record = otpStore[cleanUsername];
    if (record && Date.now() <= record.expiresAt && record.code === otp) {
        db.run(`UPDATE users SET is_verified = 1 WHERE username = ?`, [cleanUsername], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            delete otpStore[cleanUsername];
            return res.json({ message: 'Account approved successfully!' });
        });
    } else {
        return res.status(400).json({ error: 'The verification code you entered is incorrect or expired!' });
    }
});

// 3. LOGIN ENDPOINT
app.post('/login', (req, res) => {
    const cleanUsername = (req.body.username || '').trim().toLowerCase();
    const password = req.body.password || '';

    db.get(`SELECT * FROM users WHERE username = ?`, [cleanUsername], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Incorrect email or password' });

        if (user.is_verified === 0) {
            return res.status(403).json({ error: 'Please verify your email with the OTP code first (Account not verified)!' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Incorrect email or password' });

        return res.json({
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
    const cleanUsername = (req.body.username || '').trim().toLowerCase();
    if (!cleanUsername) return res.status(400).json({ error: 'Please enter your email!' });

    db.get(`SELECT id FROM users WHERE username = ?`, [cleanUsername], async (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Email not found in our system!' });

        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

        try {
            await sendOtpEmail(
                cleanUsername,
                'Mak Chat - Password Reset Code',
                resetCode
            );

            resetOtpStore[cleanUsername] = {
                code: resetCode,
                expiresAt: Date.now() + 10 * 60 * 1000
            };

            return res.json({ message: 'Password reset code sent to your email.' });
        } catch (error) {
            console.error('Resend Error:', error.message);
            return res.status(500).json({ error: `Failed to send reset email: ${error.message}` });
        }
    });
});

// 5. FORGOT PASSWORD - RESET PASSWORD
app.post('/reset-password', async (req, res) => {
    const cleanUsername = (req.body.username || '').trim().toLowerCase();
    const otp = (req.body.otp || '').trim();
    const newPassword = req.body.newPassword || '';

    if (!cleanUsername || !otp || !newPassword) return res.status(400).json({ error: 'Incomplete data!' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters!' });

    const record = resetOtpStore[cleanUsername];
    if (record && Date.now() <= record.expiresAt && record.code === otp) {
        const hashedPassword = await bcrypt.hash(newPassword, 8);
        db.run(`UPDATE users SET password = ? WHERE username = ?`, [hashedPassword, cleanUsername], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            delete resetOtpStore[cleanUsername];
            return res.json({ message: 'Password reset successfully! You can now login.' });
        });
    } else {
        return res.status(400).json({ error: 'Invalid or expired verification code!' });
    }
});

// 6. UPDATE PROFILE ENDPOINT
app.post('/update-profile', async (req, res) => {
    const cleanUsername = (req.body.username || '').trim().toLowerCase();
    const newPassword = req.body.newPassword || '';

    if (!cleanUsername) return res.status(400).json({ error: 'Incomplete data' });

    if (newPassword && newPassword.length > 0) {
        if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters!' });
        const hashedPassword = await bcrypt.hash(newPassword, 8);
        db.run(`UPDATE users SET password = ? WHERE username = ?`, [hashedPassword, cleanUsername], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            return res.json({ message: 'Profile updated successfully!' });
        });
    } else {
        return res.json({ message: 'No changes made.' });
    }
});

// 7. MESSAGES ENDPOINTS
app.post('/messages', (req, res) => {
    const sender = (req.body.sender || '').trim().toLowerCase();
    const receiver = (req.body.receiver || 'PUBLIC_ROOM').trim();
    const message = (req.body.message || '').trim();

    if (!sender || !receiver || !message) {
        return res.status(400).json({ error: 'Incomplete data' });
    }

    db.run(
        `INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)`,
        [sender, receiver, message],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            return res.json({ id: this.lastID });
        }
    );
});

app.get('/messages', (req, res) => {
    db.all(`SELECT id, sender, receiver, message, timestamp FROM messages WHERE receiver = 'PUBLIC_ROOM' ORDER BY id ASC LIMIT 100`, [], (err, messages) => {
        if (err) return res.status(500).json({ error: err.message });
        return res.json(messages);
    });
});

app.listen(PORT, () => {
    console.log(`Mak Chat Server started on port ${PORT}`);
});