const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { body, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const rateLimit = require('express-rate-limit');
const knexConfig = require('./knexfile.js');
const knex = require('knex')(knexConfig.development);
const app = express();
const PORT = 3000;
const cors = require('cors');

require('dotenv').config();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const corsOptions = {
    origin: `${process.env.FRONTEND_URL}`,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token', 'Access-Control-Allow-Origin'],
    credentials: true
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', (req, res) => {
    res.header('Access-Control-Allow-Origin', `${process.env.FRONTEND_URL}`);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-auth-token, Access-Control-Allow-Origin');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.sendStatus(204);
});


const transporter = nodemailer.createTransport({
    service: process.env.MAIL_SERVICE,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Define rate limiting rules
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Apply rate limiting to all requests
app.use(limiter);

// Configure session middleware with SQLite store
app.use(session({
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: './' }),
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 1000 * 60 * 60, // 1 hour
        sameSite: 'lax' // Adjust as needed
    }
}));

const isLoggedIn = (req, res, next) => {
    if (req.session.user) {
        return next();
    } else {
        return res.status(401).json({message: "Not authenticated"});
    }
};

app.post('/register', [
    body('firstname').trim().isLength({ min: 1 }).escape(),
    body('lastname').trim().isLength({ min: 1 }).escape(),
    body('DOB').isDate(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('confirm_password').isLength({ min: 6 }),
    body('username').trim().isLength({ min: 1 }).escape(),
    body('channel_name').trim().isLength({ min: 1 }).escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { firstname, lastname, DOB, email, password, confirm_password, username, channel_name } = req.body;

    if (password !== confirm_password) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    try {
        const sanitizedFirstname = sanitizeHtml(firstname);
        const sanitizedLastname = sanitizeHtml(lastname);
        const sanitizedUsername = sanitizeHtml(username);
        const sanitizedChannelName = sanitizeHtml(channel_name);

        const hashedPassword = await bcrypt.hash(password, 10);

        const [userId] = await knex('user').insert({
            username: sanitizedUsername,
            email,
            password: hashedPassword,
            firstname: sanitizedFirstname,
            lastname: sanitizedLastname,
            DOB,
            channel_name: sanitizedChannelName,
            created_at: new Date(),
            updated_at: new Date(),
            verified: false
        }).returning('id');

        const token = crypto.randomBytes(32).toString('hex');
        const tokenExpiration = new Date(Date.now() + 3600000);

        await knex('verification_tokens').insert({
            user_id: userId.id,
            token,
            expires_at: tokenExpiration
        });

        const verificationLink = `${process.env.FRONTEND_URL}/verify?token=${token}`;

        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Email Verification',
            text: `Hello ${sanitizedFirstname},\n\nPlease verify your email by clicking the link: ${verificationLink}\n\nThank you!`
        };

        await transporter.sendMail(mailOptions);

        res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Error registering user' });
    }
});

app.get('/verify', async (req, res) => {
    const { token } = req.query;

    try {
        const [tokenData] = await knex('verification_tokens').where({ token }).andWhere('expires_at', '>', new Date());

        if (!tokenData) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        await knex('user').where({ id: tokenData.user_id }).update({ verified: true });
        await knex('verification_tokens').where({ token }).del();

        res.status(200).json({ message: 'User verified successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error verifying user' });
    }
});

app.post('/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        const user = await knex('user').where({ email }).first();

        if (!user) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        if (!user.verified) {
            return res.status(400).json({ error: 'Please verify your email before logging in' });
        }

        req.session.user = {
            id: user.id,
            email: user.email,
            username: user.username
        };

        res.status(200).json({ message: 'Login successful', user });
    } catch (error) {
        res.status(500).json({ error: 'Error logging in user' });
    }
});

app.get('/check-session', [isLoggedIn], async (req, res) => {
    if (req.session.user) {
        return res.status(200).json({ user: req.session.user });
    }

    res.status(401).json({ error: 'User not logged in' });
})

app.get('/account', [isLoggedIn], async (req, res) => {
    console.log(req.session.user);
    if (req.session.user) {
        const user = await knex('user').where({ id: req.session.user.id }).first();
        return res.status(200).json({ user });
    }

    res.status(401).json({ error: 'User not logged in' });
});

app.post('/logout', [isLoggedIn], async (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Error logging out' });
        }

        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logout successful' });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}, http://localhost:${PORT}`);
});