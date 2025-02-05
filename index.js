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
const port = process.env.PORT;

require('dotenv').config();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
    secret: 'wedrftgyhujikolpoi9u8y7358923iruhfwgevgfhsdjklpdioweiutyfgsidha', // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

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

        // Save user info in session
        req.session.user = {
            id: user.id,
            email: user.email,
            username: user.username
        };

        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ error: 'Error logging in user' });
    }
});

app.listen(3000, () => {
    console.log(`Server running on port ${process.env.PORT}, http://localhost:${process.env.PORT}`);
});