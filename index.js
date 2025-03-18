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
const dns = require("dns");
const multer = require('multer');
const path = require('path');
const fs = require('fs');

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


const {MAIL_HOST, MAIL_PASS, MAIL_USER, MAIL_PORT} = process.env;

let mailAddress = '';
let transporter = null;

dns.setServers([
    '1.1.1.1',
    '8.8.8.8'
])

const setupMail = () => {
    if (mailAddress === '') {
        console.log(`[SMTP] Could not resolve mail host address for ${MAIL_HOST}, falling back to default...`);
        mailAddress = MAIL_HOST;
    }

    transporter = nodemailer.createTransport({
        host: mailAddress,
        port: MAIL_PORT,
        secure: true,
        auth: {
            user: MAIL_USER,
            pass: MAIL_PASS,
        },
        tls: {
            servername: MAIL_HOST,
            rejectUnauthorized: false,
        },
        connectionTimeout: 10000, // Increase timeout to 10 seconds
    });

    console.log(`[SMTP] Host set to ${mailAddress}.\n[SMTP] Verifying SMTP connection...`);
    transporter.verify((error, success) => {
        if (error) {
            console.error('[SMTP] Connection error:', error);
            throw new Error("Unrecoverable error: SMTP connection failed.");
        } else {
            console.log('[SMTP] Connection successful, ready to serve requests.');
        }
    });
}

dns.lookup(MAIL_HOST, {family: 6}, (err, address) => {
    if (err || !address) {
        console.warn(`[SMTP] Error resolving IPv6 address for ${MAIL_HOST}: ${err ? err.message : 'No address found'}\n[SMTP] Falling back to IPv4...`);

        dns.lookup(MAIL_HOST, {family: 4}, (err, address) => {
            if (err || !address) {
                console.warn(`[SMTP] Error resolving IPv4 address for ${MAIL_HOST}: ${err ? err.message : 'No address found'}\nFalling back to default...`);
                mailAddress = MAIL_HOST;
                setupMail()
                return;
            }

            console.log(`[SMTP] Mail host resolved to IPv4 address: ${address}`);
            mailAddress = address;
            setupMail()
        });
        return
    }
    console.log(`[SMTP] Mail host resolved to IPv6 address: ${address}`);
    mailAddress = address;
    setupMail()
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

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const isLoggedIn = (req, res, next) => {
    if (req.session.user) {
        return next();
    } else {
        return res.status(401).json({message: "Not authenticated"});
    }
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads'); // Use relative path
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, `${req.session.user.id}-${Date.now()}${path.extname(file.originalname)}`);
    }
});

const upload = multer({ storage });

app.post('/register', [
    body('firstname').trim().isLength({ min: 1 }).escape(),
    body('lastname').trim().isLength({ min: 1 }).escape(),
    body('DOB').isDate(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('confirm_password').isLength({ min: 6 }),
    body('username').trim().isLength({ min: 1 }).escape(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { firstname, lastname, DOB, email, password, confirm_password, username} = req.body;

    if (password !== confirm_password) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    try {
        const sanitizedFirstname = sanitizeHtml(firstname);
        const sanitizedLastname = sanitizeHtml(lastname);
        const sanitizedUsername = sanitizeHtml(username);

        const hashedPassword = await bcrypt.hash(password, 10);

        const [userId] = await knex('user').insert({
            username: sanitizedUsername,
            email,
            password: hashedPassword,
            firstname: sanitizedFirstname,
            lastname: sanitizedLastname,
            DOB,
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
            from: process.env.MAIL_USER,
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

app.get('/getUser/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const user = await knex('user').where({ id }).first();

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ user });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching user' });
    }
});

app.post('/likeVideo/:id', [isLoggedIn], async (req, res) => {
    const { id } = req.params;

    try {
        const video = await knex('video').where({ id }).first();

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        const existingLike = await knex('video_likes').where({ user_id: req.session.user.id, video_id: id }).first();
        const existingDislike = await knex('video_dislikes').where({ user_id: req.session.user.id, video_id: id }).first();

        if (existingLike) {
            return res.status(400).json({ error: 'You have already liked this video' });
        }

        if (existingDislike) {
            await knex('video_dislikes').where({ user_id: req.session.user.id, video_id: id }).del();
            await knex('video').where({ id }).decrement('dislikes_count', 1);
        }

        await knex('video_likes').insert({
            user_id: req.session.user.id,
            video_id: id
        });

        await knex('video').where({ id }).increment('likes_count', 1);

        res.status(201).json({ message: 'Video liked successfully' });
    } catch (error) {
        console.error('Error liking video:', error);
        res.status(500).json({ error: 'Error liking video' });
    }
});

app.post('/dislikeVideo/:id', [isLoggedIn], async (req, res) => {
    const { id } = req.params;

    try {
        const video = await knex('video').where({ id }).first();

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        const existingDislike = await knex('video_dislikes').where({ user_id: req.session.user.id, video_id: id }).first();
        const existingLike = await knex('video_likes').where({ user_id: req.session.user.id, video_id: id }).first();

        if (existingDislike) {
            return res.status(400).json({ error: 'You have already disliked this video' });
        }

        if (existingLike) {
            await knex('video_likes').where({ user_id: req.session.user.id, video_id: id }).del();
            await knex('video').where({ id }).decrement('likes_count', 1);
        }

        await knex('video_dislikes').insert({
            user_id: req.session.user.id,
            video_id: id
        });

        await knex('video').where({ id }).increment('dislikes_count', 1);

        res.status(201).json({ message: 'Video disliked successfully' });
    } catch (error) {
        console.error('Error disliking video:', error);
        res.status(500).json({ error: 'Error disliking video' });
    }
});

app.get('/check-session', [isLoggedIn], async (req, res) => {
    if (req.session.user) {
        return res.status(200).json({ user: req.session.user });
    }

    res.status(401).json({ error: 'User not logged in' });
})

app.get('/account', [isLoggedIn], async (req, res) => {
    if (req.session.user) {
        const user = await knex('user').where({ id: req.session.user.id }).first();
        console.log(user);
        return res.status(200).json({ user });
    }

    res.status(401).json({ error: 'User not logged in' });
});

app.post('/account/uploadProfilePicture', [isLoggedIn], upload.single('profile_picture'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const profilePicturePath = `/uploads/${req.file.filename}`;
    await knex('user').where({ id: req.session.user.id }).update({ profile_picture: profilePicturePath });
    return res.status(200).json({ message: 'Profile picture uploaded successfully' });
});

app.get('/channel/:username', async (req, res) => {
    const { username } = req.params;

    try {
        const channelInfo = await knex('user').where({ username }).first();

        if (!channelInfo) {
            return res.status(404).json({ error: 'Channel not found' });
        }

        res.status(200).json({ channelInfo });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching user' });
    }
})

const videoStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads', 'videos'); // Use relative path for videos
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, `${req.session.user.id}-${Date.now()}${path.extname(file.originalname)}`);
    }
});

const uploadVideo = multer({ storage: videoStorage });

app.post('/uploadVideo', [isLoggedIn], uploadVideo.single('video'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No video uploaded' });
    }

    const { title, description } = req.body;
    const videoPath = `/uploads/videos/${req.file.filename}`;

    try {
        await knex('video').insert({
            user_id: req.session.user.id,
            title,
            description,
            url: videoPath,
            created_at: new Date(),
            updated_at: new Date()
        });

        res.status(201).json({ message: 'Video uploaded successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error uploading video' });
    }
});

app.get('/getVideo/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const video = await knex('video').where({ id }).first();

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        res.status(200).json({ video });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching video' });
    }
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

app.get('/videos', async (req, res) => {
    try {
        const videos = await knex('video').select('*');
        res.status(200).json({ videos });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching videos' });
    }
})

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}, http://localhost:${PORT}`);
});