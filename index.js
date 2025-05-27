/**
 * Main backend server for Ninjahalfpipe.
 * Handles authentication, video management, user profiles, and more.
 * Uses Express, Knex, SQLite, and various middleware.
 */

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

/**
 * CORS configuration for frontend-backend communication.
 */
const corsOptions = {
    origin: `https://ninjahalfpipe.natninjorna.se`,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token', 'Access-Control-Allow-Origin'],
    credentials: true
};

app.use(cors(corsOptions));

// Handle preflight requests for CORS
app.options('*', (req, res) => {
    res.header('Access-Control-Allow-Origin', `https://ninjahalfpipe.natninjorna.se`);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-auth-token, Access-Control-Allow-Origin');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.sendStatus(204);
});

const {MAIL_HOST, MAIL_PASS, MAIL_USER, MAIL_PORT} = process.env;

let mailAddress = '';
let transporter = null;

// Set DNS servers for mail resolution
dns.setServers([
    '1.1.1.1',
    '8.8.8.8'
]);

/**
 * Setup mail transporter for nodemailer.
 */
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
        connectionTimeout: 10000, // 10 seconds timeout
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

// Only resolve IPv4 for mail host
dns.lookup(MAIL_HOST, { family: 4 }, (err, address) => {
    if (err || !address) {
        console.warn(`[SMTP] Error resolving IPv4 address for ${MAIL_HOST}: ${err ? err.message : 'No address found'}\nFalling back to default...`);
        mailAddress = MAIL_HOST;
    } else {
        console.log(`[SMTP] Mail host resolved to IPv4 address: ${address}`);
        mailAddress = address;
    }
    setupMail();
});

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
        sameSite: 'lax'
    }
}));

// Serve static files for profile pictures and uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

/**
 * Middleware to check if user is logged in.
 */
const isLoggedIn = (req, res, next) => {
    if (req.session.user) {
        return next();
    } else {
        return res.status(401).json({message: "Not authenticated"});
    }
};

/**
 * Multer storage config for profile pictures.
 */
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads', 'profile_pics');
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

/**
 * User registration route.
 * Validates input, hashes password, sends verification email.
 */
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
        // Sanitize input
        const sanitizedFirstname = sanitizeHtml(firstname);
        const sanitizedLastname = sanitizeHtml(lastname);
        const sanitizedUsername = sanitizeHtml(username);

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into DB
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

        // Generate verification token
        const token = crypto.randomBytes(32).toString('hex');
        const tokenExpiration = new Date(Date.now() + 3600000);

        await knex('verification_tokens').insert({
            user_id: userId.id,
            token,
            expires_at: tokenExpiration
        });

        // Send verification email
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

/**
 * Email verification route.
 * Verifies user using token sent to email.
 */
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

/**
 * User login route.
 * Validates credentials and starts session.
 */
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

        // Set session user
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

/**
 * Get user by ID.
 */
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

/**
 * Like a video.
 * Handles like/dislike logic and updates counts.
 */
app.post('/likeVideo/:id', [isLoggedIn], async (req, res) => {
    const { id } = req.params;

    try {
        const video = await knex('video').where({ id }).first();

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        // Check if already liked/disliked
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

/**
 * Dislike a video.
 * Handles like/dislike logic and updates counts.
 */
app.post('/dislikeVideo/:id', [isLoggedIn], async (req, res) => {
    const { id } = req.params;

    try {
        const video = await knex('video').where({ id }).first();

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        // Check if already disliked/liked
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

/**
 * Check if user session is active.
 */
app.get('/check-session', [isLoggedIn], async (req, res) => {
    if (req.session.user) {
        return res.status(200).json({ user: req.session.user });
    }

    res.status(401).json({ error: 'User not logged in' });
});

/**
 * Get account info for logged-in user.
 */
app.get('/account', [isLoggedIn], async (req, res) => {
    if (req.session.user) {
        const user = await knex('user').where({ id: req.session.user.id }).first();
        console.log(user);
        return res.status(200).json({ user });
    }

    res.status(401).json({ error: 'User not logged in' });
});

/**
 * Upload profile picture for user.
 */
app.post('/account/uploadProfilePicture', [isLoggedIn], upload.single('profile_picture'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const profilePicturePath = `/uploads/profile_pics/${req.file.filename}`;
    await knex('user').where({ id: req.session.user.id }).update({ profile_picture: profilePicturePath });
    return res.status(200).json({ message: 'Profile picture uploaded successfully' });
});

/**
 * Get channel info and videos by username.
 */
app.get('/channel/:username', async (req, res) => {
    const { username } = req.params;

    try {
        const channelInfo = await knex('user').where({ username }).first();

        if (!channelInfo) {
            return res.status(404).json({ error: 'Channel not found' });
        }

        const videos = await knex('video').where({ user_id: channelInfo.id }).select('id', 'title', 'thumbnail');

        res.status(200).json({ channelInfo, videos });
    } catch (error) {
        console.error('Error fetching channel data:', error);
        res.status(500).json({ error: 'Error fetching channel data' });
    }
});

/**
 * Multer storage config for video and thumbnail uploads.
 */
const videoStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        let uploadPath;
        if (file.fieldname === 'video') {
            uploadPath = path.join(__dirname, 'uploads', 'videos');
        } else if (file.fieldname === 'thumbnail') {
            uploadPath = path.join(__dirname, 'uploads', 'thumbnails');
        }
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

/**
 * Upload a new video (and optional thumbnail).
 */
app.post('/uploadVideo', [isLoggedIn], uploadVideo.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), async (req, res) => {
    if (!req.files || !req.files.video) {
        return res.status(400).json({ error: 'No video uploaded' });
    }

    const { title, description } = req.body;
    const videoPath = `/uploads/videos/${req.files.video[0].filename}`;
    const thumbnailPath = req.files.thumbnail ? `/uploads/thumbnails/${req.files.thumbnail[0].filename}` : null;

    try {
        await knex('video').insert({
            user_id: req.session.user.id,
            title,
            description,
            url: videoPath,
            thumbnail: thumbnailPath,
            created_at: new Date(),
            updated_at: new Date()
        });

        res.status(201).json({ message: 'Video uploaded successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error uploading video' });
    }
});

/**
 * Get video by ID.
 */
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

/**
 * Logout user and destroy session.
 */
app.post('/logout', [isLoggedIn], async (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Error logging out' });
        }

        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logout successful' });
    });
});


/**
 * Get all videos.
 */
app.get('/videos', async (req, res) => {
    try {
        const videos = await knex('video')
            .join('user', 'video.user_id', 'user.id')
            .select(
                'video.id',
                'video.title',
                'video.thumbnail',
                'video.views_count',
                'video.description',
                'video.created_at',
                'user.username as username'
            );
        res.status(200).json({ videos });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching videos' });
    }
});

/**
 * Post a comment on a video.
 * Validates input and checks if video exists.
 * Handles comment insertion into DB.
 */

app.post('/commentVideo/:id', [isLoggedIn], async (req, res) => {
    const { id } = req.params;
    const { comment } = req.body;

    if (!comment) {
        return res.status(400).json({ error: 'Comment cannot be empty' });
    }

    try {
        const video = await knex('video').where({ id }).first();

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        await knex('comments').insert({
            user_id: req.session.user.id,
            video_id: id,
            comment,
            created_at: new Date(),
            updated_at: new Date()
        });

        res.status(201).json({ message: 'Comment posted successfully' });
    } catch (error) {
        console.error('Error posting comment:', error);
        res.status(500).json({ error: 'Error posting comment' });
    }
});


/**
 * Get comments for a video.
 * Fetches comments from DB and joins with user table to get usernames.
 * Handles error cases.
 */
app.get('/getComments/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const comments = await knex('comments')
            .join('user', 'comments.user_id', 'user.id')
            .where('comments.video_id', id)
            .select('comments.id', 'comments.comment', 'comments.created_at', 'user.username');

        res.status(200).json({ comments });
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: 'Error fetching comments' });
    }
});


/**
 * Update video history.
 * Checks if video exists and if user has already viewed it.
 * Handles insertion or update of video history in DB.
 * Also updates the viewed_at timestamp.
 */
app.post('/history/:videoId', [isLoggedIn], async (req, res) => {
    const { videoId } = req.params;

    try {
        const video = await knex('video').where({ id: videoId }).first();

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        const existingHistory = await knex('video_history')
            .where({ user_id: req.session.user.id, video_id: videoId })
            .first();

        if (existingHistory) {
            await knex('video_history')
                .where({ user_id: req.session.user.id, video_id: videoId })
                .update({ viewed_at: new Date() });
        } else {
            await knex('video_history').insert({
                user_id: req.session.user.id,
                video_id: videoId,
                thumbnail: video.thumbnail,
                viewed_at: new Date()
            });
        }

        res.status(201).json({ message: 'Video history updated successfully' });
    } catch (error) {
        console.error('Error updating video history:', error);
        res.status(500).json({ error: 'Error updating video history' });
    }
});

/**
 * Increment video views count.
 * Checks if video exists and increments views_count in DB.
 * Handles error cases.
 */
app.post('/incrementViews/:videoId', [isLoggedIn], async (req, res) => {
    const { videoId } = req.params;

    try {
        await knex('video').where({ id: videoId }).increment('views_count', 1);
        res.status(200).json({ message: 'Views incremented' });
    } catch (error) {
        console.error('Error incrementing views:', error);
        res.status(500).json({ error: 'Error incrementing views' });
    }
});


/**
 * Get video history for logged-in user.
 */
app.get('/history', [isLoggedIn], async (req, res) => {
    try {
        const history = await knex('video_history')
            .join('video', 'video_history.video_id', 'video.id')
            .join('user', 'video.user_id', 'user.id')
            .select(
                'video.id',
                'video.title',
                'video.thumbnail',
                'video.views_count',
                'video.created_at',
                'user.username as uploader'
            )
            .where('video_history.user_id', req.session.user.id)
            .orderBy('video_history.viewed_at', 'desc');

        res.status(200).json({ history });
    } catch (error) {
        console.error('Error fetching history:', error);
        res.status(500).json({ error: 'Error fetching history' });
    }
});

/**
 * Delete a video.
 * Checks if video exists and if user is authorized to delete it.
 * Handles deletion from DB.
 */
app.delete('/video/:videoId', [isLoggedIn], async (req, res) => {
    const { videoId } = req.params;

    try {
        const video = await knex('video').where({ id: videoId }).first();

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        if (video.user_id !== req.session.user.id) {
            return res.status(403).json({ error: 'You are not authorized to delete this video' });
        }

        await knex('video').where({ id: videoId }).del();
        res.status(200).json({ message: 'Video deleted successfully' });
    } catch (error) {
        console.error('Error deleting video:', error);
        res.status(500).json({ error: 'Error deleting video' });
    }
})

/**
 * Route: GET /search
 * Description: Search for videos by title and include uploader's username.
 */
app.get('/search', async (req, res) => {
    const { query } = req.query;

    // Validate that a search query is provided
    if (!query) {
        return res.status(400).json({ error: 'Query parameter is required' });
    }

    try {
        // Join video and user tables to get video info and uploader's username
        const videos = await knex('video')
            .join('user', 'video.user_id', 'user.id')
            .where('video.title', 'like', `%${query}%`)
            .select(
                'video.id',
                'video.title',
                'video.thumbnail',
                'video.views_count',
                'video.description',
                'video.created_at',
                'user.username as username'
            );

        // Return matching videos
        res.status(200).json({ videos });
    } catch (error) {
        // Log and return error if search fails
        console.error('Error fetching search results:', error);
        res.status(500).json({ error: 'Error fetching search results' });
    }
});

/**
 * Route: POST /updateDescription
 * Description: Update the logged-in user's bio/description.
 * Requires authentication.
 */
app.post('/updateDescription', [isLoggedIn], async (req, res) => {
    const { bio } = req.body;

    // Validate that a bio/description is provided
    if (!bio) {
        return res.status(400).json({ error: 'Description is required' });
    }

    try {
        // Update the user's bio in the database
        await knex('user')
            .where({ id: req.session.user.id })
            .update({ bio, updated_at: new Date() });

        // Respond with success message
        res.status(200).json({ message: 'Description updated successfully' });
    } catch (error) {
        // Log and return error if update fails
        console.error('Error updating description:', error);
        res.status(500).json({ error: 'Error updating description' });
    }
});

app.post('/changePassword', [isLoggedIn], async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Missing password fields' });
    }

    try {
        const user = await knex('user').where({ id: req.session.user.id }).first();
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await knex('user').where({ id: user.id }).update({ password: hashedPassword, updated_at: new Date() });

        res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ error: 'Error changing password' });
    }
});

app.post('/updateEmail', [isLoggedIn], async (req, res) => {
    body('email').isEmail().normalizeEmail();
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    try {
        // Check if email is already in use
        const existing = await knex('user').where({ email }).first();
        if (existing && existing.id !== req.session.user.id) {
            return res.status(400).json({ error: 'Email already in use' });
        }

        await knex('user')
            .where({ id: req.session.user.id })
            .update({ email, updated_at: new Date() });

        res.status(200).json({ message: 'Email updated successfully' });
    } catch (error) {
        console.error('Error updating email:', error);
        res.status(500).json({ error: 'Error updating email' });
    }
});

/**
 * Start the Express server.
 */
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}, http://localhost:${PORT}`);
});