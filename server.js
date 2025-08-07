const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const nodemailer = require('nodemailer');
const axios = require('axios');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { jsPDF } = require('jspdf');
const Jimp = require('jimp');
require('jspdf-autotable');
require('dotenv').config();
const winston = require('winston');
const sharp = require('sharp');
// const { body, validationResult } = require('express-validator');
const swaggerJsDoc = require('swagger-jsdoc');
const { body, validationResult, param } = require('express-validator');
const swaggerUi = require('swagger-ui-express');
// const { body, validationResult, param } = require('express-validator');
const csurf = require('csurf');
const Sentry = require('@sentry/node');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const timeout = require('express-timeout-handler');
const compression = require('compression');
const SentryTracing = require('@sentry/tracing');
const app = express();
const cron = require('node-cron');
const { google } = require('googleapis');
const { Handlers } = require('@sentry/node');
const rateLimit = require('express-rate-limit');
// const jsPDF = require('jspdf');
const webpush = require('web-push');
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
    ]
});


Sentry.init({
    dsn: process.env.SENTRY_DSN,
    tracesSampleRate: 0.0,
    environment: process.env.NODE_ENV || 'development',
});





app.use(Handlers.requestHandler());

app.use(express.json({ type: ['application/json', 'text/plain'] }));
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
app.use(cookieParser());
app.use(csurf({ cookie: true }));
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    logger.info(`Request: ${req.method} ${req.originalUrl} - Headers: ${JSON.stringify(req.headers)}`);
    next();
});

app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));

app.use(timeout.handler({
    timeout: 10000,
    onTimeout: (req, res) => {
        logger.error(`Request timed out: ${req.originalUrl}`);
        Sentry.captureException(new Error(`Request timed out: ${req.originalUrl}`));
        res.status(504).json({ error: 'Request timed out' });
    }
}));





app.get('/api/check-session', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('username email profile');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            valid: true,
            user: {
                userId: req.user.userId,
                email: req.user.email,
                isAdmin: req.user.isAdmin,
                username: user.username,
                profile: user.profile
            }
        });
    } catch (error) {
        logger.error(`Error checking session: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to check session' });
    }
});


const swaggerOptions = {
    swaggerDefinition: {
        openapi: '3.0.0',
        info: {
            title: 'Portfolio API',
            version: '1.0.0',
            description: 'API for Ibrahim Al-Asfar\'s portfolio website'
        },
        servers: [
            { url: process.env.BASE_URL, description: 'Production server' },
            { url: 'http://localhost:3000', description: 'Local development server' }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./docs/swagger.yaml'] 
};
const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));
app.use(passport.initialize());

const helmet = require('helmet');
app.use(helmet());

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'Uploads',
        allowed_formats: ['jpeg', 'png', 'pdf'],
        resource_type: 'auto'
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Only JPEG, PNG, or PDF files are allowed'));
        }
        cb(null, true);
    }
});






mongoose.connect(process.env.MONGODB_URI)
  .then(() => logger.info('Connected to MongoDB'))
  .catch(err => {
    logger.error(`MongoDB connection error: ${err.message}`, { stack: err.stack });
    Sentry.captureException(err);
    process.exit(1);
  });

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FACEBOOK_CLIENT_ID = process.env.FACEBOOK_CLIENT_ID;
const FACEBOOK_CLIENT_SECRET = process.env.FACEBOOK_CLIENT_SECRET;
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const HUGGING_FACE_TOKEN = process.env.HUGGING_FACE_TOKEN;
const AI_API_URL = process.env.AI_API_URL;

if (!MONGODB_URI || !JWT_SECRET || !GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !FACEBOOK_CLIENT_ID || !FACEBOOK_CLIENT_SECRET || !GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET || !EMAIL_USER || !EMAIL_PASS || !HUGGING_FACE_TOKEN || !process.env.WEB_URL || !process.env.BASE_URL || !process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET || !process.env.GITHUB_TOKEN || !process.env.SENTRY_DSN) {
    logger.error('Missing environment variables');
    process.exit(1);
}

webpush.setVapidDetails(
    'mailto:marklasfar@gmail.com',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

const WEB_URL = process.env.WEB_URL;
const BASE_URL = process.env.BASE_URL;

app.use(cors({
    origin: process.env.WEB_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-New-Token', 'x-refresh-token']
}));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    }
});

// mongoose.connect(MONGODB_URI)
//     .then(() => logger.info('Connected to MongoDB'))
//     .catch(err => logger.error('MongoDB connection error:', err));

const projectSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    image: { type: String }, // جعل الصورة اختيارية
    rating: { type: String }, // جعل التقييم اختياري
    stars: { type: Number }, // جعل النجوم اختياري
    links: [{ option: String, value: String, isPrivate: { type: Boolean, default: false } }],
});
const Project = mongoose.model('Project', projectSchema);

const commentSchema = new mongoose.Schema({
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    rating: { type: Number, required: true },
    text: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    replies: [{
        text: { type: String, required: true },
        timestamp: { type: Date, default: Date.now },
    }],
});
const Comment = mongoose.model('Comment', commentSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, sparse: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    isAdmin: { type: Boolean, default: false },
    googleId: String,
    googleAccessToken: String,
    googleRefreshToken: String,
    facebookId: String,
    facebookAccessToken: String,
    facebookRefreshToken: String,
    githubRefreshToken: String,
    githubId: String,
    githubAccessToken: String,
    otp: String,
    otpExpires: Date,
    refreshTokens: [{ token: String, createdAt: { type: Date, default: Date.now } }],
    notifications: [{ type: String }],
    profile: {
        nickname: { type: String, unique: true, sparse: true },
        avatar: String,
        status:String,
        jobTitle: String,
        pdfFormat: { type: String, enum: ['jspdf', 'canva'], default: 'jspdf' },
        bio: String,
        phone: { type: String, default: '' },
        socialLinks: {
            linkedin: { type: String, default: '' },
            behance: { type: String, default: '' },
            github: { type: String, default: '' },
            whatsapp: { type: String, default: '' }
        },
        education: [{ institution: String, degree: String, year: String }],
        experience: [{ company: String, role: String, duration: String }],
        certificates: [{ name: String, issuer: String, year: String }],
        skills: [{ name: String, percentage: Number }],
        projects: [{ title: String, description: String, image: String, links: [{ option: String, value: String }] }],
        interests: [String],
        isPublic: { type: Boolean, default: true },
        customFields: [{ key: String, value: String }],
        avatarDisplayType: { type: String, enum: ['svg', 'normal'], default: 'normal' },
        svgColor: { type: String, default: '#000000' },
    //     canvaAccessToken: String,
    // canvaRefreshToken: String,
        portfolioName: { type: String, default: 'Portfolio' }
    }
});
userSchema.index({ 'profile.nickname': 1 }, { unique: true, sparse: true });
userSchema.index({ email: 1 }, { unique: true });
const User = mongoose.model('User', userSchema);

const skillSchema = new mongoose.Schema({
    name: { type: String, required: true },
    icon: { type: String, required: true },
    percentage: { type: Number, required: true },
});
const Skill = mongoose.model('Skill', skillSchema);

const conversationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    messages: [{ role: String, content: String, timestamp: { type: Date, default: Date.now } }],
});
const Conversation = mongoose.model('Conversation', conversationSchema);






passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
    scope: ['profile', 'email', 'https://www.googleapis.com/auth/drive.file'] // Add Drive scope
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            user = await User.create({
                googleId: profile.id,
                email: profile.emails[0].value,
                username: profile.displayName,
                googleAccessToken: accessToken,
                googleRefreshToken: refreshToken
            });
        } else {
            user.googleAccessToken = accessToken;
            if (refreshToken) {
                user.googleRefreshToken = refreshToken;
            }
            await user.save();
        }
        return done(null, user);
    } catch (error) {
        logger.error(`Google strategy error: ${error.message}`);
        return done(error, null);
    }
}));

app.get('/auth/google/callback', passport.authenticate('google', { session: false }), async (req, res) => {
    try {
        const { token, refreshToken } = await generateTokens(req.user);
        logger.info(`Google auth callback for user: ${req.user.email}`);
        res.redirect(`${process.env.WEB_URL}/auth/callback?token=${token}&refreshToken=${refreshToken}&provider=google`);
    } catch (error) {
        logger.error(`Google callback error for ${req.user.email}: ${error.message}`);
        res.status(500).redirect(`${process.env.WEB_URL}/login.html?error=${encodeURIComponent('Authentication failed')}`);
    }
});

passport.use(new FacebookStrategy({
    clientID: FACEBOOK_CLIENT_ID,
    clientSecret: FACEBOOK_CLIENT_SECRET,
    callbackURL: `${process.env.BASE_URL}/auth/facebook/callback`,
    profileFields: ['id', 'emails', 'displayName', 'photos', 'posts', 'friends'],
    scope: ['email', 'public_profile', 'user_posts', 'user_likes', 'user_friends'] // Add required scopes
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ facebookId: profile.id });
        if (!user) {
            user = await User.create({
                facebookId: profile.id,
                email: profile.emails ? profile.emails[0].value : `${profile.id}@facebook.com`,
                username: profile.displayName,
                facebookAccessToken: accessToken // Store access token for API calls
            });
        } else {
            user.facebookAccessToken = accessToken; // Update access token
            if (refreshToken) {
                user.refreshTokens.push({ token: refreshToken });
            }
            await user.save();
        }
        return done(null, user);
    } catch (error) {
        logger.error(`Facebook strategy error: ${error.message}`);
        return done(error, null);
    }
}));

app.get('/auth/facebook/callback', passport.authenticate('facebook', { session: false }), async (req, res) => {
    try {
        const { token, refreshToken } = await generateTokens(req.user);
        logger.info(`Facebook auth callback for user: ${req.user.email}`);
        res.redirect(`${process.env.WEB_URL}/auth/callback?token=${token}&refreshToken=${refreshToken}&provider=facebook`);
    } catch (error) {
        logger.error(`Facebook callback error for ${req.user.email}: ${error.message}`);
        res.status(500).redirect(`${process.env.WEB_URL}/login.html?error=${encodeURIComponent('Authentication failed')}`);
    }
});

passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: `${process.env.BASE_URL}/auth/github/callback`,
    scope: ['user:email', 'repo'] // Add repo scope for repository access
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ githubId: profile.id });
        if (!user) {
            user = await User.create({
                githubId: profile.id,
                email: profile.emails ? profile.emails[0].value : `${profile.id}@github.com`,
                username: profile.displayName || profile.username,
                githubAccessToken: accessToken // Store access token
            });
        } else {
            user.githubAccessToken = accessToken;
            if (refreshToken) {
                user.refreshTokens.push({ token: refreshToken });
            }
            await user.save();
        }
        return done(null, user);
    } catch (error) {
        logger.error(`GitHub strategy error: ${error.message}`);
        return done(error, null);
    }
}));
app.get('/api/csrf-token', (req, res) => {
    const csrfToken = req.csrfToken ? req.csrfToken() : null;
    if (!csrfToken) {
        logger.error('Failed to generate CSRF token');
        Sentry.captureMessage('Failed to generate CSRF token', { extra: { endpoint: '/api/csrf-token', method: 'GET' } });
        return res.status(500).json({ error: 'Failed to generate CSRF token' });
    }
    res.json({ csrfToken });
});

app.get('/auth/github/callback', passport.authenticate('github', { session: false }), async (req, res) => {
    try {
        const { token, refreshToken } = await generateTokens(req.user);
        logger.info(`GitHub auth callback for user: ${req.user.email}`);
        res.redirect(`${process.env.WEB_URL}/auth/callback?token=${token}&refreshToken=${refreshToken}&provider=github`);
    } catch (error) {
        logger.error(`GitHub callback error for ${req.user.email}: ${error.message}`);
        res.status(500).redirect(`${process.env.WEB_URL}/login.html?error=${encodeURIComponent('Authentication failed')}`);
    }
});

app.post('/api/notifications/subscribe', authenticateToken, async (req, res) => {
    try {
        const subscription = req.body;
        const user = await User.findById(req.user.userId);
        user.notifications.push(subscription);
        await user.save();
        res.json({ message: 'Subscription added successfully' });
    } catch (error) {
        logger.error(`Error subscribing to notifications: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to subscribe to notifications' });
    }
});



app.get('/api/facebook/posts', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);

        if (!user.facebookAccessToken) {
            return res.status(400).json({ error: 'Facebook account not linked' });
        }

        let accessToken = user.facebookAccessToken;

        // Attempt to fetch posts
        let response;
        try {
            response = await axios.get('https://graph.facebook.com/v20.0/me?fields=posts{created_time,message,likes.summary(true),comments.summary(true),shares},name,email', {
                headers: { Authorization: `Bearer ${accessToken}` },
            });
        } catch (error) {
            if (error.response?.status === 401 && user.facebookRefreshToken) {
                try {
                    // Attempt to refresh the token
                    const refreshResponse = await axios.get('https://graph.facebook.com/v20.0/oauth/access_token', {
                        params: {
                            grant_type: 'fb_exchange_token',
                            client_id: process.env.FACEBOOK_CLIENT_ID,
                            client_secret: process.env.FACEBOOK_CLIENT_SECRET,
                            fb_exchange_token: user.facebookRefreshToken,
                        },
                    });

                    accessToken = refreshResponse.data.access_token;
                    user.facebookAccessToken = accessToken;
                    await user.save();

                    // Retry the request with the new token
                    response = await axios.get('https://graph.facebook.com/v20.0/me?fields=posts{created_time,message,likes.summary(true),comments.summary(true),shares},name,email', {
                        headers: { Authorization: `Bearer ${accessToken}` },
                    });
                } catch (refreshError) {
                    logger.error(`Failed to refresh Facebook token: ${refreshError.message}`);
                    Sentry.captureException(refreshError);
                    return res.status(401).json({ error: 'Facebook access token expired. Please re-authenticate.' });
                }
            } else {
                throw error; // Re-throw if not a 401 or no refresh token
            }
        }

        const posts = response.data.posts.data.map(post => ({
            id: post.id,
            created_time: post.created_time,
            message: post.message || '',
            likes: post.likes?.summary?.total_count || 0,
            comments: post.comments?.summary?.total_count || 0,
            shares: post.shares?.count || 0,
        }));

        res.json({ posts, profile: { name: response.data.name, email: response.data.email } });
    } catch (error) {
        if (error.response?.status === 401) {
            return res.status(401).json({ error: 'Facebook access token expired. Please re-authenticate.' });
        }

        logger.error(`Error fetching Facebook posts: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to fetch Facebook posts' });
    }
});

app.get('/api/github/repos', authenticateToken, async (req, res) => {
    const cacheKey = `github:repos:${req.user.userId}`;
    const cachedRepos = await client.get(cacheKey);

    if (cachedRepos) {
        return res.json(JSON.parse(cachedRepos));
    }

    try {
        const user = await User.findById(req.user.userId);

        if (!user.githubAccessToken) {
            return res.status(400).json({ error: 'GitHub account not linked' });
        }

        let accessToken = user.githubAccessToken;

        // Attempt to fetch repos
        let response;
        try {
            response = await axios.get('https://api.github.com/user/repos', {
                headers: { Authorization: `Bearer ${accessToken}` },
            });
        } catch (error) {
            if (error.response?.status === 401 && user.githubRefreshToken) {
                try {
                    // Attempt to refresh the token
                    const refreshResponse = await axios.post('https://api.github.com/oauth/access_token', {
                        client_id: process.env.GITHUB_CLIENT_ID,
                        client_secret: process.env.GITHUB_CLIENT_SECRET,
                        refresh_token: user.githubRefreshToken,
                        grant_type: 'refresh_token',
                    }, {
                        headers: { 'Accept': 'application/json' },
                    });

                    accessToken = refreshResponse.data.access_token;
                    user.githubAccessToken = accessToken;
                    if (refreshResponse.data.refresh_token) {
                        user.githubRefreshToken = refreshResponse.data.refresh_token;
                    }
                    await user.save();

                    // Retry the request with the new token
                    response = await axios.get('https://api.github.com/user/repos', {
                        headers: { Authorization: `Bearer ${accessToken}` },
                    });
                } catch (refreshError) {
                    logger.error(`Failed to refresh GitHub token: ${refreshError.message}`);
                    Sentry.captureException(refreshError);
                    return res.status(401).json({ error: 'GitHub access token expired. Please re-authenticate.' });
                }
            } else {
                throw error; // Re-throw if not a 401 or no refresh token
            }
        }

        const repos = response.data.map(repo => ({
            id: repo.id,
            name: repo.name,
            description: repo.description || 'No description provided',
            url: repo.html_url,
            image: repo.owner.avatar_url,
        }));

        await client.setEx(cacheKey, 3600, JSON.stringify(repos));
        res.json(repos);
    } catch (error) {
        if (error.response?.status === 401) {
            return res.status(401).json({ error: 'GitHub access token expired. Please re-authenticate.' });
        }

        logger.error(`Error fetching GitHub repos: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to fetch GitHub repos' });
    }
});

app.post('/api/facebook/share-profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user.facebookAccessToken) {
            return res.status(400).json({ error: 'Facebook account not linked' });
        }

        const profileUrl = `${process.env.WEB_URL}/profile/${user.profile.nickname || user.username}`;
        const message = `Check out my portfolio: ${profileUrl}`;

        const response = await axios.post('https://graph.facebook.com/v20.0/me/feed', {
            message,
            link: profileUrl
        }, {
            headers: { Authorization: `Bearer ${user.facebookAccessToken}` }
        });

        res.json({ message: 'Profile shared successfully', postId: response.data.id });
    } catch (error) {
        logger.error(`Error sharing profile on Facebook: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to share profile' });
    }
});


const facebookLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many Facebook API requests, please try again later.'
});
app.use('/api/facebook', facebookLimiter);



app.post('/api/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token required' });
    }

    try {
        const user = await User.findOne({ 'refreshTokens.token': refreshToken });
        if (!user) {
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const newAccessToken = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Optionally rotate refresh token
        user.refreshTokens = user.refreshTokens.filter(token => token.token !== refreshToken);
        const newRefreshToken = jwt.sign(
            { userId: user._id },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '7d' }
        );
        user.refreshTokens.push({ token: newRefreshToken, createdAt: new Date() });
        await user.save();

        res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    } catch (error) {
        logger.error(`Error refreshing token: ${error.message}`);
        Sentry.captureException(error);
        res.status(403).json({ error: 'Invalid or expired refresh token' });
    }
});


// app.get('/auth/canva', (req, res) => {
//     const authUrl = `https://api.canva.com/v1/oauth/authorize?client_id=${process.env.CANVA_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.BASE_URL + '/auth/canva/callback')}&response_type=code&scope=design:read,design:write,asset:private:read,asset:private:write`;
//     res.redirect(authUrl);
// });

// app.get('/auth/canva/callback', async (req, res) => {
//     const { code } = req.query;
//     try {
//         const response = await axios.post('https://api.canva.com/v1/oauth/token', {
//             client_id: process.env.CANVA_CLIENT_ID,
//             client_secret: process.env.CANVA_CLIENT_SECRET,
//             grant_type: 'authorization_code',
//             code,
//             redirect_uri: process.env.BASE_URL + '/auth/canva/callback'
//         });
//         const { access_token, refresh_token } = response.data;
//         // حفظ الـ tokens في قاعدة البيانات
//         const user = await User.findById(req.user.userId);
//         user.canvaAccessToken = access_token;
//         user.canvaRefreshToken = refresh_token;
//         await user.save();
//         res.redirect(`${process.env.WEB_URL}/auth/callback?token=${access_token}&provider=canva`);
//     } catch (error) {
//         logger.error(`Canva auth error: ${error.message}`);
//         Sentry.captureException(error);
//         res.status(500).redirect(`${process.env.WEB_URL}/login.html?error=${encodeURIComponent('Canva authentication failed')}`);
//     }
// });

// app.post('/webhooks/canva/uninstall', async (req, res) => {
//     const { userId } = req.body;
//     try {
//         const user = await User.findById(userId);
//         if (user) {
//             user.canvaAccessToken = null;
//             user.refreshTokens = null;
//             await user.save();
//             logger.info(`Canva app uninstalled for user ${userId}`);
//         }
//         res.sendStatus(200);
//     } catch (error) {
//         logger.error(`Error handling Canva uninstall webhook: ${error.message}`);
//         Sentry.captureException(error);
//         res.sendStatus(500);
//     }
// });


app.get('/api/test-sentry', (req, res) => {
    const error = new Error('Test Sentry error');
    throw error; // Will be caught by error handler and sent to Sentry
});
 



// const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later.'
});
app.use('/api/login', loginLimiter);

async function generateTokens(user) {
    user.refreshTokens = user.refreshTokens.filter(t => new Date(t.createdAt) > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000));
    const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    user.refreshTokens.push({ token: refreshToken, createdAt: new Date() });
    await user.save();
    return { token, refreshToken };
}

async function createAdminUser() {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        await User.create({
            username: 'admin',
            email: 'admin@elasfar.com',
            password: hashedPassword,
            isAdmin: true
        });
        logger.info('Admin user created');
    }
}
createAdminUser();






app.post('/api/google/save-cv', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user.googleAccessToken) {
            return res.status(400).json({ error: 'Google account not linked' });
        }

        const oauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            `${process.env.BASE_URL}/auth/google/callback`
        );
        oauth2Client.setCredentials({ access_token: user.googleAccessToken });

        // Check if token is expired and try to refresh it
        if (user.googleRefreshToken) {
            try {
                const { credentials } = await oauth2Client.refreshAccessToken();
                user.googleAccessToken = credentials.access_token;
                await user.save();
                oauth2Client.setCredentials({ access_token: user.googleAccessToken });
            } catch (refreshError) {
                logger.error(`Failed to refresh Google token: ${refreshError.message}`);
                Sentry.captureException(refreshError);
                return res.status(401).json({ error: 'Google access token expired. Please re-authenticate.' });
            }
        }

        const drive = google.drive({ version: 'v3', auth: oauth2Client });

        // Create PDF with full CV details
        const doc = new jsPDF();
        doc.setFontSize(20);
        doc.text(user.profile.nickname || user.username, 10, 20);

        // Job Title
        if (user.profile.jobTitle) {
            doc.setFontSize(14);
            doc.text(user.profile.jobTitle, 10, 30);
        }

        // Bio
        if (user.profile.bio) {
            doc.setFontSize(12);
            doc.text('Bio:', 10, 40);
            doc.text(doc.splitTextToSize(user.profile.bio, 180), 10, 50);
        }

        // Contact Info
        let yOffset = user.profile.bio ? 70 : 40;
        if (user.profile.phone || user.profile.socialLinks) {
            doc.setFontSize(12);
            doc.text('Contact:', 10, yOffset);
            if (user.profile.phone) {
                doc.text(`Phone: ${user.profile.phone}`, 10, yOffset + 10);
                yOffset += 10;
            }
            Object.keys(user.profile.socialLinks).forEach((key, index) => {
                if (user.profile.socialLinks[key]) {
                    doc.text(`${key}: ${user.profile.socialLinks[key]}`, 10, yOffset + 10 * (index + 1));
                }
            });
            yOffset += 10 * (Object.keys(user.profile.socialLinks).length + 1);
        }

        // Education
        if (user.profile.education && user.profile.education.length > 0) {
            doc.setFontSize(12);
            doc.text('Education:', 10, yOffset);
            doc.autoTable({
                startY: yOffset + 10,
                head: [['Institution', 'Degree', 'Year']],
                body: user.profile.education.map(edu => [edu.institution, edu.degree, edu.year]),
            });
            yOffset = doc.lastAutoTable.finalY + 10;
        }

        // Experience
        if (user.profile.experience && user.profile.experience.length > 0) {
            doc.setFontSize(12);
            doc.text('Experience:', 10, yOffset);
            doc.autoTable({
                startY: yOffset + 10,
                head: [['Company', 'Role', 'Duration']],
                body: user.profile.experience.map(exp => [exp.company, exp.role, exp.duration]),
            });
            yOffset = doc.lastAutoTable.finalY + 10;
        }

        // Certificates
        if (user.profile.certificates && user.profile.certificates.length > 0) {
            doc.setFontSize(12);
            doc.text('Certificates:', 10, yOffset);
            doc.autoTable({
                startY: yOffset + 10,
                head: [['Name', 'Issuer', 'Year']],
                body: user.profile.certificates.map(cert => [cert.name, cert.issuer, cert.year]),
            });
            yOffset = doc.lastAutoTable.finalY + 10;
        }

        // Skills
        if (user.profile.skills && user.profile.skills.length > 0) {
            doc.setFontSize(12);
            doc.text('Skills:', 10, yOffset);
            doc.autoTable({
                startY: yOffset + 10,
                head: [['Name', 'Percentage']],
                body: user.profile.skills.map(skill => [skill.name, `${skill.percentage}%`]),
            });
            yOffset = doc.lastAutoTable.finalY + 10;
        }

        // Projects
        if (user.profile.projects && user.profile.projects.length > 0) {
            doc.setFontSize(12);
            doc.text('Projects:', 10, yOffset);
            doc.autoTable({
                startY: yOffset + 10,
                head: [['Title', 'Description', 'Links']],
                body: user.profile.projects.map(proj => [
                    proj.title,
                    proj.description,
                    proj.links.map(link => `${link.option}: ${link.value}`).join(', '),
                ]),
            });
        }

        const fileMetadata = {
            name: `${user.profile.nickname || user.username}_resume.pdf`,
            mimeType: 'application/pdf',
        };
        const media = {
            mimeType: 'application/pdf',
            body: doc.output('stream'),
        };

        const response = await drive.files.create({
            resource: fileMetadata,
            media,
            fields: 'id, webViewLink',
        });

        // Track CV save event in Google Analytics
        try {
            await axios.post('https://www.google-analytics.com/mp/collect', {
                measurement_id: process.env.GOOGLE_ANALYTICS_ID,
                api_secret: process.env.GOOGLE_ANALYTICS_API_SECRET,
                events: [{
                    name: 'save_cv',
                    params: {
                        userId: req.user.userId,
                        timestamp: new Date().toISOString(),
                    },
                }],
            }, {
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000,
            });
            logger.info(`CV save tracked for user ${req.user.userId}`);
        } catch (analyticsError) {
            logger.error(`Failed to track CV save: ${analyticsError.message}`);
            Sentry.captureException(analyticsError);
        }

        res.json({
            message: 'CV saved to Google Drive',
            fileId: response.data.id,
            link: response.data.webViewLink,
        });
    } catch (error) {
        if (error.response?.status === 401) {
            return res.status(401).json({ error: 'Google access token expired. Please re-authenticate.' });
        }
        logger.error(`Error saving CV to Google Drive: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to save CV to Google Drive' });
    }
});


app.use((err, req, res, next) => {
    logger.error(`Unhandled error: ${err.stack}`);
    Sentry.captureException(err, { extra: { endpoint: req.originalUrl, method: req.method } });
    if (err.code === 'EBADCSRFTOKEN') {
        logger.warn(`Invalid CSRF token for ${req.originalUrl}`);
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    if (err.name === 'MongoError' && err.code === 11000) {
        return res.status(400).json({ error: 'Duplicate key error', details: err.message });
    }
    if (err.name === 'MulterError') {
        return res.status(400).json({ error: 'File upload error', details: err.message });
    }
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ error: 'Invalid JWT token', details: err.message });
    }
    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'JWT token expired', details: err.message });
    }
    res.status(500).json({ error: 'Internal server error', details: err.message });
});

async function generateAIContext(question = '') {
    const projects = await Project.find().select('title description image rating stars links');
    const skills = await Skill.find();
    return `
        Website: Ibrahim Al-Asfar's personal portfolio.
        Description: A full-stack web developer portfolio showcasing projects, skills, and contact information.
        Skills: ${skills.map(s => `${s.name} (${s.percentage}%)`).join(', ')}
        Projects: ${projects.map(p => `${p.title}: ${p.description} (Links: ${p.links.map(l => l.option).join(', ')})`).join('\n')}
        ${question}
    `;
}

async function sendNotification(userId, message) {
    try {
        const user = await User.findById(userId);
        if (!user) {
            logger.error('User not found for notification:', userId);
            return;
        }
        await transporter.sendMail({
            from: EMAIL_USER,
            to: user.email,
            subject: 'New Notification',
            text: message
        });
        user.notifications.push(message);
        await user.save();
        logger.info(`Notification sent to ${user.email}: ${message}`);
    } catch (error) {
        logger.error('Error sending notification:', error);
    }
}

async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        logger.warn(`No token provided for endpoint: ${req.originalUrl}`);
        Sentry.captureMessage('No token provided', { extra: { endpoint: req.originalUrl, method: req.method } });
        return res.status(401).json({ error: 'Token is required' });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = payload;
        Sentry.setUser({ id: payload.userId, email: payload.email });
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            const refreshToken = req.body.refreshToken || req.headers['x-refresh-token'] || req.cookies.refreshToken;
            if (!refreshToken) {
                logger.warn(`No refresh token provided for expired token at: ${req.originalUrl}`);
                Sentry.captureMessage('No refresh token provided for expired token', { extra: { endpoint: req.originalUrl, method: req.method } });
                return res.status(401).json({ error: 'Access token expired. Please provide a refresh token.' });
            }

            try {
                const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
                const user = await User.findOne({ _id: decoded.userId, 'refreshTokens.token': refreshToken });
                if (!user) {
                    logger.warn(`Invalid refresh token for user ${decoded.userId}`);
                    Sentry.captureMessage('Invalid refresh token', { extra: { endpoint: req.originalUrl, method: req.method } });
                    return res.status(403).json({ error: 'Invalid refresh token' });
                }

                const newToken = jwt.sign({ userId: user._id, isAdmin: user.isAdmin, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
                req.user = { userId: user._id, isAdmin: user.isAdmin, email: user.email };
                res.setHeader('X-New-Token', newToken);
                logger.info(`Token refreshed for user ${user._id}`);
                next();
            } catch (refreshError) {
                logger.error(`Failed to refresh token: ${refreshError.message}`);
                Sentry.captureException(refreshError, { extra: { endpoint: req.originalUrl, method: req.method } });
                return res.status(403).json({ error: 'Failed to refresh token' });
            }
        } else {
            logger.error(`Invalid token: ${error.message}`);
            Sentry.captureException(error, { extra: { endpoint: req.originalUrl, method: req.method } });
            return res.status(403).json({ error: 'Invalid token' });
        }
    }
}


app.get('/api/verify-token', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
        valid: true,
        userId: req.user.userId,
        isAdmin: req.user.isAdmin,
        username: user.username,
        profile: user.profile
    });
});

app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const refreshToken = req.body.refreshToken;
        if (refreshToken) {
            user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
            await user.save();
        }
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to logout: ' + error.message });
    }
});

app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        const fileUrl = req.file.path;
        if (req.file.mimetype.startsWith('image/')) {
            try {
                const image = sharp(req.file.buffer);
                const metadata = await image.metadata();
                if (!['png', 'jpeg'].includes(metadata.format)) {
                    return res.status(400).json({ error: 'Invalid image format. Only PNG and JPEG are allowed.' });
                }
            } catch (imageError) {
                logger.error(`Error validating image: ${imageError.message}`);
                Sentry.captureException(imageError);
                return res.status(400).json({ error: 'Invalid image file' });
            }
        }
        res.json({ message: `File uploaded successfully: ${fileUrl}` });
    } catch (error) {
        if (error instanceof multer.MulterError) {
            return res.status(400).json({ error: `Multer error: ${error.message}` });
        }
        logger.error(`Upload error: ${error.message}`);
        Sentry.captureException(error);
        res.status(400).json({ error: error.message || 'Failed to upload file' });
    }
});

app.post('/api/login', [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        if (user.isAdmin) {
            const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
            const refreshToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
            user.refreshTokens.push({ token: refreshToken });
            await user.save();
            logger.info(`Admin login: ${email} - Token issued without OTP`);
            return res.json({ token, refreshToken });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000;
        await user.save();
        try {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Your OTP Code',
                text: `Your OTP code is ${otp}. It is valid for 10 minutes.`
            });
            logger.info(`OTP sent to ${email}: ${otp}`);
            res.json({ message: 'OTP sent to your email' });
        } catch (mailError) {
            logger.error('Failed to send OTP email:', mailError);
            return res.status(500).json({ error: 'Failed to send OTP email' });
        }
    } catch (error) {
        logger.error(`Login error: ${error.message}`);
        res.status(500).json({ error: 'Login failed: ' + error.message });
    }
});


const resetPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many password reset attempts, please try again later.'
});
app.use('/api/reset-password', resetPasswordLimiter);
app.use('/api/forgot-password', resetPasswordLimiter);
const otpVerifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: 'Too many OTP verification attempts, please try again later.'
});
app.use('/api/login/verify-otp', otpVerifyLimiter);

app.post('/api/login/verify-otp', otpVerifyLimiter, async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid or expired OTP' });
        }
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        user.refreshTokens.push({ token: refreshToken });
        user.otp = null;
        user.otpExpires = null;
        await user.save();
        res.json({ token, refreshToken });
    } catch (error) {
        logger.error(`OTP verification error: ${error.message}`);
        res.status(500).json({ error: 'OTP verification failed' });
    }
});

app.post('/api/register', [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
    body('username').optional().isLength({ min: 3 }).withMessage('Username must be at least 3 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, email, password: hashedPassword });
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        user.refreshTokens.push({ token: jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' }) });
        await user.save();
        res.status(201).json({ token, refreshToken: user.refreshTokens[0].token });
    } catch (error) {
        logger.error(`Registration error: ${error.message}`);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/api/projects', async (req, res) => {
    try {
const projects = await Project.find().select('title description image rating stars links');
        res.json(projects);
    } catch (error) {
        logger.error(`Error fetching projects: ${error.message}`);
        Sentry.captureException(error, { extra: { endpoint: '/api/projects', method: 'GET' } });
        res.status(500).json({ error: 'Failed to fetch projects: ' + error.message });
    }
});

app.get('/api/projects/:userId', authenticateToken, async (req, res) => {
  try {
    const projects = await Project.find({ userId: req.params.userId })
      .select('title description image rating stars links');
    res.json(projects);
  } catch (error) {
    logger.error(`Error fetching projects for user ${req.params.userId}: ${error.message}`);
    Sentry.captureException(error);
    res.status(500).json({ error: 'Failed to fetch projects: ' + error.message });
  }
});

function isAdmin(req, res, next) {
    if (!req.user.isAdmin) {
        const error = new Error('Unauthorized: Admin access required');
        Sentry.captureException(error, {
            user: { id: req.user.userId, email: req.user.email },
            extra: { endpoint: req.originalUrl, method: req.method }
        });
        return res.sendStatus(403);
    }
    next();
}




app.post('/api/projects', authenticateToken, isAdmin, [
    body('title').notEmpty().withMessage('Title is required'),
    body('description').notEmpty().withMessage('Description is required'),
    body('image').isURL().withMessage('Image must be a valid URL'),
    body('rating').notEmpty().withMessage('Rating is required'),
    body('stars').isInt({ min: 0, max: 5 }).withMessage('Stars must be between 0 and 5'),
    body('links').isArray().withMessage('Links must be an array')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { title, description, image, rating, stars, links } = req.body;
    try {
        const project = new Project({ title, description, image, rating, stars, links });
        await project.save();
        res.status(201).json(project);
    } catch (error) {
        logger.error(`Error saving project: ${error.message}`);
        Sentry.captureException(error, { user: { id: req.user.userId, email: req.user.email }, extra: { endpoint: '/api/projects', method: 'POST' } });
        res.status(400).json({ error: 'Failed to save project: ' + error.message });
    }
});


app.put('/api/projects/:projectId', authenticateToken, isAdmin, [
    param('projectId').isMongoId().withMessage('Invalid project ID'),
    body('title').notEmpty().withMessage('Title is required'),
    body('description').notEmpty().withMessage('Description is required'),
    body('image').isURL().withMessage('Image must be a valid URL'),
    body('rating').notEmpty().withMessage('Rating is required'),
    body('stars').isInt({ min: 0, max: 5 }).withMessage('Stars must be between 0 and 5'),
    body('links').isArray().withMessage('Links must be an array')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { projectId } = req.params;
    const { title, description, image, rating, stars, links } = req.body;
    try {
        const project = await Project.findByIdAndUpdate(
            projectId,
            { title, description, image, rating, stars, links },
            { new: true, runValidators: true }
        );
        if (!project) {
            const error = new Error('Project not found');
            Sentry.captureException(error, { user: { id: req.user.userId, email: req.user.email }, extra: { endpoint: `/api/projects/${projectId}`, method: 'PUT' } });
            return res.status(404).json({ error: 'Project not found' });
        }
        res.json(project);
    } catch (error) {
        logger.error(`Error updating project ${projectId}: ${error.message}`);
        Sentry.captureException(error, { user: { id: req.user.userId, email: req.user.email }, extra: { endpoint: `/api/projects/${projectId}`, method: 'PUT' } });
        res.status(400).json({ error: 'Failed to update project: ' + error.message });
    }
});


app.delete('/api/projects/:projectId', authenticateToken, isAdmin, async (req, res) => {
    const { projectId } = req.params;
    try {
        await Project.findByIdAndDelete(projectId);
        await Comment.deleteMany({ projectId });
        res.sendStatus(204);
    } catch (error) {
        logger.error(`Error deleting project ${projectId}: ${error.message}`);
        Sentry.captureException(error, { user: { id: req.user.userId, email: req.user.email }, extra: { endpoint: `/api/projects/${projectId}`, method: 'DELETE' } });
        res.status(500).json({ error: 'Failed to delete project: ' + error.message });
    }
});


app.get('/api/comments/:projectId', async (req, res) => {
    try {
const comments = await Comment.find({ projectId: req.params.projectId })
    .populate('userId', 'username email')
    .select('projectId userId rating text timestamp replies');
        res.json(comments);
    } catch (error) {
        logger.error(`Error fetching comments for project ${req.params.projectId}: ${error.message}`);
        Sentry.captureException(error, { extra: { endpoint: `/api/comments/${req.params.projectId}`, method: 'GET' } });
        res.status(500).json({ error: 'Failed to fetch comments: ' + error.message });
    }
});


app.get('/api/notifications', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        res.json(user.notifications || []);
    } catch (error) {
        logger.error(`Error fetching notifications: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to fetch notifications: ' + error.message });
    }
});

app.get('/api/comments', authenticateToken, isAdmin, async (req, res) => {
    try {
        const comments = await Comment.find()
            .populate('userId', 'username email')
            .populate('projectId', 'title')
            .select('projectId userId rating text timestamp replies');
        const sanitizedComments = comments.map(comment => ({
            ...comment._doc,
            userId: comment.userId
                ? { username: comment.userId.username || 'Anonymous', email: comment.userId.email || '' }
                : { username: 'Anonymous', email: '' },
            projectTitle: comment.projectId ? comment.projectId.title : 'Unknown Project'
        }));
        res.json(sanitizedComments);
    } catch (error) {
        logger.error(`Error fetching comments: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to load comments: ' + error.message });
    }
});


app.post('/api/comments', authenticateToken, [
    body('projectId').isMongoId().withMessage('Invalid project ID'),
    body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5'),
    body('text').notEmpty().withMessage('Comment text is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { projectId, rating, text } = req.body;
    try {
        const comment = new Comment({ projectId, userId: req.user.userId, rating, text });
        await comment.save();
        await sendNotification(req.user.userId, `You commented on project ${projectId}: "${text}"`);
        res.status(201).json(comment);
    } catch (error) {
        logger.error(`Error saving comment: ${error.message}`);
        res.status(400).json({ error: 'Failed to save comment: ' + error.message });
    }
});

app.post('/api/comments/:commentId/reply', authenticateToken, isAdmin, [
    param('commentId').isMongoId().withMessage('Invalid comment ID'),
    body('text').notEmpty().withMessage('Reply text is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { commentId } = req.params;
    const { text } = req.body;
    try {
        const comment = await Comment.findByIdAndUpdate(
            commentId,
            { $push: { replies: { text, timestamp: new Date() } } },
            { new: true, runValidators: true }
        ).populate('userId', 'username email');
        if (!comment) return res.status(404).json({ error: 'Comment not found' });
        await sendNotification(comment.userId._id, `Admin replied to your comment: "${text}"`);
        res.json(comment);
    } catch (error) {
        logger.error(`Error adding reply to comment ${commentId}: ${error.message}`);
        Sentry.captureException(error);
        res.status(400).json({ error: 'Failed to add reply: ' + error.message });
    }
});


app.delete('/api/comments/:commentId', authenticateToken, isAdmin, async (req, res) => {
    const { commentId } = req.params;
    try {
        await Comment.findByIdAndDelete(commentId);
        res.sendStatus(204);
    } catch (error) {
        logger.error(`Error deleting comment ${commentId}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to delete comment: ' + error.message });
    }
});

app.get('/api/skills', async (req, res) => {
    const skills = await Skill.find();
    res.json(skills);
});

app.post('/api/skills', authenticateToken, isAdmin, [
    body('name').notEmpty().withMessage('Skill name is required'),
    body('icon').isURL().withMessage('Icon must be a valid URL'),
    body('percentage').isInt({ min: 0, max: 100 }).withMessage('Percentage must be between 0 and 100')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { name, icon, percentage } = req.body;
    try {
        const skill = new Skill({ name, icon, percentage });
        await skill.save();
        res.status(201).json(skill);
    } catch (error) {
        logger.error(`Error saving skill: ${error.message}`);
        Sentry.captureException(error);
        res.status(400).json({ error: 'Failed to save skill: ' + error.message });
    }
});

app.put('/api/skills/:skillId', authenticateToken, isAdmin, [
    param('skillId').isMongoId().withMessage('Invalid skill ID'),
    body('name').notEmpty().withMessage('Skill name is required'),
    body('icon').isURL().withMessage('Icon must be a valid URL'),
    body('percentage').isInt({ min: 0, max: 100 }).withMessage('Percentage must be between 0 and 100')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { skillId } = req.params;
    const { name, icon, percentage } = req.body;
    try {
        const skill = await Skill.findByIdAndUpdate(
            skillId,
            { name, icon, percentage },
            { new: true, runValidators: true }
        );
        if (!skill) return res.status(404).json({ error: 'Skill not found' });
        res.json(skill);
    } catch (error) {
        logger.error(`Error updating skill ${skillId}: ${error.message}`);
        Sentry.captureException(error);
        res.status(400).json({ error: 'Failed to update skill: ' + error.message });
    }
});

app.delete('/api/skills/:skillId', authenticateToken, isAdmin, async (req, res) => {
    const { skillId } = req.params;
    try {
        await Skill.findByIdAndDelete(skillId);
        res.sendStatus(204);
    } catch (error) {
        logger.error(`Error deleting skill ${skillId}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to delete skill: ' + error.message });
    }
});



app.get('/api/profile/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('username profile');
        if (!user) {
            logger.warn(`User not found: ${req.user.userId}`);
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }

        // إعداد الملف الشخصي الافتراضي
        const profile = user.profile || {
            portfolioName: 'Portfolio',
            nickname: '',
            jobTitle: '',
            bio: '',
            phone: '',
            isPublic: false,
            socialLinks: { linkedin: '', behance: '', github: '', whatsapp: '' },
            avatar: '',
            avatarDisplayType: 'normal',
            svgColor: '#000000',
            pdfFormat: 'jspdf',
            education: [],
            experience: [],
            certificates: [],
            skills: [],
            projects: [],
            interests: []
        };

        // إزالة التحقق من الشفافية لأن الـ frontend مش بيستخدمها
        res.json({
            username: user.username,
            profile
        });
    } catch (error) {
        logger.error(`Error fetching profile for user ${req.user.userId}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'خطأ في استرجاع الملف الشخصي' });
    }
});


app.get('/api/profile/:nickname', async (req, res) => {
    try {
        const decodedNickname = decodeURIComponent(req.params.nickname);
        const user = await User.findOne({
            $or: [
                { 'profile.nickname': { $regex: `^${decodedNickname}$`, $options: 'i' } }, // Case-insensitive
                { username: { $regex: `^${decodedNickname}$`, $options: 'i' } },
            ],
        }).select('username profile notifications');

        if (!user) {
            logger.warn(`Profile not found for nickname: ${decodedNickname}`);
            return res.status(404).json({ error: `Profile not found for ${decodedNickname}` });
        }

        // Check privacy settings
        if (!user.profile.isPublic && (!req.user || req.user.userId !== user._id.toString())) {
            logger.warn(`Unauthorized access attempt to private profile: ${decodedNickname} by user: ${req.user?.userId || 'anonymous'}`);
            return res.status(403).json({ error: 'Profile is private', loginRequired: true });
        }

        // Track profile view with Google Analytics
        if (process.env.GOOGLE_ANALYTICS_ID && process.env.GOOGLE_ANALYTICS_API_SECRET) {
            try {
                await axios.post('https://www.google-analytics.com/mp/collect', {
                    measurement_id: process.env.GOOGLE_ANALYTICS_ID,
                    api_secret: process.env.GOOGLE_ANALYTICS_API_SECRET,
                    events: [{
                        name: 'view_profile',
                        params: {
                            nickname: decodedNickname,
                            userId: req.user?.userId || 'anonymous',
                            timestamp: new Date().toISOString(),
                        },
                    }],
                }, {
                    headers: { 'Content-Type': 'application/json' },
                    timeout: 5000,
                });
                logger.info(`Profile view tracked for ${decodedNickname}`);
            } catch (analyticsError) {
                logger.error(`Failed to track profile view for ${decodedNickname}: ${analyticsError.message}`);
                Sentry.captureException(analyticsError);
            }
        }

        // Send push notification to profile owner
        if (user.notifications?.length > 0 && req.user?.userId !== user._id.toString()) {
            try {
                const subscription = user.notifications[0];
                // Validate subscription object
                if (subscription.endpoint && subscription.keys?.p256dh && subscription.keys?.auth) {
                    const payload = JSON.stringify({
                        title: 'Profile Viewed',
                        body: `Your profile (${decodedNickname}) was viewed by ${req.user?.username || 'an anonymous user'}.`,
                    });
                    await webpush.sendNotification(subscription, payload);
                    logger.info(`Push notification sent to ${user._id} for profile view`);
                }
            } catch (pushError) {
                logger.error(`Failed to send push notification: ${pushError.message}`);
                Sentry.captureException(pushError);
            }
        }

        // Prepare response
        const response = {
            username: user.username,
            profile: {
                nickname: user.profile.nickname || user.username,
                portfolioName: user.profile.portfolioName || 'Portfolio',
                avatar: user.profile.avatar || '/assets/img/default-avatar.png',
                avatarDisplayType: user.profile.avatarDisplayType || 'normal',
                svgColor: user.profile.svgColor || '#000000',
                jobTitle: user.profile.jobTitle || '',
                bio: user.profile.bio || '',
                phone: user.profile.phone || '',
                socialLinks: user.profile.socialLinks || {},
                education: user.profile.education || [],
                experience: user.profile.experience || [],
                certificates: user.profile.certificates || [],
                interests: user.profile.interests || [],
                skills: user.profile.skills || [],
                projects: user.profile.projects || [],
                pdfFormat: user.profile.pdfFormat || 'jspdf',
                isPublic: user.profile.isPublic ?? true,
                status: user.profile.status || 'Available',
            },
        };

        res.json(response);
    } catch (error) {
        logger.error(`Error fetching profile for ${req.params.nickname}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: `Failed to fetch profile: ${error.message}` });
    }
});



const googleLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many Google API requests, please try again later.'
});
app.use('/api/google', googleLimiter);




app.get('/api/check-nickname', authenticateToken, [
    body('nickname').isLength({ min: 3 }).withMessage('Nickname must be at least 3 characters long'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { nickname } = req.query;
        if (!nickname) {
            return res.status(400).json({ error: 'Nickname is required' });
        }
        const user = await User.findOne({ 
            'profile.nickname': { $regex: `^${nickname}$`, $options: 'i' }, 
            _id: { $ne: req.user.userId } 
        });
        res.json({ available: !user });
    } catch (error) {
        logger.error(`Error checking nickname: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to check nickname' });
    }
});

app.put('/api/profile', authenticateToken, upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'projectImages', maxCount: 10 },
]), [
    body('nickname').optional().isLength({ min: 3 }).withMessage('Nickname must be at least 3 characters long'),
    body('jobTitle').optional().notEmpty().withMessage('Job title cannot be empty'),
    body('bio').optional().notEmpty().withMessage('Bio cannot be empty'),
    body('phone').optional().isMobilePhone().withMessage('Invalid phone number'),
    body('socialLinks').optional().custom(value => {
        try {
            const parsed = JSON.parse(value);
            const validKeys = ['linkedin', 'behance', 'github', 'whatsapp'];
            for (const key in parsed) {
                if (!validKeys.includes(key)) return false;
                if (parsed[key] && !/^https?:\/\/[^\s/$.?#].[^\s]*$/.test(parsed[key])) return false;
            }
            return true;
        } catch {
            return false;
        }
    }).withMessage('Invalid social links format or URLs'),
    body('education').optional().custom(value => {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) && parsed.every(item => item.institution && item.degree && item.year && !isNaN(parseInt(item.year)) && parseInt(item.year) >= 1900 && parseInt(item.year) <= new Date().getFullYear());
        } catch {
            return false;
        }
    }).withMessage('Invalid education format'),
    body('experience').optional().custom(value => {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) && parsed.every(item => item.company && item.role && item.duration);
        } catch {
            return false;
        }
    }).withMessage('Invalid experience format'),
    body('certificates').optional().custom(value => {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) && parsed.every(item => item.name && item.issuer && item.year && !isNaN(parseInt(item.year)) && parseInt(item.year) >= 1900 && parseInt(item.year) <= new Date().getFullYear());
        } catch {
            return false;
        }
    }).withMessage('Invalid certificates format'),
    body('skills').optional().custom(value => {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) && parsed.every(item => item.name && typeof item.percentage === 'number' && item.percentage >= 0 && item.percentage <= 100);
        } catch {
            return false;
        }
    }).withMessage('Invalid skills format'),
    body('projects').optional().custom(value => {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) && parsed.every(item => item.title && item.description && (!item.image || /^https?:\/\/[^\s/$.?#].[^\s]*$/.test(item.image)));
        } catch {
            return false;
        }
    }).withMessage('Invalid projects format'),
    body('interests').optional().custom(value => {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) && parsed.every(item => typeof item === 'string');
        } catch {
            return false;
        }
    }).withMessage('Invalid interests format'),
    body('isPublic').optional().isBoolean().withMessage('isPublic must be a boolean'),
    body('avatarDisplayType').optional().isIn(['svg', 'normal']).withMessage('Invalid avatar display type'),
    body('svgColor').optional().matches(/^#[0-9A-Fa-f]{6}$/).withMessage('Invalid SVG color format'),
    body('githubProjectIds').optional().custom(value => {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) && parsed.every(id => Number.isInteger(Number(id)));
        } catch {
            return false;
        }
    }).withMessage('Invalid GitHub project IDs format'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const {
            nickname, jobTitle, bio, phone, socialLinks, education, experience,
            certificates, skills, projects, interests, isPublic, avatarDisplayType,
            svgColor, status, portfolioName, pdfFormat
        } = req.body;

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // التحقق من توفر الـ nickname إذا تم إرساله
        if (nickname && nickname !== user.profile.nickname) {
            const existingUser = await User.findOne({ 'profile.nickname': nickname, _id: { $ne: user._id } });
            if (existingUser) {
                return res.status(400).json({ error: 'Nickname already taken' });
            }
        }

        const parseJSON = (str, defaultValue) => {
            try {
                return str ? JSON.parse(str) : defaultValue;
            } catch (error) {
                logger.error(`Invalid JSON for ${str}: ${error.message}`);
                Sentry.captureException(error);
                return defaultValue;
            }
        };

        // Parse input fields
        const parsedSocialLinks = parseJSON(socialLinks, user.profile.socialLinks);
        const parsedEducation = parseJSON(education, user.profile.education);
        const parsedExperience = parseJSON(experience, user.profile.experience);
        const parsedCertificates = parseJSON(certificates, user.profile.certificates);
        const parsedSkills = parseJSON(skills, user.profile.skills);
        let parsedProjects = parseJSON(projects, user.profile.projects);
        const parsedInterests = parseJSON(interests, user.profile.interests);
        const parsedGithubProjectIds = parseJSON(githubProjectIds, []);

        // Handle avatar image with transparency check
        let hasTransparency = false;
        if (req.files && req.files.avatar) {
            try {
                const imageBuffer = req.files.avatar[0].buffer;
                const image = sharp(imageBuffer);
                const metadata = await image.metadata();
                hasTransparency = metadata.hasAlpha || false;
                const uploadResult = await cloudinary.uploader.upload_stream({ folder: 'avatars' }).end(imageBuffer);
                user.profile.avatar = uploadResult.secure_url;
            } catch (imageError) {
                logger.error(`Error processing avatar image: ${imageError.message}`);
                Sentry.captureException(imageError);
            }
        }

        // Handle project images
        if (req.files && req.files.projectImages) {
            parsedProjects = await Promise.all(parsedProjects.map(async (project, index) => {
                if (req.files.projectImages[index]) {
                    try {
                        const imageBuffer = req.files.projectImages[index].buffer;
                        const uploadResult = await cloudinary.uploader.upload_stream({ folder: 'projects' }).end(imageBuffer);
                        return { ...project, image: uploadResult.secure_url };
                    } catch (imageError) {
                        logger.error(`Error processing project image ${index}: ${imageError.message}`);
                        Sentry.captureException(imageError);
                        return project;
                    }
                }
                return project;
            }));
        }

        // Fetch GitHub projects if githubProjectIds are provided
        if (parsedGithubProjectIds.length > 0 && user.githubAccessToken) {
            try {
                for (const githubProjectId of parsedGithubProjectIds) {
                    if (!Number.isInteger(Number(githubProjectId))) {
                        throw new Error(`Invalid GitHub project ID: ${githubProjectId}`);
                    }
                    const response = await axios.get(`https://api.github.com/repositories/${githubProjectId}`, {
                        headers: { Authorization: `Bearer ${user.githubAccessToken}` },
                    });
                    if (response.status === 401) {
                        return res.status(401).json({ error: 'GitHub access token expired. Please re-authenticate.' });
                    }
                    const repo = response.data;
                    parsedProjects.push({
                        title: repo.name,
                        description: repo.description || 'No description provided',
                        image: req.files.projectImages && req.files.projectImages[parsedProjects.length]
                            ? (await cloudinary.uploader.upload_stream({ folder: 'projects' }).end(req.files.projectImages[parsedProjects.length].buffer)).secure_url
                            : repo.owner.avatar_url,
                        links: [{ option: 'GitHub', value: repo.html_url }],
                    });
                }
            } catch (githubError) {
                logger.error(`Error fetching GitHub project: ${githubError.message}`);
                Sentry.captureException(githubError);
                return res.status(400).json({ error: `Failed to fetch GitHub project: ${githubError.message}` });
            }
        }

        // Update user profile
        user.profile = {
            nickname: nickname || user.profile.nickname,
            avatar: user.profile.avatar || undefined,
            jobTitle: jobTitle || user.profile.jobTitle,
            bio: bio || user.profile.bio,
            phone: phone || user.profile.phone,
            socialLinks: parsedSocialLinks,
            education: parsedEducation,
            experience: parsedExperience,
            certificates: parsedCertificates,
            skills: parsedSkills,
            projects: parsedProjects,
            interests: parsedInterests,
            isPublic: isPublic !== undefined ? isPublic === 'true' : user.profile.isPublic,
            avatarDisplayType: avatarDisplayType || user.profile.avatarDisplayType,
            svgColor: svgColor || user.profile.svgColor,
            customFields: parseJSON(req.body.customFields, user.profile.customFields || []),
            portfolioName: portfolioName || user.profile.portfolioName || 'Portfolio',
            status: status || user.profile.status || 'Available',
            pdfFormat: pdfFormat || user.profile.pdfFormat || 'jspdf'
        };

        await user.save();

        // Track profile update in Google Analytics
        try {
            await axios.post('https://www.google-analytics.com/mp/collect', {
                measurement_id: process.env.GOOGLE_ANALYTICS_ID,
                api_secret: process.env.GOOGLE_ANALYTICS_API_SECRET,
                events: [{
                    name: 'update_profile',
                    params: {
                        userId: req.user.userId,
                        updatedFields: Object.keys(req.body),
                        timestamp: new Date().toISOString(),
                    },
                }],
            }, {
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000,
            });
            logger.info(`Profile update tracked for user ${req.user.userId}`);
        } catch (analyticsError) {
            logger.error(`Failed to track profile update: ${analyticsError.message}`);
            Sentry.captureException(analyticsError);
        }

        res.json({
            success: true,
            message: 'Profile updated successfully',
            profile: user.profile,
            hasTransparency,
        });
    } catch (error) {
        logger.error(`Error updating profile for user ${req.user.userId}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: `Failed to update profile: ${error.message}` });
    }
});


cron.schedule('0 0 * * *', async () => {
    try {
        const users = await User.find({ githubAccessToken: { $exists: true } });
        for (const user of users) {
            const hasGitHubProjects = user.profile.projects.some(project =>
                project.links.some(link => link.option === 'GitHub')
            );
            if (!hasGitHubProjects) continue;

            try {
                const response = await axios.get('https://api.github.com/user/repos', {
                    headers: { Authorization: `Bearer ${user.githubAccessToken}` },
                });
                if (response.status === 401) {
                    logger.warn(`GitHub token expired for user ${user.email}`);
                    continue;
                }
                const repos = response.data;

                user.profile.projects = user.profile.projects.map(project => {
                    const repo = repos.find(r => r.html_url === project.links.find(l => l.option === 'GitHub')?.value);
                    if (repo) {
                        return {
                            ...project,
                            title: repo.name,
                            description: repo.description || project.description,
                            image: project.image || repo.owner.avatar_url,
                        };
                    }
                    return project;
                });

                await user.save();
                logger.info(`Synced GitHub projects for user ${user.email}`);
            } catch (error) {
                if (error.response?.status === 401) {
                    logger.warn(`GitHub token expired for user ${user.email}`);
                    continue;
                }
                logger.error(`Error syncing GitHub projects for user ${user.email}: ${error.message}`);
                Sentry.captureException(error);
            }
        }
    } catch (error) {
        logger.error(`Error in cron job: ${error.message}`);
        Sentry.captureException(error);
    }
});


const githubLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many GitHub API requests, please try again later.'
});
app.use('/api/github', githubLimiter);


app.get('/api/user-interactions', authenticateToken, async (req, res) => {
    try {
        const comments = await Comment.find({ userId: req.user.userId })
            .populate('projectId', 'title');
        res.json(comments);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch interactions: ' + error.message });
    }
});

app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find({}, 'username email profile');
        res.json(users);
    } catch (error) {
        logger.error(`Error fetching users: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to fetch users: ' + error.message });
    }
});

app.delete('/api/users/:userId', authenticateToken, isAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.userId);
        await Comment.deleteMany({ userId: req.params.userId });
        res.sendStatus(204);
    } catch (error) {
        logger.error(`Error deleting user ${req.params.userId}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to delete user: ' + error.message });
    }
});

app.get('/api/profile/pdf/:nickname', authenticateToken, async (req, res) => {
    try {
        const decodedNickname = decodeURIComponent(req.params.nickname);
        const user = await User.findOne({
            $or: [
                { 'profile.nickname': decodedNickname },
                { username: decodedNickname },
            ],
        });

        if (!user) {
            logger.warn(`Profile not found for nickname: ${decodedNickname}`);
            return res.status(404).json({ error: `Profile not found for nickname: ${decodedNickname}` });
        }

        if (!user.profile.isPublic && (!req.user || req.user.userId !== user._id.toString())) {
            logger.warn(`Unauthorized access attempt to private profile: ${decodedNickname} by user: ${req.user?.userId || 'anonymous'}`);
            return res.status(403).json({ error: 'Profile is private', loginRequired: true });
        }

        const doc = new jsPDF();
        doc.setFontSize(20);
        doc.text(user.profile.nickname || user.username, 10, 20);
        doc.setFontSize(12);
        doc.text('Portfolio Resume', 10, 30, { align: 'center' });

        // Add avatar image
        if (user.profile.avatar) {
            try {
                const imageResponse = await axios.get(user.profile.avatar, { responseType: 'arraybuffer' });
                const image = sharp(Buffer.from(imageResponse.data));
                const metadata = await image.metadata();
                if (metadata.format && ['png', 'jpeg'].includes(metadata.format)) {
                    const imageBase64 = Buffer.from(imageResponse.data).toString('base64');
                    doc.addImage(imageBase64, 'PNG', 10, 30, 30, 30);
                } else {
                    logger.warn(`Invalid image format for avatar: ${user.profile.avatar}`);
                }
            } catch (imageError) {
                logger.error(`Failed to load avatar for PDF: ${imageError.message}`);
                Sentry.captureException(imageError);
            }
        }

        // Personal Information
        doc.autoTable({
            startY: 60,
            head: [['Personal Information']],
            body: [
                ['Job Title', user.profile.jobTitle || 'Not specified'],
                ['Bio', user.profile.bio || 'Not specified'],
                ['Phone', user.profile.phone || 'Not specified'],
            ],
            theme: 'striped',
            styles: { fontSize: 10, overflow: 'linebreak' },
            columnStyles: { 0: { cellWidth: 50 }, 1: { cellWidth: 130 } },
        });

        // Social Links
        doc.autoTable({
            startY: doc.lastAutoTable.finalY + 10,
            head: [['Social Links']],
            body: [
                ['LinkedIn', user.profile.socialLinks.linkedin || 'Not specified'],
                ['Behance', user.profile.socialLinks.behance || 'Not specified'],
                ['GitHub', user.profile.socialLinks.github || 'Not specified'],
                ['WhatsApp', user.profile.socialLinks.whatsapp || 'Not specified'],
            ],
            theme: 'striped',
            styles: { fontSize: 10 },
            columnStyles: { 0: { cellWidth: 50 }, 1: { cellWidth: 130 } },
        });

        // Education
        const educationData = user.profile.education.slice(0, 50).map(edu => [
            edu.degree || 'Not specified',
            edu.institution || 'Not specified',
            edu.year || 'Not specified',
        ]);
        if (educationData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Education', 'Institution', 'Year']],
                body: educationData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 80 }, 2: { cellWidth: 40 } },
            });
        }

        // Experience
        const experienceData = user.profile.experience.slice(0, 50).map(exp => [
            exp.role || 'Not specified',
            exp.company || 'Not specified',
            exp.duration || 'Not specified',
        ]);
        if (experienceData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Role', 'Company', 'Duration']],
                body: experienceData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 80 }, 2: { cellWidth: 40 } },
            });
        }

        // Certificates
        const certificateData = user.profile.certificates.slice(0, 50).map(cert => [
            cert.name || 'Not specified',
            cert.issuer || 'Not specified',
            cert.year || 'Not specified',
        ]);
        if (certificateData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Certificate', 'Issuer', 'Year']],
                body: certificateData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 80 }, 2: { cellWidth: 40 } },
            });
        }

        // Skills
        const skillData = user.profile.skills.slice(0, 50).map(skill => [
            skill.name || 'Not specified',
            `${skill.percentage}%` || '0%',
        ]);
        if (skillData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Skill', 'Proficiency']],
                body: skillData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 100 }, 1: { cellWidth: 80 } },
            });
        }

        // Projects
        const projectData = user.profile.projects.slice(0, 50).map(project => [
            project.title || 'Not specified',
            project.description || 'Not specified',
        ]);
        if (projectData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Project Title', 'Description']],
                body: projectData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 120 } },
            });
        }

        // Interests
        const interestData = user.profile.interests.slice(0, 50).map(interest => [interest || 'Not specified']);
        if (interestData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Interests']],
                body: interestData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 180 } },
            });
        }

        // Footer
        doc.setFontSize(8);
        doc.text(`Generated on ${new Date().toLocaleDateString()}`, 10, doc.internal.pageSize.height - 10);

        // Track CV download in Google Analytics
        try {
            await axios.post('https://www.google-analytics.com/mp/collect', {
                measurement_id: process.env.GOOGLE_ANALYTICS_ID,
                api_secret: process.env.GOOGLE_ANALYTICS_API_SECRET,
                events: [{
                    name: 'download_cv',
                    params: {
                        nickname: decodedNickname,
                        userId: req.user?.userId || 'anonymous',
                        timestamp: new Date().toISOString(),
                    },
                }],
            }, {
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000,
            });
            logger.info(`CV download tracked for ${decodedNickname}`);
        } catch (analyticsError) {
            logger.error(`Failed to track CV download: ${analyticsError.message}`);
            Sentry.captureException(analyticsError);
        }

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${(user.profile.nickname || user.username).replace(/[^a-zA-Z0-9]/g, '_')}_resume.pdf`);
        res.send(doc.output());
    } catch (error) {
        logger.error(`Error generating PDF for ${req.params.nickname}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to generate PDF: ' + error.message });
    }
});



const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType } = require('docx');

app.get('/api/profile/docx/:nickname', authenticateToken, async (req, res) => {
    try {
        const decodedNickname = decodeURIComponent(req.params.nickname);
        const user = await User.findOne({
            $or: [
                { 'profile.nickname': decodedNickname },
                { username: decodedNickname },
            ],
        });

        if (!user) {
            logger.warn(`Profile not found for nickname: ${decodedNickname}`);
            return res.status(404).json({ error: `Profile not found for nickname: ${decodedNickname}` });
        }

        if (!user.profile.isPublic && (!req.user || req.user.userId !== user._id.toString())) {
            logger.warn(`Unauthorized access attempt to private profile: ${decodedNickname} by user: ${req.user?.userId || 'anonymous'}`);
            return res.status(403).json({ error: 'Profile is private', loginRequired: true });
        }

        const doc = new Document({
            sections: [{
                properties: {},
                children: [
                    new Paragraph({
                        children: [
                            new TextRun({
                                text: user.profile.nickname || user.username,
                                bold: true,
                                size: 40,
                            }),
                        ],
                    }),
                    new Paragraph({
                        children: [
                            new TextRun({
                                text: user.profile.jobTitle || 'Not specified',
                                size: 28,
                            }),
                        ],
                    }),
                    new Paragraph({ text: '' }), // Spacer
                    user.profile.bio ? new Paragraph({
                        children: [new TextRun({ text: 'Bio:', bold: true, size: 24 })],
                    }) : null,
                    user.profile.bio ? new Paragraph({
                        children: [new TextRun({ text: user.profile.bio, size: 20 })],
                    }) : null,
                    new Paragraph({ text: '' }),
                    new Paragraph({
                        children: [new TextRun({ text: 'Contact:', bold: true, size: 24 })],
                    }),
                    user.profile.phone ? new Paragraph({
                        children: [new TextRun({ text: `Phone: ${user.profile.phone}`, size: 20 })],
                    }) : null,
                    ...Object.keys(user.profile.socialLinks).map(key => user.profile.socialLinks[key] ? new Paragraph({
                        children: [new TextRun({ text: `${key}: ${user.profile.socialLinks[key]}`, size: 20 })],
                    }) : null),
                    new Paragraph({ text: '' }),
                    // Education
                    user.profile.education.length > 0 ? new Paragraph({
                        children: [new TextRun({ text: 'Education:', bold: true, size: 24 })],
                    }) : null,
                    user.profile.education.length > 0 ? new Table({
                        width: { size: 100, type: WidthType.PERCENTAGE },
                        rows: [
                            new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph('Institution')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Degree')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Year')], margins: { top: 100, bottom: 100 } }),
                                ],
                            }),
                            ...user.profile.education.slice(0, 50).map(edu => new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph(edu.institution || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(edu.degree || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(edu.year || 'Not specified')] }),
                                ],
                            })),
                        ],
                    }) : null,
                    // Experience
                    user.profile.experience.length > 0 ? new Paragraph({
                        children: [new TextRun({ text: 'Experience:', bold: true, size: 24 })],
                    }) : null,
                    user.profile.experience.length > 0 ? new Table({
                        width: { size: 100, type: WidthType.PERCENTAGE },
                        rows: [
                            new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph('Role')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Company')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Duration')], margins: { top: 100, bottom: 100 } }),
                                ],
                            }),
                            ...user.profile.experience.slice(0, 50).map(exp => new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph(exp.role || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(exp.company || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(exp.duration || 'Not specified')] }),
                                ],
                            })),
                        ],
                    }) : null,
                    // Certificates
                    user.profile.certificates.length > 0 ? new Paragraph({
                        children: [new TextRun({ text: 'Certificates:', bold: true, size: 24 })],
                    }) : null,
                    user.profile.certificates.length > 0 ? new Table({
                        width: { size: 100, type: WidthType.PERCENTAGE },
                        rows: [
                            new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph('Name')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Issuer')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Year')], margins: { top: 100, bottom: 100 } }),
                                ],
                            }),
                            ...user.profile.certificates.slice(0, 50).map(cert => new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph(cert.name || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(cert.issuer || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(cert.year || 'Not specified')] }),
                                ],
                            })),
                        ],
                    }) : null,
                    // Skills
                    user.profile.skills.length > 0 ? new Paragraph({
                        children: [new TextRun({ text: 'Skills:', bold: true, size: 24 })],
                    }) : null,
                    user.profile.skills.length > 0 ? new Table({
                        width: { size: 100, type: WidthType.PERCENTAGE },
                        rows: [
                            new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph('Skill')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Proficiency')], margins: { top: 100, bottom: 100 } }),
                                ],
                            }),
                            ...user.profile.skills.slice(0, 50).map(skill => new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph(skill.name || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(`${skill.percentage}%` || '0%')] }),
                                ],
                            })),
                        ],
                    }) : null,
                    // Projects
                    user.profile.projects.length > 0 ? new Paragraph({
                        children: [new TextRun({ text: 'Projects:', bold: true, size: 24 })],
                    }) : null,
                    user.profile.projects.length > 0 ? new Table({
                        width: { size: 100, type: WidthType.PERCENTAGE },
                        rows: [
                            new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph('Title')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Description')], margins: { top: 100, bottom: 100 } }),
                                    new TableCell({ children: [new Paragraph('Links')], margins: { top: 100, bottom: 100 } }),
                                ],
                            }),
                            ...user.profile.projects.slice(0, 50).map(proj => new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph(proj.title || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(proj.description || 'Not specified')] }),
                                    new TableCell({ children: [new Paragraph(proj.links?.map(link => `${link.option}: ${link.value}`).join(', ') || 'Not specified')] }),
                                ],
                            })),
                        ],
                    }) : null,
                    // Interests
                    user.profile.interests.length > 0 ? new Paragraph({
                        children: [new TextRun({ text: 'Interests:', bold: true, size: 24 })],
                    }) : null,
                    user.profile.interests.length > 0 ? new Table({
                        width: { size: 100, type: WidthType.PERCENTAGE },
                        rows: [
                            new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph('Interests')], margins: { top: 100, bottom: 100 } }),
                                ],
                            }),
                            ...user.profile.interests.slice(0, 50).map(interest => new TableRow({
                                children: [
                                    new TableCell({ children: [new Paragraph(interest || 'Not specified')] }),
                                ],
                            })),
                        ],
                    }) : null,
                ].filter(Boolean),
            }],
        });

        const buffer = await Packer.toBuffer(doc);

        // Track CV download in Google Analytics
        try {
            await axios.post('https://www.google-analytics.com/mp/collect', {
                measurement_id: process.env.GOOGLE_ANALYTICS_ID,
                api_secret: process.env.GOOGLE_ANALYTICS_API_SECRET,
                events: [{
                    name: 'download_cv_docx',
                    params: {
                        nickname: decodedNickname,
                        userId: req.user?.userId || 'anonymous',
                        timestamp: new Date().toISOString(),
                    },
                }],
            }, {
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000,
            });
            logger.info(`DOCX CV download tracked for ${decodedNickname}`);
        } catch (analyticsError) {
            logger.error(`Failed to track DOCX CV download: ${analyticsError.message}`);
            Sentry.captureException(analyticsError);
        }

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        res.setHeader('Content-Disposition', `attachment; filename=${(user.profile.nickname || user.username).replace(/[^a-zA-Z0-9]/g, '_')}_resume.docx`);
        res.send(buffer);
    } catch (error) {
        logger.error(`Error generating DOCX for ${req.params.nickname}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to generate DOCX: ' + error.message });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000;
        await user.save();
        try {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset OTP',
                text: `Your OTP code for password reset is ${otp}. It is valid for 10 minutes.`
            });
            logger.info(`Password reset OTP sent to ${email}: ${otp}`);
            res.json({ message: 'Reset code sent to your email' });
        } catch (mailError) {
            logger.error(`Failed to send password reset OTP to ${email}: ${mailError.message}`);
            return res.status(500).json({ error: 'Failed to send reset code' });
        }
    } catch (error) {
        logger.error(`Forgot password error for ${email}: ${error.message}`);
        res.status(500).json({ error: 'Failed to process forgot password request' });
    }
});

app.post('/api/reset-password', [
    body('email').isEmail().withMessage('Invalid email format'),
    body('otp').notEmpty().withMessage('OTP is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, otp, newPassword } = req.body;
    try {
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null;
        user.otpExpires = null;
        await user.save();
        logger.info(`Password reset successfully for ${email}`);
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        logger.error(`Reset password error for ${email}: ${error.message}`);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

app.get('/api/health', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      throw new Error('MongoDB is not connected');
    }
    await mongoose.connection.db.admin().ping();
    const services = {
      status: 'ok',
      mongodb: 'connected',
      cloudinary: cloudinary.config().cloud_name ? 'configured' : 'not configured',
      sentry: process.env.SENTRY_DSN ? 'configured' : 'not configured',
      timestamp: new Date()
    };
    res.json(services);
  } catch (error) {
    logger.error(`Health check error: ${error.message}`);
    Sentry.captureException(error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});


app.post('/api/subscribe', authenticateToken, async (req, res) => {
    try {
        const subscription = req.body;
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        user.notifications.push(subscription);
        await user.save();
        res.status(201).json({ message: 'Subscription saved' });
    } catch (error) {
        logger.error(`Error saving subscription: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to save subscription' });
    }
});

app.get('/api/users/search', async (req, res) => {
    const { query } = req.query;
    try {
        const users = await User.find({
            $or: [
                { 'profile.nickname': { $regex: query, $options: 'i' } },
                { username: { $regex: query, $options: 'i' } }
            ],
            'profile.isPublic': true
        }, 'username profile.nickname profile.avatar profile.portfolioName');
        res.json(users.map(user => ({
            username: user.username,
            nickname: user.profile.nickname,
            avatar: user.profile.avatar,
            profileUrl: `/profile/${user.profile.nickname || user.username}`,
            portfolioName: user.profile.portfolioName
        })));
    } catch (error) {
        logger.error(`Search error: ${error.message}`);
        res.status(500).json({ error: 'Failed to search users' });
    }
});

app.post('/api/ask', [
    body('question').notEmpty().withMessage('Question is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { question } = req.body;
    try {
        const context = await generateAIContext(`Question: ${question}`);
        const response = await axios.post(
            `${AI_API_URL}/api/ask`,
            { question: context },
            { headers: { 'Content-Type': 'application/json' } }
        );
        res.json({ answer: response.data.answer || 'Sorry, I could not generate an answer.' });
    } catch (error) {
        logger.error('Error processing question:', error.message);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to process question: ' + error.message });
    }
});

app.post('/api/chat', [
    body('message').notEmpty().withMessage('Message is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { message } = req.body;
    try {
        const context = await generateAIContext(`User message: ${message}`);
        const response = await axios.post(
            `${AI_API_URL}/api/ask`,
            { question: context },
            { headers: { 'Content-Type': 'application/json' } }
        );
        res.json({ reply: response.data.answer || 'Sorry, I could not generate a response.' });
    } catch (error) {
        logger.error('Error processing chat:', error.message);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Something went wrong' });
    }
});

const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many registration attempts, please try again later.'
});
app.use('/api/register', registerLimiter);

const commentLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many comment attempts, please try again later.'
});
app.use('/api/comments', commentLimiter);

const converseLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many chat attempts, please try again later.'
});
app.use('/api/converse', converseLimiter);

app.post('/api/converse', authenticateToken, [
    body('messages').isArray({ min: 1 }).withMessage('Messages must be a non-empty array'),
    body('messages.*.role').isIn(['user', 'assistant']).withMessage('Message role must be either user or assistant'),
    body('messages.*.content').notEmpty().withMessage('Message content is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { messages } = req.body;
    try {
        const MAX_CONVERSATIONS_PER_USER = 100;
        const conversationCount = await Conversation.countDocuments({ userId: req.user.userId });
        if (conversationCount >= MAX_CONVERSATIONS_PER_USER) {
            await Conversation.findOneAndDelete(
                { userId: req.user.userId },
                { sort: { 'messages.timestamp': 1 } }
            );
        }
        const conversation = messages.map(msg => `${msg.role}: ${msg.content}`).join('\n');
        const context = await generateAIContext(`Conversation:\n${conversation}\nRespond to the last user message in the conversation.`);
        const response = await axios.post(
            `${AI_API_URL}/api/ask`,
            { question: context },
            { headers: { 'Content-Type': 'application/json' } }
        );
        await Conversation.create({
            userId: req.user.userId,
            messages: messages.concat({ role: 'assistant', content: response.data.answer })
        });
        res.json({ response: response.data.answer || 'Sorry, I could not generate a response.' });
    } catch (error) {
        logger.error('Error processing conversation:', error.message);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to process conversation: ' + error.message });
    }
});

app.get('/api/conversations/export', authenticateToken, isAdmin, async (req, res) => {
    try {
        const conversations = await Conversation.find();
        const csvData = conversations.map(conv =>
            conv.messages.map(msg => `"${msg.role}: ${msg.content.replace(/"/g, '""')}"`).join(',')
        ).join('\n');
        res.header('Content-Type', 'text/csv');
        res.attachment('conversations.csv');
        res.send(csvData);
    } catch (error) {
        logger.error(`Error exporting conversations: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to export conversations: ' + error.message });
    }
});


//MARK_AI

app.get('/api/github-projects', async (req, res) => {
    try {
        const response = await axios.get('https://api.github.com/users/Mark-Lasfar/repos', {
            headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch GitHub projects' });
    }
});



//User

app.get('/api/github/repos', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user.githubAccessToken) {
            return res.status(400).json({ error: 'GitHub account not linked' });
        }

        const response = await axios.get('https://api.github.com/user/repos', {
            headers: { Authorization: `Bearer ${user.githubAccessToken}` }
        });

        const repos = response.data.map(repo => ({
            id: repo.id,
            name: repo.name,
            description: repo.description || 'No description provided',
            url: repo.html_url,
            image: repo.owner.avatar_url // Use owner avatar as a fallback image
        }));

        res.json(repos);
    } catch (error) {
        logger.error(`Error fetching GitHub repos: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to fetch GitHub repositories' });
    }
});

app.get('/', (req, res) => {
    res.json({ message: 'Welcome to Ibrahim Al-Asfar\'s Portfolio Backend API' });
});

app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));