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
require('jspdf-autotable');
require('dotenv').config();
const winston = require('winston');
const sharp = require('sharp');
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const { body, validationResult, param } = require('express-validator');
const csurf = require('csurf');
const Sentry = require('@sentry/node');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const timeout = require('express-timeout-handler');
const compression = require('compression');
const SentryTracing = require('@sentry/tracing');
const app = express();

const { Handlers } = require('@sentry/node');

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



const WEB_URL = process.env.WEB_URL;
const BASE_URL = process.env.BASE_URL;

app.use(cors({
    origin: WEB_URL,
    credentials: true
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
    image: { type: String, required: true },
    rating: { type: String, required: true },
    stars: { type: Number, required: true },
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
    facebookId: String,
    githubId: String,
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
    callbackURL: `${process.env.BASE_URL}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            user = await User.create({
                googleId: profile.id,
                email: profile.emails[0].value,
                username: profile.displayName
            });
        }
        if (refreshToken) {
            user.refreshTokens.push({ token: refreshToken });
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
    profileFields: ['id', 'emails', 'displayName']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ facebookId: profile.id });
        if (!user) {
            user = await User.create({
                facebookId: profile.id,
                email: profile.emails ? profile.emails[0].value : `${profile.id}@facebook.com`,
                username: profile.displayName
            });
        }
        if (refreshToken) {
            user.refreshTokens.push({ token: refreshToken });
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
    callbackURL: `${process.env.BASE_URL}/auth/github/callback`
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ githubId: profile.id });
        if (!user) {
            user = await User.create({
                githubId: profile.id,
                email: profile.emails ? profile.emails[0].value : `${profile.id}@github.com`,
                username: profile.displayName || profile.username
            });
        }
        if (refreshToken) {
            user.refreshTokens.push({ token: refreshToken });
            await user.save();
        }
        return done(null, user);
    } catch (error) {
        logger.error(`GitHub strategy error: ${error.message}`);
        return done(error, null);
    }
}));
app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
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




const rateLimit = require('express-rate-limit');
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



// app.use(Sentry.getExpressErrorHandler());

app.use((err, req, res, next) => {
    logger.error(`Unhandled error: ${err.stack}`);
    if (err.code === 'EBADCSRFTOKEN') {
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
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        const error = new Error('Token is required');
        Sentry.captureException(error, { extra: { endpoint: req.originalUrl, method: req.method } });
        return res.status(401).json({ error: 'Token is required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                const refreshToken = req.body.refreshToken || req.headers['x-refresh-token'];
                if (!refreshToken) {
                    const error = new Error('Refresh token is required');
                    Sentry.captureException(error, { extra: { endpoint: req.originalUrl, method: req.method } });
                    return res.status(401).json({ error: 'Refresh token is required' });
                }
                try {
                    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
                    const dbUser = await User.findOne({ _id: decoded.userId, 'refreshTokens.token': refreshToken });
                    if (!dbUser) {
                        const error = new Error('Invalid refresh token');
                        Sentry.captureException(error, { extra: { endpoint: req.originalUrl, method: req.method } });
                        return res.status(403).json({ error: 'Invalid refresh token' });
                    }
                    const newToken = jwt.sign({ userId: dbUser._id, isAdmin: dbUser.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });
                    req.user = { userId: dbUser._id, isAdmin: dbUser.isAdmin, email: dbUser.email };
                    Sentry.setUser({ id: dbUser._id, email: dbUser.email }); // Set user for Sentry
                    res.setHeader('X-New-Token', newToken);
                    next();
                } catch (refreshError) {
                    Sentry.captureException(refreshError, { extra: { endpoint: req.originalUrl, method: req.method } });
                    return res.status(403).json({ error: 'Failed to refresh token' });
                }
            } else {
                Sentry.captureException(err, { extra: { endpoint: req.originalUrl, method: req.method } });
                return res.status(403).json({ error: 'Invalid token' });
            }
        } else {
            req.user = user;
            Sentry.setUser({ id: user.userId, email: user.email }); // Set user for Sentry
            next();
        }
    });


    
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

app.get('/api/profile/:nickname', async (req, res) => {
    const { nickname } = req.params;
    try {
        const decodedNickname = decodeURIComponent(nickname);
        const user = await User.findOne({
            $or: [
                { 'profile.nickname': decodedNickname },
                { username: decodedNickname }
            ]
        });
        if (!user) {
            return res.status(404).json({ error: `Profile not found for nickname: ${decodedNickname}` });
        }
        if (!user.profile.isPublic && !req.user) {
            return res.status(403).json({ error: 'Profile is private', loginRequired: true });
        }
        res.json({
            username: user.username,
            profile: {
                nickname: user.profile.nickname,
                portfolioName: user.profile.portfolioName,
                avatar: user.profile.avatar,
                avatarDisplayType: user.profile.avatarDisplayType,
                svgColor: user.profile.svgColor,
                jobTitle: user.profile.jobTitle,
                bio: user.profile.bio,
                phone: user.profile.phone,
                socialLinks: user.profile.socialLinks,
                education: user.profile.education,
                experience: user.profile.experience,
                certificates: user.profile.certificates,
                interests: user.profile.interests,
                skills: user.profile.skills,
                projects: user.profile.projects,
                pdfFormat: user.profile.pdfFormat || 'jspdf'
            }
        });
    } catch (error) {
        logger.error(`Error fetching profile for ${nickname}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to fetch profile: ' + error.message });
    }
});

app.put('/api/profile', authenticateToken, upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'projectImages', maxCount: 10 }
    
]), 



[
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
            return Array.isArray(parsed) && parsed.every(item => item.institution && item.degree && item.year);
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
            return Array.isArray(parsed) && parsed.every(item => item.name && item.issuer && item.year);
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
            return Array.isArray(parsed) && parsed.every(item => item.title && item.description && item.image && /^https?:\/\/[^\s/$.?#].[^\s]*$/.test(item.image));
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
    body('svgColor').optional().matches(/^#[0-9A-Fa-f]{6}$/).withMessage('Invalid SVG color format')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { nickname, jobTitle, bio, phone, socialLinks, education, experience, certificates, skills, projects, interests, isPublic, avatarDisplayType, svgColor } = req.body;
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const parseJSON = (str, defaultValue) => {
            try {
                return str ? JSON.parse(str) : defaultValue;
            } catch (error) {
                logger.error(`Invalid JSON for ${str}: ${error.message}`);
                return defaultValue;
            }
        };

        const parsedSocialLinks = parseJSON(socialLinks, user.profile.socialLinks);
        const parsedEducation = parseJSON(education, user.profile.education);
        const parsedExperience = parseJSON(experience, user.profile.experience);
        const parsedCertificates = parseJSON(certificates, user.profile.certificates);
        const parsedSkills = parseJSON(skills, user.profile.skills);
        let parsedProjects = parseJSON(projects, user.profile.projects);

        if (req.files && req.files.projectImages) {
            parsedProjects = parsedProjects.map((project, index) => ({
                ...project,
                image: req.files.projectImages && req.files.projectImages[index] ? req.files.projectImages[index].path : project.image
            }));
        }

let hasTransparency = false;
if (req.files && req.files.avatar) {
    try {
        const imageBuffer = req.files.avatar[0].buffer;
        const image = sharp(imageBuffer);
        const metadata = await image.metadata();
        hasTransparency = metadata.hasAlpha || false;
        user.profile.avatar = req.files.avatar[0].path;
    } catch (imageError) {
        logger.error(`Error processing avatar image: ${imageError.message}`);
        Sentry.captureException(imageError);
    }
}

        user.profile = {
            nickname: nickname || user.profile.nickname,
            avatar: user.profile.avatar,
            jobTitle: jobTitle || user.profile.jobTitle,
            bio: bio || user.profile.bio,
            phone: phone || user.profile.phone,
            socialLinks: parsedSocialLinks,
            education: parsedEducation,
            experience: parsedExperience,
            certificates: parsedCertificates,
            skills: parsedSkills,
            projects: parsedProjects,
            interests: parseJSON(interests, user.profile.interests),
            isPublic: isPublic !== undefined ? isPublic === 'true' : user.profile.isPublic,
            avatarDisplayType: avatarDisplayType || user.profile.avatarDisplayType,
            svgColor: svgColor || user.profile.svgColor,
            customFields: parseJSON(req.body.customFields, user.profile.customFields || [])
        };

        await user.save();
        logger.info(`Profile updated for user ${req.user.userId}`);
        res.json({ success: true, message: 'Profile updated successfully', profile: user.profile, hasTransparency });
    } catch (error) {
        logger.error(`Error updating profile for user ${req.user.userId}: ${error.message}`);
        res.status(500).json({ error: `Failed to update profile: ${error.message}` });
    }
});

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

app.get('/api/profile/pdf/:nickname', async (req, res) => {
    try {
        const decodedNickname = decodeURIComponent(req.params.nickname);
        const user = await User.findOne({ 'profile.nickname': decodedNickname });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (!user.profile.isPublic && !req.user) return res.status(403).json({ error: 'Profile is private' });

        const doc = new jsPDF();
        doc.setFontSize(20);
        doc.text(user.profile.nickname || user.username, 10, 20);
        doc.setFontSize(12);
        doc.text('Portfolio Resume', 10, 30, { align: 'center' });

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
            columnStyles: { 0: { cellWidth: 50 }, 1: { cellWidth: 130 } }
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
            columnStyles: { 0: { cellWidth: 50 }, 1: { cellWidth: 130 } }
        });

        // Education
        const educationData = user.profile.education.slice(0, 50).map(edu => [
            edu.degree || 'Not specified',
            edu.institution || 'Not specified',
            edu.year || 'Not specified'
        ]);
        if (educationData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Education', 'Institution', 'Year']],
                body: educationData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 80 }, 2: { cellWidth: 40 } }
            });
        }

        // Experience
        const experienceData = user.profile.experience.slice(0, 50).map(exp => [
            exp.role || 'Not specified',
            exp.company || 'Not specified',
            exp.duration || 'Not specified'
        ]);
        if (experienceData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Role', 'Company', 'Duration']],
                body: experienceData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 80 }, 2: { cellWidth: 40 } }
            });
        }

        // Certificates
        const certificateData = user.profile.certificates.slice(0, 50).map(cert => [
            cert.name || 'Not specified',
            cert.issuer || 'Not specified',
            cert.year || 'Not specified'
        ]);
        if (certificateData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Certificate', 'Issuer', 'Year']],
                body: certificateData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 80 }, 2: { cellWidth: 40 } }
            });
        }

        // Skills
        const skillData = user.profile.skills.slice(0, 50).map(skill => [
            skill.name || 'Not specified',
            `${skill.percentage}%` || '0%'
        ]);
        if (skillData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Skill', 'Proficiency']],
                body: skillData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 100 }, 1: { cellWidth: 80 } }
            });
        }

        // Projects
        const projectData = user.profile.projects.slice(0, 50).map(project => [
            project.title || 'Not specified',
            project.description || 'Not specified'
        ]);
        if (projectData.length > 0) {
            doc.autoTable({
                startY: doc.lastAutoTable.finalY + 10,
                head: [['Project Title', 'Description']],
                body: projectData,
                theme: 'striped',
                styles: { fontSize: 10 },
                columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 120 } }
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
                columnStyles: { 0: { cellWidth: 180 } }
            });
        }

        // Footer
        doc.setFontSize(8);
        doc.text(`Generated on ${new Date().toLocaleDateString()}`, 10, doc.internal.pageSize.height - 10);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${(user.profile.nickname || user.username).replace(/[^a-zA-Z0-9]/g, '_')}_resume.pdf`);
        res.send(doc.output());
    } catch (error) {
        logger.error(`Error generating PDF for ${req.params.nickname}: ${error.message}`);
        Sentry.captureException(error);
        res.status(500).json({ error: 'Failed to generate PDF: ' + error.message });
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

app.get('/', (req, res) => {
    res.json({ message: 'Welcome to Ibrahim Al-Asfar\'s Portfolio Backend API' });
});

app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));