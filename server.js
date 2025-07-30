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
require('dotenv').config();
const winston = require('winston');
const sharp = require('sharp');

const app = express();
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

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
        const allowedTypes = ['image/jpeg', 'image/png'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Only JPEG or PNG images are allowed'));
        }
        cb(null, true);
    }
});

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'logs/app.log' })
    ]
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

if (!MONGODB_URI || !JWT_SECRET || !GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !EMAIL_USER || !EMAIL_PASS || !HUGGING_FACE_TOKEN) {
    console.error('Missing environment variables');
    process.exit(1);
}

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

mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

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
        jobTitle: String,
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
    callbackURL: `${process.env.BASE_URL}/auth/callback`
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
        user = await User.create({
            googleId: profile.id,
            email: profile.emails[0].value,
            username: profile.displayName,
            refreshToken: refreshToken,
        });
    } else if (refreshToken) {
        user.refreshToken = refreshToken;
        await user.save();
    }
    return done(null, user);
}));

app.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    try {
        const token = jwt.sign({ userId: req.user._id, isAdmin: req.user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.redirect(`${process.env.BASE_URL}/auth/callback?token=${token}&provider=google`);
    } catch (error) {
        res.redirect(`${process.env.BASE_URL}/login.html?error=${encodeURIComponent('Google authentication failed')}`);
    }
});

passport.use(new FacebookStrategy({
    clientID: FACEBOOK_CLIENT_ID,
    clientSecret: FACEBOOK_CLIENT_SECRET,
    callbackURL: `${process.env.BASE_URL}/auth/callback`,
    profileFields: ['id', 'emails', 'displayName']
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ facebookId: profile.id });
    if (!user) {
        user = await User.create({
            facebookId: profile.id,
            email: profile.emails ? profile.emails[0].value : `${profile.id}@facebook.com`,
            username: profile.displayName,
            refreshToken: refreshToken
        });
    } else if (refreshToken) {
        user.refreshToken = refreshToken;
        await user.save();
    }
    return done(null, user);
}));

app.get('/auth/facebook/callback', passport.authenticate('facebook', { session: false }), (req, res) => {
    try {
        const token = jwt.sign({ userId: req.user._id, isAdmin: req.user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.redirect(`${process.env.BASE_URL}/auth/callback?token=${token}&provider=facebook`);
    } catch (error) {
        res.redirect(`${process.env.BASE_URL}/login.html?error=${encodeURIComponent('Facebook authentication failed')}`);
    }
});

passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: `${process.env.BASE_URL}/auth/callback`
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ githubId: profile.id });
    if (!user) {
        user = await User.create({
            githubId: profile.id,
            email: profile.emails ? profile.emails[0].value : `${profile.id}@github.com`,
            username: profile.displayName || profile.username,
            refreshToken: refreshToken
        });
    } else if (refreshToken) {
        user.refreshToken = refreshToken;
        await user.save();
    }
    return done(null, user);
}));

app.get('/auth/github/callback', passport.authenticate('github', { session: false }), (req, res) => {
    try {
        const token = jwt.sign({ userId: req.user._id, isAdmin: req.user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.redirect(`${process.env.BASE_URL}/auth/callback?token=${token}&provider=github`);
    } catch (error) {
        res.redirect(`${process.env.BASE_URL}/login.html?error=${encodeURIComponent('GitHub authentication failed')}`);
    }
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

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
        console.log('Admin user created');
    }
}
createAdminUser();

async function sendNotification(userId, message) {
    try {
        const user = await User.findById(userId);
        if (!user) {
            console.error('User not found for notification:', userId);
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
        console.log(`Notification sent to ${user.email}: ${message}`);
    } catch (error) {
        console.error('Error sending notification:', error);
    }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token is required' });

    jwt.verify(token, JWT_SECRET, async (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                const refreshToken = req.body.refreshToken || req.headers['x-refresh-token'];
                if (!refreshToken) return res.status(401).json({ error: 'Refresh token is required' });
                try {
                    const decoded = jwt.verify(refreshToken, JWT_SECRET);
                    const dbUser = await User.findOne({ _id: decoded.userId, 'refreshTokens.token': refreshToken });
                    if (!dbUser) return res.status(403).json({ error: 'Invalid refresh token' });
                    const newToken = jwt.sign({ userId: dbUser._id, isAdmin: dbUser.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
                    req.user = { userId: dbUser._id, isAdmin: dbUser.isAdmin };
                    res.setHeader('X-New-Token', newToken);
                    next();
                } catch (refreshError) {
                    return res.status(403).json({ error: 'Failed to refresh token' });
                }
            } else {
                return res.status(403).json({ error: 'Invalid token' });
            }
        } else {
            req.user = user;
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
        res.json({ message: `File uploaded successfully: ${fileUrl}` });
    } catch (error) {
        res.status(400).json({ error: error.message || 'Failed to upload file' });
    }
});

app.post('/api/login/otp/verify', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ error: 'Invalid or expired OTP' });
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        user.refreshTokens.push({ token: refreshToken });
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();
        res.json({ token, refreshToken });
    } catch (error) {
        res.status(500).json({ error: 'Failed to verify OTP: ' + error.message });
    }
});

app.get('/api/profile/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        let hasTransparency = false;
        if (user.profile.avatar) {
            const image = sharp(user.profile.avatar);
            const metadata = await image.metadata();
            hasTransparency = metadata.hasAlpha || false;
        }
        res.json({
            username: user.username,
            profile: {
                ...user.profile,
                customFields: user.profile.customFields || []
            },
            hasTransparency
        });
    } catch (error) {
        logger.error(`Error fetching profile for user ${req.user.userId}: ${error.message}`);
        res.status(500).json({ error: 'Failed to fetch profile: ' + error.message });
    }
});

app.post('/api/ask', async (req, res) => {
    const { question } = req.body;
    try {
        const projects = await Project.find();
        const skills = await Skill.find();
        const context = `
            Website: Ibrahim Al-Asfar's personal portfolio.
            Description: A full-stack web developer portfolio showcasing projects, skills, and contact information.
            Skills: ${skills.map(s => `${s.name} (${s.percentage}%)`).join(', ')}
            Projects: ${projects.map(p => `${p.title}: ${p.description} (Links: ${p.links.map(l => l.option).join(', ')})`).join('\n')}
            Question: ${question}
        `;
        const response = await axios.post(
            `${process.env.AI_API_URL}/api/ask`,
            { question: context },
            { headers: { 'Content-Type': 'application/json' } }
        );
        res.json({ answer: response.data.answer || 'Sorry, I could not generate an answer.' });
    } catch (error) {
        console.error('Error processing question:', error.message);
        res.status(500).json({ error: 'Failed to process question: ' + error.message });
    }
});

app.post('/api/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ error: 'Refresh token is required' });
    try {
        const decoded = jwt.verify(refreshToken, JWT_SECRET);
        const user = await User.findOne({ _id: decoded.userId, 'refreshTokens.token': refreshToken });
        if (!user) return res.status(403).json({ error: 'Invalid refresh token' });
        const newToken = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        const newRefreshToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
        user.refreshTokens.push({ token: newRefreshToken });
        await user.save();
        res.json({ token: newToken, refreshToken: newRefreshToken });
    } catch (error) {
        res.status(403).json({ error: 'Failed to refresh token: ' + error.message });
    }
});

app.post('/api/converse', authenticateToken, async (req, res) => {
    const { messages } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'Messages are required and must be an array' });
    }
    try {
        const projects = await Project.find();
        const skills = await Skill.find();
        const conversation = messages.map(msg => `${msg.role}: ${msg.content}`).join('\n');
        const context = `
            You are elasfar-AI, a helpful assistant for Ibrahim Al-Asfar's portfolio website.
            Website: Ibrahim Al-Asfar's personal portfolio.
            Description: A full-stack web developer portfolio showcasing projects, skills, and contact information.
            Skills: ${skills.map(s => `${s.name} (${s.percentage}%)`).join(', ')}
            Projects: ${projects.map(p => `${p.title}: ${p.description} (Links: ${p.links.map(l => l.option).join(', ')})`).join('\n')}
            Conversation:
            ${conversation}
            Respond to the last user message in the conversation.
        `;
        const response = await axios.post(
            `${process.env.AI_API_URL}/api/ask`,
            { question: context },
            { headers: { 'Content-Type': 'application/json' } }
        );
        await Conversation.create({
            userId: req.user.userId,
            messages: messages.concat({ role: 'assistant', content: response.data.answer })
        });
        res.json({ response: response.data.answer || 'Sorry, I could not generate a response.' });
    } catch (error) {
        console.error('Error processing conversation:', error.message);
        res.status(500).json({ error: 'Failed to process conversation: ' + error.message });
    }
});

app.get('/api/conversations/export', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    try {
        const conversations = await Conversation.find();
        const csvData = conversations.map(conv => 
            conv.messages.map(msg => `"${msg.role}: ${msg.content.replace(/"/g, '""')}"`).join(',')
        ).join('\n');
        res.header('Content-Type', 'text/csv');
        res.attachment('conversations.csv');
        res.send(csvData);
    } catch (error) {
        res.status(500).json({ error: 'Failed to export conversations' });
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

app.post('/api/chat', async (req, res) => {
    const { message } = req.body;
    try {
        const projects = await Project.find();
        const skills = await Skill.find();
        const context = `
            You are a helpful assistant for Ibrahim Al-Asfar's portfolio website. Use the following context to answer the user's message:
            Website: Ibrahim Al-Asfar's personal portfolio.
            Description: A full-stack web developer portfolio showcasing projects, skills, and contact information.
            Skills: ${skills.map(s => `${s.name} (${s.percentage}%)`).join(', ')}
            Projects: ${projects.map(p => `${p.title}: ${p.description} (Links: ${p.links.map(l => l.option).join(', ')})`).join('\n')}
            User message: ${message}
        `;
        const response = await axios.post(
            `${process.env.AI_API_URL}/api/ask`,
            { question: context },
            { headers: { 'Content-Type': 'application/json' } }
        );
        res.json({ reply: response.data.answer || 'Sorry, I could not generate a response.' });
    } catch (error) {
        console.error('Error:', error.message);
        res.status(500).json({ error: 'Something went wrong' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        if (user.isAdmin) {
            const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
            const refreshToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
            user.refreshTokens.push({ token: refreshToken });
            await user.save();
            console.log(`Admin login: ${email} - Token issued without OTP`);
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
            console.log(`OTP sent to ${email}: ${otp}`);
            res.json({ message: 'OTP sent to your email' });
        } catch (mailError) {
            console.error('Failed to send OTP email:', mailError);
            return res.status(500).json({ error: 'Failed to send OTP email' });
        }
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Login failed: ' + error.message });
    }
});

app.post('/api/login/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid or expired OTP' });
        }
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        user.refreshTokens.push({ token: refreshToken });
        user.otp = null;
        user.otpExpires = null;
        await user.save();
        res.json({ token, refreshToken });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ error: 'OTP verification failed' });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters long' });
        }
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
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/api/projects', async (req, res) => {
    const projects = await Project.find();
    res.json(projects);
});

app.post('/api/projects', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    const { title, description, image, rating, stars, links } = req.body;
    try {
        const project = new Project({ title, description, image, rating, stars, links });
        await project.save();
        res.status(201).json(project);
    } catch (error) {
        console.error('Error saving project:', error);
        res.status(400).json({ error: 'Failed to save project: ' + error.message });
    }
});

app.put('/api/projects/:projectId', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    const { projectId } = req.params;
    const { title, description, image, rating, stars, links } = req.body;
    const project = await Project.findByIdAndUpdate(projectId, { title, description, image, rating, stars, links }, { new: true });
    res.json(project);
});

app.delete('/api/projects/:projectId', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    const { projectId } = req.params;
    await Project.findByIdAndDelete(projectId);
    await Comment.deleteMany({ projectId });
    res.sendStatus(204);
});

app.get('/api/comments/:projectId', async (req, res) => {
    const comments = await Comment.find({ projectId: req.params.projectId }).populate('userId', 'username email');
    res.json(comments);
});

app.get('/api/notifications', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    try {
        const user = await User.findById(req.user.userId);
        res.json(user.notifications || []);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch notifications: ' + error.message });
    }
});

app.get('/api/comments', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    try {
        const comments = await Comment.find()
            .populate('userId', 'username email')
            .populate('projectId', 'title');
        const sanitizedComments = comments.map(comment => ({
            ...comment._doc,
            userId: comment.userId
                ? { username: comment.userId.username || 'Anonymous', email: comment.userId.email || '' }
                : { username: 'Anonymous', email: '' },
            projectTitle: comment.projectId ? comment.projectId.title : 'Unknown Project'
        }));
        res.json(sanitizedComments);
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: 'Failed to load comments: ' + error.message });
    }
});

app.post('/api/comments', authenticateToken, async (req, res) => {
    const { projectId, rating, text } = req.body;
    const comment = new Comment({ projectId, userId: req.user.userId, rating, text });
    await comment.save();
    await sendNotification(req.user.userId, `You commented on project ${projectId}: "${text}"`);
    res.status(201).json(comment);
});

app.post('/api/comments/:commentId/reply', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    const { commentId } = req.params;
    const { text } = req.body;
    const comment = await Comment.findByIdAndUpdate(
        commentId,
        { $push: { replies: { text, timestamp: new Date() } } },
        { new: true }
    ).populate('userId', 'username email');
    await sendNotification(comment.userId._id, `Admin replied to your comment: "${text}"`);
    res.json(comment);
});

app.delete('/api/comments/:commentId', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    const { commentId } = req.params;
    await Comment.findByIdAndDelete(commentId);
    res.sendStatus(204);
});

app.get('/api/skills', async (req, res) => {
    const skills = await Skill.find();
    res.json(skills);
});

app.post('/api/skills', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    const { name, icon, percentage } = req.body;
    const skill = new Skill({ name, icon, percentage });
    await skill.save();
    res.status(201).json(skill);
});

app.put('/api/skills/:skillId', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    const { skillId } = req.params;
    const { name, icon, percentage } = req.body;
    const skill = await Skill.findByIdAndUpdate(skillId, { name, icon, percentage }, { new: true });
    res.json(skill);
});

app.delete('/api/skills/:skillId', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    const { skillId } = req.params;
    await Skill.findByIdAndDelete(skillId);
    res.sendStatus(204);
});

app.get('/api/profile/:nickname', async (req, res) => {
    const { nickname } = req.params;
    const user = await User.findOne({ nickname });
    if (!user) return res.status(404).json({ error: 'User not found' });
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
            projects: user.profile.projects
        }
    });
});

app.put('/api/profile', authenticateToken, upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'projectImages', maxCount: 10 }
]), async (req, res) => {
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

        const isValidUrl = (url) => {
            if (!url) return true;
            try {
                new URL(url);
                return true;
            } catch {
                return false;
            }
        };

        const parsedSocialLinks = parseJSON(socialLinks, user.profile.socialLinks);
        for (const [key, url] of Object.entries(parsedSocialLinks)) {
            if (url && !isValidUrl(url)) {
                return res.status(400).json({ error: `Invalid ${key} URL` });
            }
        }

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
            const imageBuffer = req.files.avatar[0].buffer;
            const image = sharp(imageBuffer);
            const metadata = await image.metadata();
            hasTransparency = metadata.hasAlpha || false;
            user.profile.avatar = req.files.avatar[0].path;
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

app.get('/api/users', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    try {
        const users = await User.find({}, 'username email profile');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users: ' + error.message });
    }
});

app.delete('/api/users/:userId', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.sendStatus(403);
    try {
        await User.findByIdAndDelete(req.params.userId);
        await Comment.deleteMany({ userId: req.params.userId });
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete user: ' + error.message });
    }
});

app.get('/api/profile/pdf/:nickname', async (req, res) => {
    try {
        const user = await User.findOne({ 'profile.nickname': req.params.nickname });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (!user.profile.isPublic && !req.user) return res.status(403).json({ error: 'Profile is private' });

        const doc = new jsPDF();
        doc.setFontSize(20);
        doc.text(user.profile.nickname || user.username, 10, 20);
        doc.setFontSize(12);
        doc.text(`Job Title: ${user.profile.jobTitle || 'Not specified'}`, 10, 30);
        doc.text(`Bio: ${user.profile.bio || 'Not specified'}`, 10, 40);
        doc.text(`Phone: ${user.profile.phone || 'Not specified'}`, 10, 50);
        doc.text('Social Links:', 10, 60);
        doc.text(`LinkedIn: ${user.profile.socialLinks.linkedin || 'Not specified'}`, 10, 70);
        doc.text(`Behance: ${user.profile.socialLinks.behance || 'Not specified'}`, 10, 80);
        doc.text(`GitHub: ${user.profile.socialLinks.github || 'Not specified'}`, 10, 90);
        doc.text(`WhatsApp: ${user.profile.socialLinks.whatsapp || 'Not specified'}`, 10, 100);
        doc.text('Education:', 10, 110);
        user.profile.education.forEach((edu, i) => {
            doc.text(`${edu.degree} at ${edu.institution} (${edu.year})`, 10, 120 + i * 10);
        });
        doc.text('Experience:', 10, 120 + user.profile.education.length * 10);
        user.profile.experience.forEach((exp, i) => {
            doc.text(`${exp.role} at ${exp.company} (${exp.duration})`, 10, 130 + user.profile.education.length * 10 + i * 10);
        });
        doc.text('Certificates:', 10, 130 + user.profile.education.length * 10 + user.profile.experience.length * 10);
        user.profile.certificates.forEach((cert, i) => {
            doc.text(`${cert.name} by ${cert.issuer} (${cert.year})`, 10, 140 + user.profile.education.length * 10 + user.profile.experience.length * 10 + i * 10);
        });
        doc.text('Skills:', 10, 140 + user.profile.education.length * 10 + user.profile.experience.length * 10 + user.profile.certificates.length * 10);
        user.profile.skills.forEach((skill, i) => {
            doc.text(`${skill.name} (${skill.percentage}%)`, 10, 150 + user.profile.education.length * 10 + user.profile.experience.length * 10 + user.profile.certificates.length * 10 + i * 10);
        });
        doc.text('Projects:', 10, 150 + user.profile.education.length * 10 + user.profile.experience.length * 10 + user.profile.certificates.length * 10 + user.profile.skills.length * 10);
        user.profile.projects.forEach((project, i) => {
            doc.text(`${project.title}: ${project.description}`, 10, 160 + user.profile.education.length * 10 + user.profile.experience.length * 10 + user.profile.certificates.length * 10 + user.profile.skills.length * 10 + i * 10);
        });
        doc.text('Interests:', 10, 160 + user.profile.education.length * 10 + user.profile.experience.length * 10 + user.profile.certificates.length * 10 + user.profile.skills.length * 10 + user.profile.projects.length * 10);
        user.profile.interests.forEach((interest, i) => {
            doc.text(interest, 10, 170 + user.profile.education.length * 10 + user.profile.experience.length * 10 + user.profile.certificates.length * 10 + user.profile.skills.length * 10 + user.profile.projects.length * 10 + i * 10);
        });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${user.profile.nickname || user.username}_resume.pdf`);
        res.send(doc.output());
    } catch (error) {
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

app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    try {
        if (!email || !otp || !newPassword) {
            return res.status(400).json({ error: 'Email, OTP, and new password are required' });
        }
        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters long' });
        }
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();
        logger.info(`Password reset successfully for ${email}`);
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        logger.error(`Reset password error for ${email}: ${error.message}`);
        res.status(500).json({ error: 'Failed to reset password' });
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
        console.error('Search error:', error);
        res.status(500).json({ error: 'Failed to search users' });
    }
});

app.get('/', (req, res) => {
    res.json({ message: 'Welcome to Ibrahim Al-Asfar\'s Portfolio Backend API' });
});

// module.exports = app;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));