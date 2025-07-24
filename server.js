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
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(passport.initialize());



cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});


// إعداد Multer لرفع الملفات
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'uploads', // اسم المجلد في Cloudinary
        allowed_formats: ['jpeg', 'png', 'pdf'],
        resource_type: 'auto' // لدعم الصور وPDF
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
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



// التحقق من المتغيرات
if (!MONGODB_URI || !JWT_SECRET || !GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !EMAIL_USER || !EMAIL_PASS || !HUGGING_FACE_TOKEN) {
    console.error('Missing environment variables');
    process.exit(1);
}

// إعداد Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    }
});

// الاتصال بـ MongoDB
mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// نموذج المشروع
const projectSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    image: { type: String, required: true },
    rating: { type: String, required: true },
    stars: { type: Number, required: true },
    links: [{ option: String, value: String, isPrivate: { type: Boolean, default: false } }],
});
const Project = mongoose.model('Project', projectSchema);

// نموذج التعليق
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

// نموذج المستخدم
const userSchema = new mongoose.Schema({
    username: { type: String, sparse: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    isAdmin: { type: Boolean, default: false },
    googleId: String,
    facebookId: String,
    githubId: String,
    refreshToken: String,
    notifications: [{ type: String }],
});
const User = mongoose.model('User', userSchema);

// نموذج المهارة
const skillSchema = new mongoose.Schema({
    name: { type: String, required: true },
    icon: { type: String, required: true },
    percentage: { type: Number, required: true },
});
const Skill = mongoose.model('Skill', skillSchema);

// نموذج المحادثة
const conversationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    messages: [{ role: String, content: String, timestamp: { type: Date, default: Date.now } }],
});
const Conversation = mongoose.model('Conversation', conversationSchema);

// إعداد Passport لـ Google
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
            accessToken: accessToken, // accessToken 
            refreshToken: refreshToken,
        });
    } else {
        user.accessToken = accessToken; //  accessToken
        await user.save();
    }
    return done(null, user);
}));

app.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    try {
        const token = jwt.sign({ userId: req.user._id, isAdmin: req.user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.redirect(`${process.env.BASE_URL}/auth/callback?token=${token}`);
    } catch (error) {
        res.redirect(`${process.env.BASE_URL}/login.html?error=${encodeURIComponent('Google authentication failed')}`);
    }
});

// إعداد Passport لـ Facebook
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
        res.redirect(`${process.env.BASE_URL}/auth/callback?token=${token}`);
    } catch (error) {
        res.redirect(`${process.env.BASE_URL}/login.html?error=${encodeURIComponent('Facebook authentication failed')}`);
    }
});

// إعداد Passport لـ GitHub
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
        res.redirect(`${process.env.BASE_URL}/auth/callback?token=${token}`);
    } catch (error) {
        res.redirect(`${process.env.BASE_URL}/login.html?error=${encodeURIComponent('GitHub authentication failed')}`);
    }
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

// التحقق من التوكن
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.get('/api/verify-token', authenticateToken, (req, res) => {
    res.json({ valid: true, userId: req.user.userId, isAdmin: req.user.isAdmin });
});

// رفع الملفات
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        // Cloudinary بيرجع الـ URL في req.file.path
        const fileUrl = req.file.path; // رابط الملف على Cloudinary
        res.json({ message: `File uploaded successfully: ${fileUrl}` });
    } catch (error) {
        res.status(400).json({ error: error.message || 'Failed to upload file' });
    }
});

// تعديل /api/ask لاستخدام Render
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

    const user = await User.findOne({ refreshToken });
    if (!user) return res.status(403).json({ error: 'Invalid refresh token' });

    try {
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(403).json({ error: 'Failed to refresh token' });
    }
});

// دعم المحادثة
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
        // تخزين المحادثة
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

// تصدير المحادثات
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

// جلب مشاريع GitHub
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

// تعديل /api/chat لاستخدام Render
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

// باقي واجهات الـ API
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Email not found' });
        }
        if (!(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Incorrect password' });
        }
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
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
        res.status(201).json({ token });
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

app.get('/assets/ibrahim.pdf', (req, res) => {
    res.download(path.join(__dirname, 'public/assets/ibrahim.pdf'));
});

app.get('/', (req, res) => {
    res.json({ message: 'Welcome to Ibrahim Al-Asfar\'s Portfolio Backend API' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));