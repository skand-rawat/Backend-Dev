const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const DOMPurify = require('isomorphic-dompurify');
const validator = require('validator');
const xss = require('xss');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ============================================================
// 1. HELMET CONFIGURATION - Social Media Platform
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "https://cdn.jsdelivr.net",
        "https://www.google-analytics.com",
        "https://platform.twitter.com",
        "https://platform.instagram.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com"
      ],
      imgSrc: [
        "'self'",
        "https:",
        "data:"
      ],
      connectSrc: [
        "'self'",
        "https://api.twitter.com",
        "https://www.google-analytics.com"
      ],
      frameSrc: [
        "https://platform.twitter.com",
        "https://platform.instagram.com"
      ],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// ============================================================
// 2. MIDDLEWARE SETUP
// ============================================================
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// CORS for mobile and web clients
app.use(cors({
  origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// MongoDB sanitization
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`Sanitized field: ${key}`);
  }
}));

// ============================================================
// 3. DATABASE CONNECTION
// ============================================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/connecthub', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// ============================================================
// 4. SESSION CONFIGURATION
// ============================================================
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/connecthub',
  touchAfter: 24 * 3600,
  crypto: {
    secret: process.env.SESSION_SECRET || 'change-this-secret'
  }
});

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  name: 'connecthubSessionId',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours for social media
    path: '/',
    domain: process.env.COOKIE_DOMAIN || undefined
  }
}));

// ============================================================
// 5. SCHEMAS WITH COMPREHENSIVE VALIDATION
// ============================================================

// User Schema - Comprehensive sanitization
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [20, 'Username cannot exceed 20 characters'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain alphanumeric, underscore, and hyphen']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [
      {
        validator: function(v) {
          return validator.isEmail(v);
        },
        message: 'Please provide a valid email'
      },
      {
        validator: async function(v) {
          // Verify email isn't already in use
          const count = await this.constructor.countDocuments({ email: v, _id: { $ne: this._id } });
          return count === 0;
        },
        message: 'Email already in use'
      }
    ]
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  bio: {
    type: String,
    maxlength: [500, 'Bio cannot exceed 500 characters'],
    default: ''
  },
  profileUrl: {
    type: String,
    default: null,
    validate: {
      validator: function(v) {
        if (!v) return true; // Allow null/empty
        // Validate URL format and prevent javascript: protocol
        try {
          const url = new URL(v);
          return url.protocol === 'http:' || url.protocol === 'https:';
        } catch {
          return false;
        }
      },
      message: 'Invalid profile URL. Must be a valid HTTP/HTTPS URL'
    }
  },
  followers: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  following: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Sanitize bio on save
userSchema.pre('save', function(next) {
  if (this.isModified('bio')) {
    // Allow only basic formatting - bold, italic, links
    const allowedTags = ['b', 'i', 'em', 'strong', 'a', 'br'];
    this.bio = xss(this.bio, {
      whiteList: {
        'b': [],
        'i': [],
        'em': [],
        'strong': [],
        'a': ['href', 'title'],
        'br': []
      },
      stripIgnoredTag: true,
      stripLeakage: true
    });
  }
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Post Schema - XSS protection
const postSchema = new mongoose.Schema({
  authorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: [true, 'Post content is required'],
    maxlength: [5000, 'Post cannot exceed 5000 characters']
  },
  likes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  comments: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    content: {
      type: String,
      maxlength: [500, 'Comment cannot exceed 500 characters']
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  isPublic: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Sanitize content on save
postSchema.pre('save', function(next) {
  if (this.isModified('content')) {
    const allowedTags = ['b', 'i', 'em', 'strong', 'a', 'br', 'p', 'ul', 'ol', 'li'];
    this.content = xss(this.content, {
      whiteList: {
        'b': [],
        'i': [],
        'em': [],
        'strong': [],
        'a': ['href', 'title'],
        'br': [],
        'p': [],
        'ul': [],
        'ol': [],
        'li': []
      },
      stripIgnoredTag: true,
      stripLeakage: true
    });
  }
  
  // Sanitize comments
  if (this.isModified('comments')) {
    this.comments.forEach(comment => {
      if (comment.content) {
        comment.content = xss(comment.content, {
          whiteList: {
            'b': [],
            'i': [],
            'em': [],
            'strong': [],
            'a': ['href'],
            'br': []
          },
          stripIgnoredTag: true,
          stripLeakage: true
        });
      }
    });
  }
  next();
});

// Direct Message Schema
const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  recipientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: [true, 'Message content is required'],
    maxlength: [1000, 'Message cannot exceed 1000 characters']
  },
  isRead: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Sanitize message content
messageSchema.pre('save', function(next) {
  if (this.isModified('content')) {
    this.content = DOMPurify.sanitize(this.content, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: []
    });
  }
  next();
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Message = mongoose.model('Message', messageSchema);

// ============================================================
// 6. AUTHENTICATION MIDDLEWARE
// ============================================================

const isAuthenticated = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// ============================================================
// 7. RATE LIMITING
// ============================================================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests'
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: 'Too many messages sent'
});

// ============================================================
// 8. AUTHENTICATION ROUTES
// ============================================================

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    
    // Validation
    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    // Check user exists
    let user = await User.findOne({ $or: [{ email }, { username }] });
    if (user) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    user = new User({
      username,
      email,
      password
    });
    
    await user.save();
    
    req.session.userId = user._id;
    req.session.username = user.username;
    
    res.status(201).json({
      message: 'Registration successful',
      userId: user._id
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    
    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.userId = user._id;
    req.session.username = user.username;
    
    res.json({ message: 'Login successful', userId: user._id });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
app.post('/api/auth/logout', isAuthenticated, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connecthubSessionId');
    res.json({ message: 'Logout successful' });
  });
});

// ============================================================
// 9. USER PROFILE ROUTES - Sanitized Output
// ============================================================

// Get user profile
app.get('/api/users/:userId', apiLimiter, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    const user = await User.findById(req.params.userId)
      .select('-password')
      .populate('followers', 'username')
      .populate('following', 'username');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Sanitize bio for display
    const sanitizedUser = user.toObject();
    sanitizedUser.bio = DOMPurify.sanitize(sanitizedUser.bio);
    
    res.json(sanitizedUser);
  } catch (error) {
    console.error('Profile retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve profile' });
  }
});

// Update user profile
app.put('/api/users/profile/update', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const { bio, profileUrl } = req.body;
    
    const updates = {};
    
    if (bio !== undefined) {
      if (typeof bio !== 'string' || bio.length > 500) {
        return res.status(400).json({ error: 'Invalid bio' });
      }
      updates.bio = bio;
    }
    
    if (profileUrl !== undefined) {
      if (profileUrl && !validator.isURL(profileUrl)) {
        return res.status(400).json({ error: 'Invalid profile URL' });
      }
      // Additional check to prevent javascript: protocol
      if (profileUrl && (profileUrl.toLowerCase().startsWith('javascript:') || 
          profileUrl.toLowerCase().startsWith('data:'))) {
        return res.status(400).json({ error: 'Invalid URL protocol' });
      }
      updates.profileUrl = profileUrl;
    }
    
    const user = await User.findByIdAndUpdate(
      req.session.userId,
      updates,
      { new: true, runValidators: true }
    ).select('-password');
    
    res.json({
      message: 'Profile updated successfully',
      user
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ============================================================
// 10. POST ROUTES - XSS Protected
// ============================================================

// Create post
app.post('/api/posts', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const { content, isPublic } = req.body;
    
    if (!content || typeof content !== 'string' || content.length === 0) {
      return res.status(400).json({ error: 'Post content is required' });
    }
    
    if (content.length > 5000) {
      return res.status(400).json({ error: 'Post too long' });
    }
    
    const post = new Post({
      authorId: req.session.userId,
      content,
      isPublic: isPublic !== false // Default to true
    });
    
    await post.save();
    
    await post.populate('authorId', 'username');
    
    res.status(201).json({
      message: 'Post created successfully',
      post
    });
  } catch (error) {
    console.error('Post creation error:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Get feed
app.get('/api/posts/feed', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 20;
    const skip = (page - 1) * limit;
    
    const posts = await Post.find({ isPublic: true })
      .populate('authorId', 'username profileUrl')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    
    const total = await Post.countDocuments({ isPublic: true });
    
    res.json({
      posts,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Feed retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve feed' });
  }
});

// Get user posts
app.get('/api/users/:userId/posts', apiLimiter, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    // Verify user exists
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const posts = await Post.find({
      authorId: req.params.userId,
      isPublic: true
    })
    .populate('authorId', 'username')
    .sort({ createdAt: -1 });
    
    res.json(posts);
  } catch (error) {
    console.error('User posts error:', error);
    res.status(500).json({ error: 'Failed to retrieve posts' });
  }
});

// Add comment
app.post('/api/posts/:postId/comments', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }
    
    const { content } = req.body;
    
    if (!content || typeof content !== 'string' || content.length === 0) {
      return res.status(400).json({ error: 'Comment content is required' });
    }
    
    if (content.length > 500) {
      return res.status(400).json({ error: 'Comment too long' });
    }
    
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    post.comments.push({
      userId: req.session.userId,
      content
    });
    
    await post.save();
    
    res.json({
      message: 'Comment added successfully',
      post
    });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// ============================================================
// 11. DIRECT MESSAGE ROUTES - Authorization Protected
// ============================================================

// Send message
app.post('/api/messages', isAuthenticated, messageLimiter, async (req, res) => {
  try {
    const { recipientId, content } = req.body;
    
    if (!recipientId || !mongoose.Types.ObjectId.isValid(recipientId)) {
      return res.status(400).json({ error: 'Invalid recipient ID' });
    }
    
    if (!content || typeof content !== 'string' || content.length === 0) {
      return res.status(400).json({ error: 'Message content is required' });
    }
    
    if (content.length > 1000) {
      return res.status(400).json({ error: 'Message too long' });
    }
    
    // Verify recipient exists
    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }
    
    // Prevent self-messaging
    if (req.session.userId.toString() === recipientId.toString()) {
      return res.status(400).json({ error: 'Cannot send message to yourself' });
    }
    
    const message = new Message({
      senderId: req.session.userId,
      recipientId,
      content
    });
    
    await message.save();
    
    res.status(201).json({
      message: 'Message sent successfully',
      messageData: message
    });
  } catch (error) {
    console.error('Message creation error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get messages (only for sender or recipient)
app.get('/api/messages/conversation/:userId', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    const otherUserId = req.params.userId;
    const currentUserId = req.session.userId;
    
    // AUTHORIZATION CHECK - Only allow viewing own messages
    if (otherUserId.toString() !== currentUserId.toString()) {
      // Get messages between current user and other user
      const messages = await Message.find({
        $or: [
          { senderId: currentUserId, recipientId: otherUserId },
          { senderId: otherUserId, recipientId: currentUserId }
        ]
      })
      .populate('senderId', 'username')
      .populate('recipientId', 'username')
      .sort({ createdAt: 1 });
      
      return res.json(messages);
    }
    
    res.status(403).json({ error: 'Unauthorized access' });
  } catch (error) {
    console.error('Message retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve messages' });
  }
});

// Get my messages
app.get('/api/messages/inbox', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const messages = await Message.find({ recipientId: req.session.userId })
      .populate('senderId', 'username profileUrl')
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json(messages);
  } catch (error) {
    console.error('Inbox retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve inbox' });
  }
});

// ============================================================
// 12. FOLLOW SYSTEM - Authorization Protected
// ============================================================

// Follow user
app.post('/api/users/:userId/follow', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    const targetUserId = req.params.userId;
    const currentUserId = req.session.userId;
    
    // Prevent self-follow
    if (targetUserId.toString() === currentUserId.toString()) {
      return res.status(400).json({ error: 'Cannot follow yourself' });
    }
    
    // Verify target user exists
    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Add follower/following relationship
    await User.findByIdAndUpdate(
      currentUserId,
      { $addToSet: { following: targetUserId } },
      { new: true }
    );
    
    await User.findByIdAndUpdate(
      targetUserId,
      { $addToSet: { followers: currentUserId } },
      { new: true }
    );
    
    res.json({ message: 'User followed successfully' });
  } catch (error) {
    console.error('Follow error:', error);
    res.status(500).json({ error: 'Failed to follow user' });
  }
});

// Unfollow user
app.post('/api/users/:userId/unfollow', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    const targetUserId = req.params.userId;
    const currentUserId = req.session.userId;
    
    await User.findByIdAndUpdate(
      currentUserId,
      { $pull: { following: targetUserId } },
      { new: true }
    );
    
    await User.findByIdAndUpdate(
      targetUserId,
      { $pull: { followers: currentUserId } },
      { new: true }
    );
    
    res.json({ message: 'User unfollowed successfully' });
  } catch (error) {
    console.error('Unfollow error:', error);
    res.status(500).json({ error: 'Failed to unfollow user' });
  }
});

// ============================================================
// 13. ERROR HANDLING
// ============================================================

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  console.error('Global error:', err);
  const isDev = process.env.NODE_ENV === 'development';
  res.status(err.status || 500).json({
    error: isDev ? err.message : 'An error occurred'
  });
});

// ============================================================
// 14. SERVER START
// ============================================================

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`✓ ConnectHub server running on port ${PORT}`);
  console.log(`✓ Session storage: MongoDB with encryption`);
  console.log(`✓ XSS protection: Active`);
  console.log(`✓ Authorization: Enforced`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close();
    process.exit(0);
  });
});

module.exports = app;
