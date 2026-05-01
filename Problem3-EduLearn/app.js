const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const validator = require('validator');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// ============================================================
// 1. HELMET CONFIGURATION - Learning Platform
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://www.youtube.com",
        "https://cdn.jsdelivr.net"
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
      frameSrc: [
        "https://www.youtube.com",
        "https://www.youtube-nocookie.com"
      ],
      mediaSrc: [
        "'self'",
        "https://s3.amazonaws.com"
      ],
      connectSrc: [
        "'self'",
        "https://api.stripe.com"
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
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// ============================================================
// 2. MIDDLEWARE SETUP
// ============================================================
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`Sanitized field: ${key}`);
  }
}));

// ============================================================
// 3. FILE UPLOAD CONFIGURATION
// ============================================================
const uploadDir = path.join(__dirname, 'uploads');
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = crypto.randomBytes(8).toString('hex');
    cb(null, `${Date.now()}-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});

// File filter for documents
const documentFilter = (req, file, cb) => {
  const allowedMimes = ['application/pdf', 'image/jpeg', 'image/png', 'image/dicom'];
  const allowedExt = ['.pdf', '.jpg', '.jpeg', '.png', '.dcm'];
  
  const ext = path.extname(file.originalname).toLowerCase();
  
  if (allowedMimes.includes(file.mimetype) && allowedExt.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Only PDF, JPEG, PNG, and DICOM files are allowed'));
  }
};

const uploadDocument = multer({
  storage,
  fileFilter: documentFilter,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// ============================================================
// 4. DATABASE CONNECTION
// ============================================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/edulearn', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// ============================================================
// 5. SESSION MANAGEMENT
// ============================================================
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/edulearn',
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
  name: 'eduSessionId',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours for educational platform
    path: '/'
  }
}));

// ============================================================
// 6. SCHEMAS WITH COMPREHENSIVE VALIDATION
// ============================================================

// User Schema - Multi-role support
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: [/^[a-zA-Z0-9_-]+$/, 'Invalid username format']
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Invalid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false
  },
  role: {
    type: String,
    enum: ['student', 'instructor', 'admin'],
    default: 'student',
    required: true
  },
  // MFA fields for instructors
  mfaEnabled: {
    type: Boolean,
    default: false
  },
  mfaSecret: {
    type: String,
    select: false
  },
  profile: {
    firstName: {
      type: String,
      trim: true,
      maxlength: 50
    },
    lastName: {
      type: String,
      trim: true,
      maxlength: 50
    },
    bio: {
      type: String,
      maxlength: 500,
      default: ''
    }
  },
  enrolledCourses: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course'
  }],
  createdCourses: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course'
  }],
  paymentHistory: [{
    courseId: mongoose.Schema.Types.ObjectId,
    amount: Number,
    date: Date,
    transactionId: String
  }],
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  createdAt: { type: Date, default: Date.now }
});

// Hash password and sanitize bio
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    try {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
    } catch (error) {
      return next(error);
    }
  }
  
  if (this.isModified('profile.bio')) {
    this.profile.bio = xss(this.profile.bio, {
      whiteList: {
        'b': [], 'i': [], 'em': [], 'strong': [],
        'a': ['href'], 'br': []
      },
      stripIgnoredTag: true
    });
  }
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Course Schema with XSS protection
const courseSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Course title is required'],
    trim: true,
    maxlength: 200
  },
  description: {
    type: String,
    required: [true, 'Course description is required'],
    maxlength: 2000
  },
  instructorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative'],
    max: [100000, 'Price exceeds maximum']
  },
  category: {
    type: String,
    enum: ['programming', 'design', 'business', 'other'],
    required: true
  },
  isPublished: {
    type: Boolean,
    default: false
  },
  students: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  createdAt: { type: Date, default: Date.now }
});

// Sanitize description
courseSchema.pre('save', function(next) {
  if (this.isModified('description')) {
    const allowedTags = ['p', 'b', 'i', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'br', 'h2', 'h3'];
    this.description = xss(this.description, {
      whiteList: {
        'p': [], 'b': [], 'i': [], 'strong': [], 'em': [],
        'ul': [], 'ol': [], 'li': [],
        'a': ['href', 'title'], 'br': [],
        'h2': [], 'h3': []
      },
      stripIgnoredTag: true,
      stripLeakage: true
    });
  }
  next();
});

// Quiz Schema
const quizSchema = new mongoose.Schema({
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course',
    required: true
  },
  title: {
    type: String,
    required: [true, 'Quiz title is required'],
    maxlength: 200
  },
  questions: [{
    questionText: {
      type: String,
      required: true,
      maxlength: 500
    },
    options: [{
      type: String,
      maxlength: 200
    }],
    correctAnswer: {
      type: Number,
      min: 0,
      max: 3
    },
    points: {
      type: Number,
      default: 1,
      min: 1,
      max: 100
    }
  }],
  passingScore: {
    type: Number,
    default: 70,
    min: 0,
    max: 100
  },
  createdAt: { type: Date, default: Date.now }
});

// Quiz Submission Schema
const quizSubmissionSchema = new mongoose.Schema({
  quizId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Quiz',
    required: true
  },
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  answers: [{
    questionId: Number,
    selectedAnswer: Number
  }],
  score: Number,
  passed: Boolean,
  submittedAt: { type: Date, default: Date.now },
  locked: { type: Boolean, default: false }
});

// Prevent answer modification
quizSubmissionSchema.pre('save', function(next) {
  if (this.locked) {
    return next(new Error('Cannot modify locked submission'));
  }
  this.locked = true;
  next();
});

// File Upload Schema
const fileUploadSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course',
    required: true
  },
  originalName: String,
  storageName: String,
  mimeType: String,
  size: Number,
  hash: String,
  uploadedAt: { type: Date, default: Date.now },
  accessLog: [{
    userId: mongoose.Schema.Types.ObjectId,
    accessedAt: Date
  }]
});

const User = mongoose.model('User', userSchema);
const Course = mongoose.model('Course', courseSchema);
const Quiz = mongoose.model('Quiz', quizSchema);
const QuizSubmission = mongoose.model('QuizSubmission', quizSubmissionSchema);
const FileUpload = mongoose.model('FileUpload', fileUploadSchema);

// ============================================================
// 7. AUTHENTICATION MIDDLEWARE
// ============================================================

const isAuthenticated = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.session.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
};

// ============================================================
// 8. RATE LIMITING
// ============================================================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

const quizLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: 'Too many quiz submissions'
});

// ============================================================
// 9. AUTHENTICATION ROUTES
// ============================================================

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password, confirmPassword, role } = req.body;
    
    // Validation
    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password too short' });
    }
    
    // Check duplicate
    let user = await User.findOne({ $or: [{ email }, { username }] });
    if (user) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    // Ensure only admin can create admin roles
    const userRole = role && ['instructor', 'student'].includes(role) ? role : 'student';
    
    user = new User({
      username,
      email,
      password,
      role: userRole
    });
    
    await user.save();
    
    req.session.userId = user._id;
    req.session.role = user.role;
    req.session.username = user.username;
    
    res.status(201).json({
      message: 'Registration successful',
      userId: user._id,
      role: user.role
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
    
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check account lock
    if (user.lockUntil && user.lockUntil > Date.now()) {
      return res.status(429).json({ error: 'Account temporarily locked' });
    }
    
    const isPasswordValid = await user.comparePassword(password);
    
    if (!isPasswordValid) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
      }
      await user.save();
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Reset attempts
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();
    
    req.session.userId = user._id;
    req.session.role = user.role;
    req.session.username = user.username;
    
    res.json({
      message: 'Login successful',
      userId: user._id,
      role: user.role
    });
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
    res.clearCookie('eduSessionId');
    res.json({ message: 'Logout successful' });
  });
});

// ============================================================
// 10. COURSE ROUTES
// ============================================================

// Create course (instructor only)
app.post('/api/courses', isAuthenticated, requireRole(['instructor', 'admin']), apiLimiter, async (req, res) => {
  try {
    const { title, description, price, category } = req.body;
    
    // Validation
    if (!title || !description || price === undefined || !category) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const numPrice = parseFloat(price);
    if (isNaN(numPrice) || numPrice < 0 || numPrice > 100000) {
      return res.status(400).json({ error: 'Invalid price' });
    }
    
    if (!['programming', 'design', 'business', 'other'].includes(category)) {
      return res.status(400).json({ error: 'Invalid category' });
    }
    
    const course = new Course({
      title: validator.trim(title),
      description,
      instructorId: req.session.userId,
      price: numPrice,
      category
    });
    
    await course.save();
    
    res.status(201).json({
      message: 'Course created',
      course
    });
  } catch (error) {
    console.error('Course creation error:', error);
    res.status(500).json({ error: 'Failed to create course' });
  }
});

// Get courses - ensure user can only see non-conflicting courses
app.get('/api/courses', apiLimiter, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 20;
    const skip = (page - 1) * limit;
    
    // Ensure instructor can only see their own courses and their role
    let query = { isPublished: true };
    
    if (req.session.userId && req.session.role === 'instructor') {
      query = {
        $or: [
          { isPublished: true },
          { instructorId: req.session.userId }
        ]
      };
    }
    
    const courses = await Course.find(query)
      .populate('instructorId', 'username profile.firstName profile.lastName')
      .skip(skip)
      .limit(limit)
      .lean();
    
    const total = await Course.countDocuments(query);
    
    res.json({
      courses,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    });
  } catch (error) {
    console.error('Course retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve courses' });
  }
});

// ============================================================
// 11. QUIZ ROUTES - Secure Submission
// ============================================================

// Submit quiz
app.post('/api/quizzes/:quizId/submit', isAuthenticated, quizLimiter, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.quizId)) {
      return res.status(400).json({ error: 'Invalid quiz ID' });
    }
    
    const { answers } = req.body;
    
    if (!Array.isArray(answers)) {
      return res.status(400).json({ error: 'Invalid answers format' });
    }
    
    const quiz = await Quiz.findById(req.params.quizId).populate('courseId');
    if (!quiz) {
      return res.status(404).json({ error: 'Quiz not found' });
    }
    
    // Verify student is enrolled in course
    const enrollment = await User.findById(req.session.userId);
    if (!enrollment.enrolledCourses.includes(quiz.courseId._id)) {
      return res.status(403).json({ error: 'Not enrolled in this course' });
    }
    
    // Calculate score
    let score = 0;
    answers.forEach(answer => {
      const question = quiz.questions[answer.questionId];
      if (question && answer.selectedAnswer === question.correctAnswer) {
        score += question.points;
      }
    });
    
    const totalPoints = quiz.questions.reduce((sum, q) => sum + q.points, 0);
    const percentage = (score / totalPoints) * 100;
    const passed = percentage >= quiz.passingScore;
    
    // Create submission - LOCKED IMMEDIATELY
    const submission = new QuizSubmission({
      quizId: req.params.quizId,
      studentId: req.session.userId,
      answers,
      score,
      passed,
      locked: true
    });
    
    await submission.save();
    
    res.status(201).json({
      message: 'Quiz submitted',
      submission: {
        score,
        percentage: percentage.toFixed(2),
        passed,
        _id: submission._id
      }
    });
  } catch (error) {
    console.error('Quiz submission error:', error);
    res.status(500).json({ error: 'Failed to submit quiz' });
  }
});

// Get submission (immutable)
app.get('/api/submissions/:submissionId', isAuthenticated, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.submissionId)) {
      return res.status(400).json({ error: 'Invalid submission ID' });
    }
    
    const submission = await QuizSubmission.findById(req.params.submissionId);
    
    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }
    
    // Only student or instructor can view
    if (submission.studentId.toString() !== req.session.userId.toString() && 
        req.session.role !== 'instructor') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Verify immutability
    if (!submission.locked) {
      return res.status(400).json({ error: 'Submission is not locked' });
    }
    
    res.json(submission);
  } catch (error) {
    console.error('Submission retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve submission' });
  }
});

// ============================================================
// 12. FILE UPLOAD ROUTES - Secure Document Handling
// ============================================================

// Upload course material
app.post('/api/courses/:courseId/upload', 
  isAuthenticated,
  requireRole(['instructor', 'admin']),
  uploadDocument.single('file'),
  async (req, res) => {
    try {
      if (!mongoose.Types.ObjectId.isValid(req.params.courseId)) {
        return res.status(400).json({ error: 'Invalid course ID' });
      }
      
      if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
      }
      
      // Verify instructor owns course
      const course = await Course.findById(req.params.courseId);
      if (!course || course.instructorId.toString() !== req.session.userId.toString()) {
        if (req.file.path) await fs.unlink(req.file.path);
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // Calculate file hash for integrity
      const fileContent = await fs.readFile(req.file.path);
      const hash = crypto.createHash('sha256').update(fileContent).digest('hex');
      
      const fileRecord = new FileUpload({
        userId: req.session.userId,
        courseId: req.params.courseId,
        originalName: req.file.originalname,
        storageName: req.file.filename,
        mimeType: req.file.mimetype,
        size: req.file.size,
        hash
      });
      
      await fileRecord.save();
      
      res.status(201).json({
        message: 'File uploaded successfully',
        fileId: fileRecord._id
      });
    } catch (error) {
      if (req.file && req.file.path) {
        fs.unlink(req.file.path).catch(console.error);
      }
      console.error('File upload error:', error);
      res.status(500).json({ error: 'Failed to upload file' });
    }
  }
);

// Download file with access logging
app.get('/api/files/:fileId/download', isAuthenticated, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.fileId)) {
      return res.status(400).json({ error: 'Invalid file ID' });
    }
    
    const fileRecord = await FileUpload.findById(req.params.fileId);
    if (!fileRecord) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Verify access permission
    const course = await Course.findById(fileRecord.courseId);
    const user = await User.findById(req.session.userId);
    
    const hasAccess = 
      user._id.toString() === fileRecord.userId.toString() ||
      course.instructorId.toString() === req.session.userId.toString() ||
      course.students.includes(req.session.userId) ||
      req.session.role === 'admin';
    
    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Log access
    fileRecord.accessLog.push({
      userId: req.session.userId,
      accessedAt: new Date()
    });
    await fileRecord.save();
    
    const filePath = path.join(__dirname, 'uploads', fileRecord.storageName);
    res.download(filePath, fileRecord.originalName);
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({ error: 'Failed to download file' });
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
  console.log(`✓ EduLearn server running on port ${PORT}`);
  console.log(`✓ Multi-role RBAC: Enabled`);
  console.log(`✓ File upload security: Enabled`);
  console.log(`✓ Quiz submission integrity: Locked`);
});

process.on('SIGTERM', () => {
  console.log('Shutting down gracefully');
  server.close(() => {
    mongoose.connection.close();
    process.exit(0);
  });
});

module.exports = app;
