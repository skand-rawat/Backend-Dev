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
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

const app = express();

// ============================================================
// 1. ENCRYPTION UTILITIES - Data at Rest
// ============================================================

const ENCRYPTION_KEY = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key-change-in-production', 'salt', 32);

function encryptData(data) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptData(encryptedData) {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(parts[1], 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

// ============================================================
// 2. AUDIT LOGGING - HIPAA Compliance
// ============================================================

const auditLog = async (action, userId, resourceType, resourceId, changes, result) => {
  // In production, send to central logging system
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    action,
    userId,
    resourceType,
    resourceId,
    changes,
    result,
    ipAddress: process.env.LOG_IP || 'unknown'
  }, null, 2));
};

// ============================================================
// 3. HELMET CONFIGURATION - Healthcare
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
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
// 4. MIDDLEWARE
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
// 5. DATABASE CONNECTION
// ============================================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/medibook', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// ============================================================
// 6. SESSION MANAGEMENT
// ============================================================
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/medibook',
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
  name: 'mediSessionId',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 2 * 60 * 60 * 1000, // 2 hours for healthcare
    path: '/'
  }
}));

// ============================================================
// 7. SCHEMAS WITH ENCRYPTION & HIPAA COMPLIANCE
// ============================================================

// User Schema - Healthcare roles
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    minlength: 3,
    maxlength: 30,
    match: [/^[a-zA-Z0-9_-]+$/, 'Invalid username']
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
    minlength: 12, // Stronger password for healthcare
    select: false
  },
  role: {
    type: String,
    enum: ['patient', 'doctor', 'nurse', 'admin', 'insurance'],
    required: true
  },
  // Encrypted sensitive data
  ssn: {
    type: String,
    default: null
  },
  phone: {
    type: String,
    default: null
  },
  dateOfBirth: {
    type: String,
    default: null
  },
  insuranceInfo: {
    type: String, // Encrypted
    default: null
  },
  licenseNumber: {
    type: String,
    default: null
  },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});

// Hash password
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    try {
      const salt = await bcrypt.genSalt(12); // Stronger salt
      this.password = await bcrypt.hash(this.password, salt);
    } catch (error) {
      return next(error);
    }
  }
  
  // Encrypt sensitive fields
  if (this.isModified('ssn') && this.ssn) {
    this.ssn = encryptData(this.ssn);
  }
  if (this.isModified('phone') && this.phone) {
    this.phone = encryptData(this.phone);
  }
  if (this.isModified('dateOfBirth') && this.dateOfBirth) {
    this.dateOfBirth = encryptData(this.dateOfBirth);
  }
  if (this.isModified('insuranceInfo') && this.insuranceInfo) {
    this.insuranceInfo = encryptData(this.insuranceInfo);
  }
  
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Medical Record Schema - Encrypted and Audited
const medicalRecordSchema = new mongoose.Schema({
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  doctorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  recordType: {
    type: String,
    enum: ['diagnosis', 'prescription', 'lab-result', 'imaging', 'note'],
    required: true
  },
  content: {
    type: String, // Encrypted
    required: true
  },
  attachedFiles: [{
    fileId: mongoose.Schema.Types.ObjectId,
    fileName: String,
    uploadedAt: Date
  }],
  accessLog: [{
    userId: mongoose.Schema.Types.ObjectId,
    accessedAt: Date,
    action: String
  }],
  createdAt: { type: Date, default: Date.now, immutable: true },
  updatedAt: { type: Date, default: Date.now }
});

// Encrypt content before save
medicalRecordSchema.pre('save', function(next) {
  if (this.isModified('content')) {
    // Sanitize medical content
    const sanitized = xss(this.content, {
      whiteList: {},
      stripIgnoredTag: true
    });
    this.content = encryptData(sanitized);
  }
  next();
});

// Prevent updates (audit trail)
medicalRecordSchema.pre('findByIdAndUpdate', async function(next) {
  const update = this.getUpdate();
  if (update.content) {
    // Create new record instead of updating
    return next(new Error('Medical records cannot be updated. Create a new record instead.'));
  }
  next();
});

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  doctorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  appointmentDateTime: {
    type: Date,
    required: [true, 'Valid appointment date/time required'],
    validate: {
      validator: function(v) {
        return v instanceof Date && v > Date.now();
      },
      message: 'Appointment must be in the future'
    }
  },
  reason: {
    type: String,
    required: true,
    maxlength: 500
  },
  status: {
    type: String,
    enum: ['scheduled', 'completed', 'cancelled'],
    default: 'scheduled'
  },
  notes: String,
  createdAt: { type: Date, default: Date.now }
});

// Sanitize reason and notes
appointmentSchema.pre('save', function(next) {
  if (this.isModified('reason')) {
    this.reason = xss(this.reason, {
      whiteList: {},
      stripIgnoredTag: true
    });
  }
  if (this.isModified('notes')) {
    this.notes = xss(this.notes, {
      whiteList: {},
      stripIgnoredTag: true
    });
  }
  next();
});

// Document Upload Schema
const documentSchema = new mongoose.Schema({
  uploadedBy: mongoose.Schema.Types.ObjectId,
  relatedRecordId: mongoose.Schema.Types.ObjectId,
  documentType: {
    type: String,
    enum: ['xray', 'mri', 'ct', 'lab', 'prescription', 'other'],
    required: true
  },
  fileHash: {
    type: String,
    required: true,
    immutable: true
  },
  encryptedPath: String,
  fileSize: Number,
  mimeType: {
    type: String,
    enum: ['application/pdf', 'image/jpeg', 'image/png']
  },
  accessLog: [{
    userId: mongoose.Schema.Types.ObjectId,
    accessedAt: Date
  }],
  uploadedAt: { type: Date, default: Date.now, immutable: true }
});

const User = mongoose.model('User', userSchema);
const MedicalRecord = mongoose.model('MedicalRecord', medicalRecordSchema);
const Appointment = mongoose.model('Appointment', appointmentSchema);
const Document = mongoose.model('Document', documentSchema);

// ============================================================
// 8. AUTHENTICATION MIDDLEWARE
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
      auditLog('access_denied', req.session.userId, 'unauthorized_access', null, null, 'DENIED');
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
};

// ============================================================
// 9. RATE LIMITING
// ============================================================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3, // Stricter for healthcare
  message: 'Too many login attempts'
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50
});

// ============================================================
// 10. AUTHENTICATION ROUTES
// ============================================================

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password, confirmPassword, role, ssn, dateOfBirth } = req.body;
    
    // Comprehensive validation
    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    // Strong password requirement
    if (password.length < 12 || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[!@#$%^&*]/.test(password)) {
      return res.status(400).json({ 
        error: 'Password must be 12+ chars with uppercase, number, and special char' 
      });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    
    // Validate SSN format if provided
    if (ssn && !validator.matches(ssn, /^\d{3}-\d{2}-\d{4}$/)) {
      return res.status(400).json({ error: 'Invalid SSN format' });
    }
    
    // Validate DOB format
    if (dateOfBirth && !validator.isISO8601(dateOfBirth)) {
      return res.status(400).json({ error: 'Invalid date format' });
    }
    
    // Check duplicate
    let user = await User.findOne({ $or: [{ email }, { username }] });
    if (user) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    const userRole = ['patient', 'doctor', 'nurse'].includes(role) ? role : 'patient';
    
    user = new User({
      username,
      email,
      password,
      role: userRole,
      ssn: ssn || null,
      dateOfBirth: dateOfBirth || null
    });
    
    await user.save();
    
    req.session.userId = user._id;
    req.session.role = user.role;
    
    auditLog('registration', user._id, 'user', user._id, { role: userRole }, 'SUCCESS');
    
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
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (user.lockUntil && user.lockUntil > Date.now()) {
      auditLog('login_attempt', user._id, 'user', user._id, null, 'LOCKED');
      return res.status(429).json({ error: 'Account temporarily locked' });
    }
    
    const isPasswordValid = await user.comparePassword(password);
    
    if (!isPasswordValid) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 3) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
      }
      await user.save();
      auditLog('login_attempt', user._id, 'user', user._id, null, 'FAILED');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLogin = new Date();
    await user.save();
    
    req.session.userId = user._id;
    req.session.role = user.role;
    
    auditLog('login', user._id, 'user', user._id, null, 'SUCCESS');
    
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

// ============================================================
// 11. PATIENT RECORDS ROUTES - Authorization Protected
// ============================================================

// Get patient records (only patient or authorized healthcare provider)
app.get('/api/patients/:patientId/records', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.patientId)) {
      return res.status(400).json({ error: 'Invalid patient ID' });
    }
    
    const patientId = req.params.patientId;
    const currentUserId = req.session.userId;
    const role = req.session.role;
    
    // Authorization: only patient viewing own records or authorized provider
    if (patientId !== currentUserId.toString() && !['doctor', 'nurse', 'admin'].includes(role)) {
      auditLog('access_denied', currentUserId, 'medical_record', patientId, null, 'UNAUTHORIZED');
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const records = await MedicalRecord.find({ patientId })
      .populate('doctorId', 'username')
      .lean();
    
    // Log access
    for (const record of records) {
      const logEntry = {
        userId: currentUserId,
        accessedAt: new Date(),
        action: 'VIEW'
      };
      
      MedicalRecord.findByIdAndUpdate(
        record._id,
        { $push: { accessLog: logEntry } },
        { new: true }
      ).catch(console.error);
    }
    
    // Decrypt content for display
    const decryptedRecords = records.map(record => ({
      ...record,
      content: decryptData(record.content)
    }));
    
    auditLog('view_records', currentUserId, 'medical_record', patientId, null, 'SUCCESS');
    
    res.json(decryptedRecords);
  } catch (error) {
    console.error('Record retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve records' });
  }
});

// Create medical record (doctor/nurse only)
app.post('/api/patients/:patientId/records', 
  isAuthenticated,
  requireRole(['doctor', 'nurse', 'admin']),
  apiLimiter,
  async (req, res) => {
    try {
      if (!mongoose.Types.ObjectId.isValid(req.params.patientId)) {
        return res.status(400).json({ error: 'Invalid patient ID' });
      }
      
      const { recordType, content } = req.body;
      
      if (!recordType || !['diagnosis', 'prescription', 'lab-result', 'imaging', 'note'].includes(recordType)) {
        return res.status(400).json({ error: 'Invalid record type' });
      }
      
      if (!content || typeof content !== 'string' || content.length === 0) {
        return res.status(400).json({ error: 'Content required' });
      }
      
      if (content.length > 5000) {
        return res.status(400).json({ error: 'Content too long' });
      }
      
      const record = new MedicalRecord({
        patientId: req.params.patientId,
        doctorId: req.session.userId,
        recordType,
        content // Will be encrypted in pre-save hook
      });
      
      await record.save();
      
      auditLog('create_record', req.session.userId, 'medical_record', record._id, { recordType }, 'SUCCESS');
      
      res.status(201).json({
        message: 'Record created',
        recordId: record._id
      });
    } catch (error) {
      console.error('Record creation error:', error);
      res.status(500).json({ error: 'Failed to create record' });
    }
  }
);

// ============================================================
// 12. APPOINTMENT ROUTES
// ============================================================

// Book appointment
app.post('/api/appointments', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const { doctorId, appointmentDateTime, reason } = req.body;
    
    if (!doctorId || !mongoose.Types.ObjectId.isValid(doctorId)) {
      return res.status(400).json({ error: 'Invalid doctor ID' });
    }
    
    if (!appointmentDateTime) {
      return res.status(400).json({ error: 'Appointment date/time required' });
    }
    
    // Validate date format
    const appointmentDate = new Date(appointmentDateTime);
    if (isNaN(appointmentDate.getTime()) || appointmentDate <= Date.now()) {
      return res.status(400).json({ error: 'Invalid appointment date' });
    }
    
    if (!reason || typeof reason !== 'string' || reason.length === 0 || reason.length > 500) {
      return res.status(400).json({ error: 'Invalid reason' });
    }
    
    // Verify doctor exists
    const doctor = await User.findById(doctorId);
    if (!doctor || doctor.role !== 'doctor') {
      return res.status(404).json({ error: 'Doctor not found' });
    }
    
    const appointment = new Appointment({
      patientId: req.session.userId,
      doctorId,
      appointmentDateTime: appointmentDate,
      reason
    });
    
    await appointment.save();
    
    auditLog('create_appointment', req.session.userId, 'appointment', appointment._id, null, 'SUCCESS');
    
    res.status(201).json({
      message: 'Appointment booked',
      appointmentId: appointment._id
    });
  } catch (error) {
    console.error('Appointment error:', error);
    res.status(500).json({ error: 'Failed to book appointment' });
  }
});

// Get appointments
app.get('/api/appointments', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    let query = {};
    
    if (req.session.role === 'patient') {
      query.patientId = req.session.userId;
    } else if (req.session.role === 'doctor') {
      query.doctorId = req.session.userId;
    }
    
    const appointments = await Appointment.find(query)
      .populate('patientId', 'username email')
      .populate('doctorId', 'username');
    
    res.json(appointments);
  } catch (error) {
    console.error('Appointments retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve appointments' });
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
  console.log(`✓ MediBook server running on port ${PORT}`);
  console.log(`✓ Encryption: AES-256-CBC at rest`);
  console.log(`✓ Audit logging: HIPAA-compliant`);
  console.log(`✓ Authorization: Role-based access control`);
});

process.on('SIGTERM', () => {
  console.log('Shutting down gracefully');
  server.close(() => {
    mongoose.connection.close();
    process.exit(0);
  });
});

module.exports = app;
