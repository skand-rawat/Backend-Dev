const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const DOMPurify = require('isomorphic-dompurify');
const validator = require('validator');
const bcrypt = require('bcrypt');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ============================================================
// 1. HELMET CONFIGURATION - Security Headers for E-Commerce
// ============================================================
app.use(helmet({
  // Content Security Policy - strict for e-commerce with CDN
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "https://js.stripe.com", // Payment gateway
        "https://www.youtube.com", // Product demo videos
        "https://cdn.jsdelivr.net" // Safe CDN
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'", // Allow inline for bootstrap/framework
        "https://fonts.googleapis.com"
      ],
      imgSrc: [
        "'self'",
        "https://*.cloudfront.net", // CDN for product images
        "https://*.amazonaws.com",
        "data:"
      ],
      frameSrc: [
        "https://js.stripe.com",
        "https://www.youtube.com"
      ],
      connectSrc: [
        "'self'",
        "https://api.stripe.com",
        "https://analytics.google.com"
      ],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  // Enforce HTTPS
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  // Prevent clickjacking
  frameguard: {
    action: 'deny'
  },
  // Prevent MIME type sniffing
  noSniff: true,
  // Prevent XSS (though modern browsers have better protection)
  xssFilter: true,
  // Referrer policy
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// ============================================================
// 2. MIDDLEWARE SETUP
// ============================================================
app.use(express.json({ limit: '10kb' })); // Limit JSON payload
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// CORS Configuration for e-commerce
app.use(cors({
  origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// MongoDB Sanitization - prevent NoSQL injection
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`Sanitized field: ${key}`);
  }
}));

// ============================================================
// 3. DATABASE CONNECTION
// ============================================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/shopeasy', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// ============================================================
// 4. SESSION MANAGEMENT - Production-Ready with MongoStore
// ============================================================
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/shopeasy',
  touchAfter: 24 * 3600, // Lazy session update
  crypto: {
    secret: process.env.SESSION_SECRET || 'change-this-secret-key'
  }
});

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'change-this-secret-key',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Change default session name
  cookie: {
    httpOnly: true, // Prevent XSS access
    secure: process.env.NODE_ENV === 'production', // HTTPS only
    sameSite: 'strict', // CSRF protection
    maxAge: 30 * 60 * 1000, // 30 minutes (realistic for e-commerce)
    path: '/',
    domain: process.env.COOKIE_DOMAIN || undefined
  }
}));

// CSRF Protection
app.use(csrf({ cookie: false }));

// ============================================================
// 5. MONGOOSE SCHEMAS WITH VALIDATION
// ============================================================

// User Schema with security
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain alphanumeric characters, underscore, and hyphen']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false // Don't return password by default
  },
  role: {
    type: String,
    enum: ['customer', 'admin'],
    default: 'customer'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  lastLogin: Date,
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

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Product Schema with price validation
const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Product name is required'],
    trim: true,
    maxlength: [100, 'Product name cannot exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Product description is required'],
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative'],
    max: [999999, 'Price exceeds maximum allowed'],
    validate: {
      validator: function(v) {
        return v > 0; // Prices must be positive
      },
      message: 'Price must be greater than zero'
    }
  },
  category: {
    type: String,
    enum: ['electronics', 'gadgets', 'accessories'],
    required: true
  },
  stock: {
    type: Number,
    required: true,
    min: [0, 'Stock cannot be negative'],
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Review Schema with XSS protection
const reviewSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  rating: {
    type: Number,
    required: [true, 'Rating is required'],
    min: [1, 'Rating must be between 1 and 5'],
    max: [5, 'Rating must be between 1 and 5']
  },
  title: {
    type: String,
    required: [true, 'Review title is required'],
    maxlength: [100, 'Title cannot exceed 100 characters'],
    trim: true
  },
  content: {
    type: String,
    required: [true, 'Review content is required'],
    maxlength: [1000, 'Review cannot exceed 1000 characters']
  },
  verified: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Pre-save hook to sanitize review content
reviewSchema.pre('save', function(next) {
  if (this.isModified('content')) {
    this.content = DOMPurify.sanitize(this.content, { 
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: []
    });
  }
  if (this.isModified('title')) {
    this.title = DOMPurify.sanitize(this.title, { 
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: []
    });
  }
  next();
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Review = mongoose.model('Review', reviewSchema);

// ============================================================
// 6. AUTHENTICATION MIDDLEWARE
// ============================================================

// Check if user is logged in
const isAuthenticated = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// Check if user is admin
const isAdmin = (req, res, next) => {
  if (req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Account lockout protection
const checkAccountLock = async (req, res, next) => {
  const { email } = req.body;
  if (!email) return next();
  
  const user = await User.findOne({ email });
  if (user && user.lockUntil && user.lockUntil > Date.now()) {
    return res.status(429).json({ 
      error: 'Account temporarily locked. Try again later.' 
    });
  }
  next();
};

// ============================================================
// 7. RATE LIMITING
// ============================================================

// Strict rate limiting for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req, res) => {
    // Don't limit admin IP (configure as needed)
    return req.ip === process.env.ADMIN_IP;
  }
});

// General API rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});

// Search rate limiting
const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30,
  message: 'Too many search requests'
});

// ============================================================
// 8. AUTHENTICATION ROUTES
// ============================================================

// Register
app.post('/api/auth/register', 
  generalLimiter,
  checkAccountLock,
  async (req, res) => {
    try {
      const { username, email, password, confirmPassword } = req.body;
      
      // Input validation
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
      
      // Check if user exists
      let user = await User.findOne({ $or: [{ email }, { username }] });
      if (user) {
        return res.status(409).json({ error: 'User already exists' });
      }
      
      // Create new user
      user = new User({
        username,
        email,
        password,
        role: 'customer'
      });
      
      await user.save();
      
      // Set session
      req.session.userId = user._id;
      req.session.role = user.role;
      
      res.status(201).json({
        message: 'Registration successful',
        userId: user._id
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// Login
app.post('/api/auth/login',
  loginLimiter,
  checkAccountLock,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      
      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }
      
      // Find user and include password field
      const user = await User.findOne({ email }).select('+password');
      
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Check if account is locked
      if (user.lockUntil && user.lockUntil > Date.now()) {
        return res.status(429).json({ error: 'Account is temporarily locked' });
      }
      
      // Compare passwords
      const isPasswordValid = await user.comparePassword(password);
      
      if (!isPasswordValid) {
        user.loginAttempts = (user.loginAttempts || 0) + 1;
        
        // Lock account after 5 failed attempts
        if (user.loginAttempts >= 5) {
          user.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        }
        
        await user.save();
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Reset login attempts on successful login
      user.loginAttempts = 0;
      user.lockUntil = undefined;
      user.lastLogin = new Date();
      await user.save();
      
      // Set session
      req.session.userId = user._id;
      req.session.role = user.role;
      req.session.email = user.email;
      
      res.json({
        message: 'Login successful',
        userId: user._id,
        role: user.role
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// Logout
app.post('/api/auth/logout', isAuthenticated, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('sessionId');
    res.json({ message: 'Logout successful' });
  });
});

// ============================================================
// 9. PRODUCT ROUTES - MongoDB Injection Protected
// ============================================================

// Get all products with safe search
app.get('/api/products', searchLimiter, async (req, res) => {
  try {
    // Input sanitization - already done by mongoSanitize middleware
    const { search, category, minPrice, maxPrice, page = 1, limit = 10 } = req.query;
    
    let filter = {};
    
    // Safe search - using regex with escaped input
    if (search) {
      const sanitizedSearch = validator.escape(search);
      filter.name = new RegExp(sanitizedSearch, 'i');
    }
    
    // Safe category filter
    if (category && ['electronics', 'gadgets', 'accessories'].includes(category)) {
      filter.category = category;
    }
    
    // Safe price range filter
    if (minPrice || maxPrice) {
      filter.price = {};
      
      const min = parseFloat(minPrice);
      const max = parseFloat(maxPrice);
      
      if (!isNaN(min) && min >= 0) {
        filter.price.$gte = min;
      }
      if (!isNaN(max) && max >= 0) {
        filter.price.$lte = max;
      }
    }
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const products = await Product.find(filter)
      .skip(skip)
      .limit(parseInt(limit))
      .lean();
    
    const total = await Product.countDocuments(filter);
    
    res.json({
      products,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Product search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }
    
    const product = await Product.findById(req.params.id);
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json(product);
  } catch (error) {
    console.error('Product retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve product' });
  }
});

// Create product (admin only)
app.post('/api/products',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    try {
      const { name, description, price, category, stock } = req.body;
      
      // Input validation
      if (!name || !description || price === undefined || !category || stock === undefined) {
        return res.status(400).json({ error: 'All fields are required' });
      }
      
      // Price validation - critical for e-commerce
      const numPrice = parseFloat(price);
      if (isNaN(numPrice) || numPrice <= 0 || numPrice > 999999) {
        return res.status(400).json({ error: 'Invalid price' });
      }
      
      // Stock validation
      const numStock = parseInt(stock);
      if (isNaN(numStock) || numStock < 0) {
        return res.status(400).json({ error: 'Invalid stock quantity' });
      }
      
      const product = new Product({
        name: validator.trim(name),
        description: validator.trim(description),
        price: numPrice,
        category,
        stock: numStock
      });
      
      await product.save();
      
      res.status(201).json({
        message: 'Product created successfully',
        product
      });
    } catch (error) {
      console.error('Product creation error:', error);
      res.status(500).json({ error: 'Failed to create product' });
    }
  }
);

// ============================================================
// 10. REVIEW ROUTES - XSS Protected
// ============================================================

// Get reviews for a product
app.get('/api/products/:productId/reviews', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.productId)) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }
    
    const reviews = await Review.find({ productId: req.params.productId })
      .populate('userId', 'username')
      .sort({ createdAt: -1 });
    
    res.json(reviews);
  } catch (error) {
    console.error('Review retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve reviews' });
  }
});

// Create review
app.post('/api/products/:productId/reviews',
  isAuthenticated,
  generalLimiter,
  async (req, res) => {
    try {
      if (!mongoose.Types.ObjectId.isValid(req.params.productId)) {
        return res.status(400).json({ error: 'Invalid product ID' });
      }
      
      const { rating, title, content } = req.body;
      
      // Input validation
      if (!rating || !title || !content) {
        return res.status(400).json({ error: 'All fields are required' });
      }
      
      // Rating validation
      const numRating = parseInt(rating);
      if (isNaN(numRating) || numRating < 1 || numRating > 5) {
        return res.status(400).json({ error: 'Rating must be between 1 and 5' });
      }
      
      // Title validation
      if (validator.isEmpty(title) || title.length > 100) {
        return res.status(400).json({ error: 'Invalid title length' });
      }
      
      // Content validation
      if (validator.isEmpty(content) || content.length > 1000) {
        return res.status(400).json({ error: 'Invalid content length' });
      }
      
      // Verify product exists
      const product = await Product.findById(req.params.productId);
      if (!product) {
        return res.status(404).json({ error: 'Product not found' });
      }
      
      const review = new Review({
        productId: req.params.productId,
        userId: req.session.userId,
        rating: numRating,
        title,
        content
      });
      
      await review.save();
      
      res.status(201).json({
        message: 'Review created successfully',
        review
      });
    } catch (error) {
      console.error('Review creation error:', error);
      res.status(500).json({ error: 'Failed to create review' });
    }
  }
);

// ============================================================
// 11. ERROR HANDLING
// ============================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  
  // Don't expose sensitive error details
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : 'An error occurred',
    ...(isDevelopment && { stack: err.stack })
  });
});

// ============================================================
// 12. SERVER START
// ============================================================

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`✓ ShopEasy server running on port ${PORT}`);
  console.log(`✓ Session storage: MongoDB with encryption`);
  console.log(`✓ Security headers: Helmet configured`);
  console.log(`✓ Rate limiting: Enabled`);
  console.log(`✓ Input sanitization: Active`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close();
    process.exit(0);
  });
});

module.exports = app;
