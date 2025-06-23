const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const NodeCache = require('node-cache');
require('dotenv').config();
const encrypt = require('mongoose-encryption');

const app = express();

// Initialize cache
const cache = new NodeCache({ stdTTL: 600 }); // 10 minutes

// Environment variable validation
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET', 'ENCRYPTION_KEY'];
requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
});

// Configuration
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Logger setup
const logger = winston.createLogger({
  level: NODE_ENV === 'production' ? 'warn' : 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'logs/app.log',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
  ],
});

if (NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: NODE_ENV === 'production' ? 100 : 1000,
  message: { message: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Auth rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: 'Too many authentication attempts, please try again later.' },
  skipSuccessfulRequests: true,
});

// CORS setup
const corsOrigins = NODE_ENV === 'production'
  ? [FRONTEND_URL]
  : [FRONTEND_URL, 'http://localhost:3000', 'http://127.0.0.1:3000', 'http://192.168.100.95:3000'];
app.use(cors({
  origin: corsOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.options('*', cors());

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static(path.join(__dirname, 'client'), {
  maxAge: NODE_ENV === 'production' ? '1d' : '0'
}));

// Request logging middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// MongoDB connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000,
  heartbeatFrequencyMS: 2000,
  maxPoolSize: 10,
  bufferCommands: false,
})
  .then(() => logger.info('Connected to MongoDB successfully'))
  .catch((err) => {
    logger.error('MongoDB connection error:', err);
    process.exit(1);
  });

mongoose.connection.on('error', (err) => logger.error('MongoDB connection error:', err));
mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'));
mongoose.connection.on('reconnected', () => logger.info('MongoDB reconnected'));

// Schemas
const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please enter a valid email']
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date }
}, { 
  timestamps: true,
  toJSON: { transform: (doc, ret) => { delete ret.password; return ret; } }
});
userSchema.index({ email: 1 });
const User = mongoose.model('User', userSchema);

const actionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  item: { type: String, required: true, trim: true },
  quantity: { type: Number, required: true, min: [1, 'Quantity must be at least 1'] },
  action: { type: String, required: true, enum: ['add_to_cart', 'remove_from_cart', 'purchase'], trim: true },
  metadata: { type: mongoose.Schema.Types.Mixed }
}, { timestamps: true });
actionSchema.index({ userId: 1, createdAt: -1 });
const Action = mongoose.model('Action', actionSchema);

const coffeeSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Coffee name is required'], trim: true, maxlength: [100, 'Coffee name too long'] },
  price: { type: Number, required: [true, 'Price is required'], min: [0.01, 'Price must be positive'] },
  image: { type: String, required: [true, 'Image URL is required'], match: [/^https?:\/\/.+/, 'Please enter a valid image URL'] },
  description: { type: String, default: 'Premium quality coffee', maxlength: [500, 'Description too long'] },
  category: { type: String, default: 'Hot Coffee', enum: ['Hot Coffee', 'Iced Coffee', 'Specialty'] },
  isAvailable: { type: Boolean, default: true },
  ingredients: [{ type: String }]
}, { timestamps: true });
coffeeSchema.index({ category: 1, isAvailable: 1 });
const Coffee = mongoose.model('Coffee', coffeeSchema);

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  items: [{
    name: { type: String, required: true },
    price: { type: Number, required: true, min: 0 },
    quantity: { type: Number, required: true, min: 1 },
    _id: false
  }],
  total: { type: Number, required: true, min: [0.01, 'Total must be positive'] },
  status: { type: String, enum: ['pending', 'confirmed', 'preparing', 'ready', 'completed', 'cancelled'], default: 'pending' },
  paymentMethod: { type: String, default: 'card' },
  notes: { type: String, maxlength: 500 },
  cardInfo: {
    cardNumber: { type: String, required: true, get: (v) => v, set: (v) => v.replace(/\s/g, '') },
    expiryDate: { type: String, required: true, get: (v) => v, set: (v) => v.replace(/\//g, '') },
    cardHolder: { type: String, required: true }
  }
}, { 
  timestamps: true,
  toJSON: { transform: (doc, ret) => { delete ret.cardInfo.cardNumber; delete ret.cardInfo.expiryDate; return ret; } }
});
const SIGNING_KEY = process.env.SIGNING_KEY;

orderSchema.plugin(encrypt, {
  encryptionKey: Buffer.from(ENCRYPTION_KEY, 'base64'),
  signingKey: Buffer.from(SIGNING_KEY, 'base64'),
  encryptedFields: ['cardInfo.cardNumber', 'cardInfo.expiryDate'],
  decryptPostSave: false
});

orderSchema.index({ userId: 1, createdAt: -1 });
orderSchema.index({ status: 1 });
const Order = mongoose.model('Order', orderSchema);

// Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Access denied. No token provided or invalid format' });
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('+isActive');
    if (!user || !user.isActive) {
      return res.status(401).json({ message: 'User no longer exists or is inactive' });
    }
    req.userId = decoded.userId;
    req.user = user;
    next();
  } catch (err) {
    logger.error('Auth middleware error:', err);
    if (err.name === 'TokenExpiredError') return res.status(401).json({ message: 'Token expired' });
    if (err.name === 'JsonWebTokenError') return res.status(401).json({ message: 'Invalid token' });
    res.status(401).json({ message: 'Authentication failed' });
  }
};

const validateInput = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details.map(d => d.message).join(', ') });
  next();
};

const sanitizeInput = (req, res, next) => {
  const sanitize = (obj) => {
    for (let key in obj) if (typeof obj[key] === 'string') obj[key] = obj[key].trim();
    next();
  };
  sanitize(req.body);
};

// Routes
app.post('/api/auth/register', authLimiter, sanitizeInput, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 6) {
    return res.status(400).json({ message: 'Invalid email or password' });
  }
  try {
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) return res.status(409).json({ message: 'User already exists' });
    const hashedPassword = await bcrypt.hash(password, NODE_ENV === 'production' ? 12 : 10);
    const user = await new User({ email: email.toLowerCase(), password: hashedPassword }).save();
    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    logger.info(`User registered: ${email}`);
    res.status(201).json({ message: 'User registered', token, user: { id: user._id, email: user.email, createdAt: user.createdAt } });
  } catch (err) {
    logger.error('Registration error:', err);
    if (err.code === 11000) return res.status(409).json({ message: 'User already exists' });
    res.status(500).json({ message: 'Registration failed' });
  }
});

app.post('/api/auth/login', authLimiter, sanitizeInput, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
  try {
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password +loginAttempts +lockUntil');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 5) user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
      await user.save();
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLogin = new Date();
    await user.save();
    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    logger.info(`User logged in: ${email}`);
    res.json({ message: 'Login successful', token, user: { id: user._id, email: user.email, lastLogin: user.lastLogin } });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ message: 'Login failed' });
  }
});

app.get('/api/actions', authMiddleware, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 10));
    const actions = await Action.find({ userId: req.userId }).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean();
    const total = await Action.countDocuments({ userId: req.userId });
    res.json({ actions, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    logger.error('Fetch actions error:', err);
    res.status(500).json({ message: 'Error fetching actions' });
  }
});

app.post('/api/actions', authMiddleware, sanitizeInput, async (req, res) => {
  const { item, quantity, action, metadata } = req.body;
  if (!item || !quantity || !action || !Number.isInteger(quantity) || quantity <= 0 || !['add_to_cart', 'remove_from_cart', 'purchase'].includes(action)) {
    return res.status(400).json({ message: 'Invalid action data' });
  }
  try {
    const newAction = await new Action({ userId: req.userId, item: item.substring(0, 100), quantity, action, metadata: metadata || {} }).save();
    logger.info(`Action saved: ${action} ${item} (${quantity})`);
    res.status(201).json({ message: 'Action saved', action: newAction });
  } catch (err) {
    logger.error('Action save error:', err);
    res.status(500).json({ message: 'Failed to save action' });
  }
});

app.get('/api/coffees', async (req, res) => {
  try {
    const cachedCoffees = cache.get('coffees');
    if (cachedCoffees) return res.json(cachedCoffees);
    let coffees = await Coffee.find({ isAvailable: true }).select('name price image description category').sort({ category: 1, name: 1 }).lean();
    if (coffees.length === 0) {
      const initialCoffees = [
        { name: "Espresso", price: 3.50, image: "https://www.tasteofhome.com/wp-content/uploads/2023/03/TOH-espresso-GettyImages-1291298315-JVcrop.jpg", description: "Rich and bold single shot", category: "Hot Coffee" },
        { name: "Ice Americano", price: 1.50, image: "https://images.ctfassets.net/v601h1fyjgba/1vlXSpBbgUo9yLzh71tnOT/a1afdbe54a383d064576b5e628035f04/Iced_Americano.jpg", description: "Refreshing iced coffee", category: "Iced Coffee" },
        { name: "Cappuccino", price: 4.50, image: "https://www.nescafe.com/nz/sites/default/files/2023-09/NESCAF%C3%89%20Cappuccino.jpg", description: "Perfect balance of espresso and steamed milk", category: "Hot Coffee" },
        { name: "Latte", price: 5.00, image: "https://www.cuisinart.com/dw/image/v2/ABAF_PRD/on/demandware.static/-/Sites-us-cuisinart-sfra-Library/default/dw2ca0aa66/images/recipe-Images/cafe-latte1-recipe.jpg?sw=1200&sh=1200&sm=fit", description: "Smooth and creamy coffee experience", category: "Hot Coffee" },
        { name: "Flat White", price: 4.25, image: "https://methodicalcoffee.com/cdn/shop/articles/Flat_white_sitting_on_a_table_1024x.jpg?v=1695740372", description: "Velvety microfoam perfection", category: "Hot Coffee" },
        { name: "Cold Brew", price: 4.00, image: "https://lifesimplified.gorenje.com/wp-content/uploads/2024/06/gorenje-blog-refreshing_cold_brew_coffee.jpg", description: "Smooth, less acidic coffee", category: "Iced Coffee" },
        { name: "Iced Latte", price: 3.75, image: "https://alidasfood.com/wp-content/uploads/2021/09/Cafe-Latte-Gelado.jpg", description: "Cool and refreshing latte", category: "Iced Coffee" },
      ];
      coffees = await Coffee.insertMany(initialCoffees);
      logger.info('Seeded initial coffee data');
    }
    cache.set('coffees', coffees);
    res.json(coffees);
  } catch (err) {
    logger.error('Fetch coffees error:', err);
    res.status(500).json({ message: 'Error fetching coffee menu' });
  }
});

app.post('/api/orders', authMiddleware, sanitizeInput, async (req, res) => {
  const { items, total, notes, cardDetails } = req.body;
  logger.info('Received order request:', { items, total, notes, cardDetails: { cardHolder: cardDetails?.cardHolder } });
  if (!Array.isArray(items) || items.length === 0 || typeof total !== 'number' || total <= 0) {
    return res.status(400).json({ message: 'Invalid order data' });
  }
  for (const item of items) {
    if (!item.name || !item.price || !item.quantity || typeof item.price !== 'number' || item.price <= 0 || !Number.isInteger(item.quantity) || item.quantity <= 0) {
      return res.status(400).json({ message: 'Invalid item data' });
    }
  }
  const calculatedTotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  if (Math.abs(calculatedTotal - total) > 0.01) {
    return res.status(400).json({ message: 'Order total mismatch' });
  }
  if (!cardDetails || !cardDetails.cardNumber || cardDetails.cardNumber.replace(/\s/g, '').length !== 16 || !cardDetails.expiryDate || !/^\d{2}\/\d{2}$/.test(cardDetails.expiryDate) || !cardDetails.cardHolder || !/^[a-zA-Z\s]+$/.test(cardDetails.cardHolder.trim())) {
    return res.status(400).json({ message: 'Invalid payment details' });
  }
  try {
    const order = await new Order({
      userId: req.userId,
      items: items.map(item => ({ name: item.name.substring(0, 100), price: Math.round(item.price * 100) / 100, quantity: item.quantity })),
      total: Math.round(total * 100) / 100,
      notes: notes ? notes.substring(0, 500) : undefined,
      cardInfo: { cardNumber: cardDetails.cardNumber, expiryDate: cardDetails.expiryDate, cardHolder: cardDetails.cardHolder }
    }).save();
    logger.info(`Order saved: ${order._id}`, { userId: req.userId, total });
    await new Action({ userId: req.userId, item: `Order #${order._id}`, quantity: items.length, action: 'purchase', metadata: { orderId: order._id, total } }).save();
    logger.info(`Order placed by user ${req.userId}: $${total}`);
    res.status(201).json({ message: 'Order placed', order: { id: order._id, items: order.items, total: order.total, status: order.status, createdAt: order.createdAt, cardHolder: order.cardInfo.cardHolder } });
  } catch (err) {
    logger.error('Order creation error:', err);
    res.status(500).json({ message: 'Order placement failed' });
  }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
    const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).select('items total status createdAt notes cardInfo.cardHolder').lean();
    const total = await Order.countDocuments({ userId: req.userId });
    res.json({ orders, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    logger.error('Fetch orders error:', err);
    res.status(500).json({ message: 'Error fetching orders' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage(),
  });
});

app.get('/api/admin/stats', authMiddleware, async (req, res) => {
  try {
    const stats = {
      totalOrders: await Order.countDocuments(),
      totalUsers: await User.countDocuments(),
      totalRevenue: await Order.aggregate([{ $group: { _id: null, total: { $sum: '$total' } } }]),
      recentOrders: await Order.find().sort({ createdAt: -1 }).limit(5).populate('userId', 'email').lean()
    };
    res.json(stats);
  } catch (err) {
    logger.error('Stats fetch error:', err);
    res.status(500).json({ message: 'Error fetching statistics' });
  }
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  if (err.type === 'entity.parse.failed') return res.status(400).json({ message: 'Invalid JSON' });
  if (err.type === 'entity.too.large') return res.status(413).json({ message: 'Request too large' });
  res.status(500).json({ message: NODE_ENV === 'production' ? 'Internal server error' : err.message });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client', 'index.html'));
});

const gracefulShutdown = async (signal) => {
  logger.info(`${signal} received. Shutting down...`);
  try {
    await mongoose.connection.close();
    logger.info('MongoDB closed');
    process.exit(0);
  } catch (err) {
    logger.error('Shutdown error:', err);
    process.exit(1);
  }
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('uncaughtException', (err) => { logger.error('Uncaught Exception:', err); process.exit(1); });
process.on('unhandledRejection', (err) => { logger.error('Unhandled Rejection:', err); process.exit(1); });

const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT} in ${NODE_ENV} mode`);
  logger.info(`Health check: http://localhost:${PORT}/api/health`);
});

server.on('error', (err) => {
  logger.error('Server error:', err);
  if (err.code === 'EADDRINUSE') logger.error(`Port ${PORT} in use`);
  process.exit(1);
});

module.exports = app;