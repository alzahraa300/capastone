const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const cors = require('cors');
require('dotenv').config(); // Add this for environment variables

const app = express();

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/app.log' }),
    new winston.transports.Console(),
  ],
});

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection - Fixed with database name and proper error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://192.168.100.46:27017/mernapp';
const JWT_SECRET = process.env.JWT_SECRET || 'hot fish';
const PORT = process.env.PORT || 5000; // Changed from 27017 to 5000

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => logger.info('Connected to MongoDB'))
  .catch((err) => {
    logger.error('MongoDB connection error:', err);
    process.exit(1); // Exit if can't connect to database
  });

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, {
  timestamps: true // Add timestamps for created/updated dates
});
const User = mongoose.model('User', userSchema);

// Action Schema
const actionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  item: { type: String, required: true },
  quantity: { type: Number, required: true },
  action: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
}, {
  timestamps: true
});
const Action = mongoose.model('Action', actionSchema);

// Authentication Middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided or invalid format' });
  }
  
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    logger.error('Invalid token:', err.message);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Input validation middleware
const validateInput = (requiredFields) => {
  return (req, res, next) => {
    const missingFields = requiredFields.filter(field => !req.body[field]);
    if (missingFields.length > 0) {
      return res.status(400).json({ 
        message: `Missing required fields: ${missingFields.join(', ')}` 
      });
    }
    next();
  };
};

// Register Route
app.post('/api/auth/register', validateInput(['email', 'password']), async (req, res) => {
  const { email, password } = req.body;
  
  // Basic email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }
  
  // Password strength validation
  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }
  
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12); // Increased salt rounds
    const user = new User({ email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    logger.info(`User registered: ${email}`);
    res.status(201).json({ 
      token,
      user: { id: user._id, email: user.email }
    });
  } catch (err) {
    logger.error('Registration error:', err);
    res.status(500).json({ message: 'Registration failed. Please try again.' });
  }
});

// Login Route
app.post('/api/auth/login', validateInput(['email', 'password']), async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn(`Failed login attempt - user not found: ${email}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      logger.warn(`Failed login attempt - wrong password: ${email}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    logger.info(`User logged in: ${email}`);
    res.json({ 
      token,
      user: { id: user._id, email: user.email }
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ message: 'Login failed. Please try again.' });
  }
});

// Get Actions Route
app.get('/api/actions', authMiddleware, async (req, res) => {
  try {
    const actions = await Action.find({ userId: req.userId }).sort({ timestamp: -1 });
    res.json(actions);
  } catch (err) {
    logger.error('Get actions error:', err);
    res.status(500).json({ message: 'Failed to fetch actions' });
  }
});

// Action Route
app.post('/api/actions', authMiddleware, validateInput(['item', 'quantity', 'action']), async (req, res) => {
  const { item, quantity, action } = req.body;
  
  // Validate quantity is a positive number
  if (typeof quantity !== 'number' || quantity <= 0) {
    return res.status(400).json({ message: 'Quantity must be a positive number' });
  }
  
  try {
    const actionData = new Action({ 
      userId: req.userId, 
      item: item.trim(), 
      quantity, 
      action: action.trim() 
    });
    await actionData.save();
    
    logger.info(`Action saved: ${action} - ${item} (${quantity}) by user ${req.userId}`);
    res.status(201).json({ 
      message: 'Action saved successfully',
      action: actionData
    });
  } catch (err) {
    logger.error('Action save error:', err);
    res.status(500).json({ message: 'Failed to save action' });
  }
});

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Shutting down server...');
  await mongoose.connection.close();
  process.exit(0);
});

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`MongoDB URI: ${MONGODB_URI}`);
});