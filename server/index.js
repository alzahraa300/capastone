const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const cors = require('cors');
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

// MongoDB Connection
mongoose.connect('mongodb://10.0.2.15:27017/mern_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => logger.info('Connected to MongoDB'))
  .catch((err) => logger.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// Action Schema
const actionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  item: { type: String, required: true },
  quantity: { type: Number, required: true },
  action: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});
const Action = mongoose.model('Action', actionSchema);

// Authentication Middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, 'secret_key');
    req.userId = decoded.userId;
    next();
  } catch (err) {
    logger.error('Invalid token:', err);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Register Route
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });
    logger.info(`User registered: ${email}`);
    res.json({ token });
  } catch (err) {
    logger.error('Registration error:', err);
    res.status(400).json({ message: 'Registration failed' });
  }
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      logger.warn(`Failed login attempt for: ${email}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });
    logger.info(`User logged in: ${email}`);
    res.json({ token });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(400).json({ message: 'Login failed' });
  }
});

// Action Route
app.post('/api/actions', authMiddleware, async (req, res) => {
  const { item, quantity, action } = req.body;
  try {
    const actionData = new Action({ userId: req.userId, item, quantity, action });
    await actionData.save();
    logger.info(`Action saved: ${action} by user ${req.userId}`);
    res.json({ message: 'Action saved' });
  } catch (err) {
    logger.error('Action save error:', err);
    res.status(400).json({ message: 'Failed to save action' });
  }
});

app.listen(5000, () => logger.info('Server running on port 5000'));