// Import required modules and libraries
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const csurf = require('csurf');
const session = require('express-session');
const User = require('./models/User'); // User model

// Create an Express application
const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Set up secure HTTP headers using Helmet
app.use(helmet());

// Set up Express session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
}));

// CSRF Protection using csurf
const csrfProtection = csurf({ cookie: true });

// Middleware(s)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Rate Limiter for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5,
  message: 'Too many login attempts, please try again later.'
});

app.use('/login', loginLimiter);

// Define routes

// Homepage route
app.get('/', csrfProtection, (req, res) => {
  res.render('index', { csrfToken: req.csrfToken() });
});

// Login route (GET)
app.get('/login', csrfProtection, (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() });
});

// Login route (POST) with validation
app.post('/login', [
  body('email').isEmail().normalizeEmail().withMessage('Enter a valid email address'),
  body('password').isLength({ min: 5 }).trim().escape().withMessage('Password must be at least 5 characters long'),
  csrfProtection
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  // Find the user in the database based on the email
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err) throw err;
    if (user && bcrypt.compareSync(req.body.password, user.password)) {
      // Store user data in the session upon successful login
      req.session.user = user;
      res.send('Login successful!');
    } else {
      res.status(401).send('Invalid email or password');
    }
  });
});

// Define additional protected routes as needed

// Start the Express server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
