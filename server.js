const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // for random token
require('dotenv').config();

// Models Import
const Contact = require('./models/Contact');
const User = require('./models/User');

const app = express();

// --- CLEAN & SOLID CORS CONFIGURATION ---
const allowedOrigins = [
  "http://localhost:5173",
  "https://portfolio-frontend-vert-pi.vercel.app",
  "https://portfolio-frontend-vert-pi.vercel.app/",
   "portfolio-frontend-vert-pi.vercel.app"
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization", "x-encryption-version"]
}));

// Express Essentials
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('🍃 MongoDB connected successfully...'))
  .catch(err => console.error('❌ Database connection error:', err));

// --- EMAIL CONFIGURATION (Nodemailer) ---
const transporter = nodemailer.createTransport({
  host: 'smtp.ethereal.email',
  port: 587,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// --- API ROUTES ---

// Base Check Route
app.get('/', (req, res) => {
  res.send('Portfolio Backend Engine is running smoothly.');
});

// 1. Contact Us API Route
app.post('/api/contacts', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }
    const newContact = new Contact({ name, email, message });
    await newContact.save();
    res.status(201).json({ success: true, message: 'Message saved successfully!' });
  } catch (error) {
    console.error('Contact Error:', error);
    res.status(500).json({ success: false, error: 'Server Error' });
  }
});

// 2. USER SIGNUP API
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: 'Please enter all fields' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'User already exists with this email' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const token = crypto.randomBytes(32).toString('hex');

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      verificationToken: token
    });
    await newUser.save();

    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const host = req.get('host');
    const verificationUrl = `${protocol}://${host}/api/auth/verify/${token}`;

    const mailOptions = {
      from: '"Portfolio Portal" <no-reply@portfolio.com>',
      to: email,
      subject: 'Verify Your Portfolio Account',
      html: `
        <h2>Welcome to the Portfolio App, ${name}!</h2>
        <p>Please click the link below to verify your email address and activate your account:</p>
        <a href="${verificationUrl}" target="_blank" style="padding: 10px 20px; background-color: #14342b; color: white; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a>
        <br/><br/>
        <p>If the button doesn't work, copy-paste this link into your browser:</p>
        <p>${verificationUrl}</p>
      `
    };

    await transporter.sendMail(mailOptions);
    res.status(201).json({ 
      success: true, 
      message: 'Registration successful! Please check your Ethereal inbox to verify your email.' 
    });

  } catch (error) {
    console.error('Signup Error:', error);
    res.status(500).json({ success: false, error: 'Server Error during signup' });
  }
});

// 3. EMAIL VERIFICATION API ROUTE
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res.status(400).send('<h1>Verification failed. Invalid or expired token.</h1>');
    }

    user.isVerified = true;
    user.verificationToken = undefined; 
    await user.save();

    res.send(`
      <div style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1 style="color: #14342b;">Email Verified Successfully! 🎉</h1>
        <p>Hi ${user.name}, your account is now fully active. You can now log in from the frontend.</p>
      </div>
    `);

  } catch (error) {
    console.error('Verification Error:', error);
    res.status(500).send('<h1>Server Error during verification</h1>');
  }
});

// 4. USER LOGIN API
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Please enter all fields' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(400).json({ 
        success: false, 
        error: 'Your email is not verified yet. Please check your inbox.' 
      });
    }

    res.status(200).json({
      success: true,
      message: 'Login successful! Welcome back.',
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ success: false, error: 'Server Error during login' });
  }
});

// Vercel Serverless Export Architecture
const PORT = process.env.PORT || 5000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`🚀 Server running locally on port ${PORT}`);
  });
}

module.exports = app;