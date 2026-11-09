require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Middleware ----------
app.use(
  helmet({
    // Relaxed so Tailwind CDN, AOS, Phosphor icons and Google Fonts keep working
    contentSecurityPolicy: false,
  })
);
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || true }));
app.use(express.json({ limit: '10kb' }));

// Serve the portfolio (put index.html inside the /public folder)
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Database ----------
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

const messageSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, trim: true, lowercase: true, maxlength: 200 },
    budget: { type: String, required: true, enum: ['< $1k', '$1k - $5k', '$5k - $10k', '$10k+'] },
    details: { type: String, required: true, trim: true, maxlength: 3000 },
    ip: String,
  },
  { timestamps: true }
);
const Message = mongoose.model('Message', messageSchema);

// ---------- Email (optional) ----------
const mailer =
  process.env.SMTP_HOST && process.env.SMTP_USER
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure: Number(process.env.SMTP_PORT) === 465,
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      })
    : null;

// ---------- Contact API ----------
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 submissions per IP per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'Too many requests. Please try again later.' },
});

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/contact', contactLimiter, async (req, res) => {
  try {
    const { name, email, budget, details, website } = req.body || {};

    // Honeypot: real users never fill this hidden field, bots do
    if (website) return res.json({ ok: true });

    if (!name || !email || !budget || !details) {
      return res.status(400).json({ ok: false, error: 'All fields are required.' });
    }
    if (!emailRegex.test(email)) {
      return res.status(400).json({ ok: false, error: 'Please enter a valid email.' });
    }

    const saved = await Message.create({
      name,
      email,
      budget,
      details,
      ip: req.ip,
    });

    // Email notification should never block the response
    if (mailer) {
      mailer
        .sendMail({
          from: `"Portfolio" <${process.env.SMTP_USER}>`,
          to: process.env.NOTIFY_EMAIL || process.env.SMTP_USER,
          replyTo: email,
          subject: `New project enquiry from ${name}`,
          text: `Name: ${name}\nEmail: ${email}\nBudget: ${budget}\n\n${details}`,
        })
        .catch((err) => console.error('Email error:', err.message));
    }

    res.status(201).json({ ok: true, id: saved._id });
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(400).json({ ok: false, error: 'Invalid form data.' });
    }
    console.error(err);
    res.status(500).json({ ok: false, error: 'Something went wrong. Please try again.' });
  }
});

// ---------- Admin: view messages (protected by a secret key) ----------
app.get('/api/messages', async (req, res) => {
  if (!process.env.ADMIN_KEY || req.get('x-admin-key') !== process.env.ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  const messages = await Message.find().sort({ createdAt: -1 }).limit(100);
  res.json({ ok: true, messages });
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
