require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const Validator = require('validator');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const OTP_TTL_MS = 60 * 1000; // 1 минута
const MAX_VERIFY_TRIES = 5;
const RESEND_COOLDOWN_MS = 30 * 1000; // 30 секунд между отправками одному email

// In-memory store (email -> { code, createdAt, tries, timeoutId, lastSentAt })
const otpStore = new Map();

// Nodemailer transporter (Gmail App Password)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Rate limit by IP for /send-otp to avoid spam
const sendLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { success: false, message: 'Too many requests from this IP. Try later.' }
});

// Helper: store OTP and schedule auto-delete
function storeOtp(email, code) {
  const now = Date.now();
  if (otpStore.has(email)) {
    // clear previous timeout if any
    const old = otpStore.get(email);
    if (old.timeoutId) clearTimeout(old.timeoutId);
  }

  const timeoutId = setTimeout(() => {
    otpStore.delete(email);
  }, OTP_TTL_MS);

  otpStore.set(email, {
    code: String(code),
    createdAt: now,
    tries: 0,
    timeoutId,
    lastSentAt: now
  });
}

// Endpoint: send OTP
app.post('/send-otp', sendLimiter, async (req, res) => {
  try {
    const email = (req.body.email || '').toLowerCase();
    if (!Validator.isEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email' });

    // per-email cooldown
    const rec = otpStore.get(email);
    if (rec && (Date.now() - rec.lastSentAt) < RESEND_COOLDOWN_MS) {
      return res.status(429).json({ success: false, message: 'Wait before requesting a new code' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    const mail = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP code',
      text: `Your OTP: ${otp} (valid 1 minute)`,
      html: `<p>Your OTP: <b>${otp}</b></p><p>Valid for 1 minute.</p>`
    };

    await transporter.sendMail(mail);

    storeOtp(email, otp);
    return res.json({ success: true, message: 'OTP sent' });
  } catch (e) {
    console.error('send-otp error', e && e.toString ? e.toString() : e);
    return res.status(500).json({ success: false, message: 'Internal error' });
  }
});

// Endpoint: verify OTP
app.post('/verify-otp', (req, res) => {
  try {
    const email = (req.body.email || '').toLowerCase();
    const code = String(req.body.otp || '');

    if (!Validator.isEmail(email) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ success: false, message: 'Invalid input' });
    }

    const rec = otpStore.get(email);
    if (!rec) return res.status(400).json({ success: false, message: 'Code not found or expired' });

    if (rec.tries >= MAX_VERIFY_TRIES) {
      otpStore.delete(email);
      return res.status(429).json({ success: false, message: 'Too many attempts' });
    }

    if (rec.code !== code) {
      rec.tries = (rec.tries || 0) + 1;
      otpStore.set(email, rec);
      return res.status(400).json({ success: false, message: 'Invalid code' });
    }

    // success: clear timeout and delete
    if (rec.timeoutId) clearTimeout(rec.timeoutId);
    otpStore.delete(email);

    // generate JWT to return (you can change payload)
    const token = jwt.sign({ email }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });

    return res.json({ success: true, token, message: 'Verified' });
  } catch (e) {
    console.error('verify-otp error', e && e.toString ? e.toString() : e);
    return res.status(500).json({ success: false, message: 'Internal error' });
  }
});

app.get('/', (req, res) => res.json({ ok: true, uptime: process.uptime() }));

app.listen(PORT, () => {
  console.log(`OTP server listening on port ${PORT}`);
});