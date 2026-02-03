require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const { query } = require('./db');

const app = express();

/* 🔑 REQUIRED FOR RENDER COOKIES */
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: true, // ✅ FORCE HTTPS COOKIES ON RENDER
  maxAge: 7 * 24 * 60 * 60 * 1000
};

const CATEGORIES = ['Games', 'Consoles', 'Accessories', 'Gift Cards'];
const CONDITIONS = ['Acceptable', 'Used', 'Like New', 'Unpacked'];

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/* ================= AUTH HELPERS ================= */

function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, username: user.username },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

async function hydrateUser(req, res, next) {
  const token = req.cookies.session;
  if (!token) {
    res.locals.currentUser = null;
    return next();
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await query(
      'SELECT id, username, email, avatar_url FROM users WHERE id = $1',
      [payload.id]
    );
    res.locals.currentUser = rows[0] || null;
  } catch {
    res.locals.currentUser = null;
    res.clearCookie('session', COOKIE_OPTIONS);
  }
  next();
}

function requireAuth(req, res, next) {
  if (!res.locals.currentUser) return res.redirect('/auth/sign-in');
  next();
}

app.use(hydrateUser);

/* ================= ROUTES ================= */

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.get('/', async (req, res) => {
  const { rows } = await query(`
    SELECT listings.*, users.username AS seller_name
    FROM listings
    JOIN users ON users.id = listings.seller_id
    ORDER BY listings.created_at DESC
    LIMIT 6
  `);

  res.render('pages/landing', {
    latestListings: rows,
    currentUser: res.locals.currentUser
  });
});

/* ================= AUTH ================= */

app.get('/auth/sign-in', (req, res) => {
  res.render('pages/sign-in', { error: null });
});

app.post('/auth/sign-in', async (req, res) => {
  const email = req.body.email?.toLowerCase().trim();
  const password = req.body.password;

  if (!email || !password) {
    return res.render('pages/sign-in', { error: 'Missing credentials' });
  }

  const { rows } = await query(
    'SELECT * FROM users WHERE email = $1',
    [email]
  );

  const user = rows[0];
  if (!user) {
    return res.render('pages/sign-in', { error: 'Invalid credentials' });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.render('pages/sign-in', { error: 'Invalid credentials' });
  }

  const token = createToken(user);
  res.cookie('session', token, COOKIE_OPTIONS);
  res.redirect('/');
});

app.post('/auth/logout', (req, res) => {
  res.clearCookie('session', COOKIE_OPTIONS);
  res.redirect('/');
});

app.get('/auth/register', (req, res) => {
  res.render('pages/register', { error: null });
});

app.post('/auth/register', async (req, res) => {
  const username = req.body.username?.trim();
  const email = req.body.email?.toLowerCase().trim();
  const password = req.body.password;

  if (!username || !email || !password) {
    return res.render('pages/register', { error: 'All fields required' });
  }

  const hash = await bcrypt.hash(password, 10);

  try {
    const { rows } = await query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email`,
      [username, email, hash]
    );

    const token = createToken(rows[0]);
    res.cookie('session', token, COOKIE_OPTIONS);
    res.redirect('/');
  } catch {
    res.render('pages/register', { error: 'User already exists' });
  }
});

/* ================= MARKETPLACE ================= */

app.get('/marketplace', async (req, res) => {
  const { rows } = await query(`
    SELECT listings.*, users.username AS seller_name
    FROM listings
    JOIN users ON users.id = listings.seller_id
    ORDER BY listings.created_at DESC
  `);

  res.render('pages/marketplace', {
    listings: rows,
    currentUser: res.locals.currentUser
  });
});

/* ================= START ================= */

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
