require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const { pool, query } = require('./db');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const EMAIL_FROM = process.env.EMAIL_FROM || 'therealsellar@gmail.com';
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-cookie-secret-change-me';
const RESET_CODE_TTL_MINUTES = 15;
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_COOKIE = 'session';
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const CATEGORIES = ['Games', 'Consoles', 'Accessories', 'Gift Cards'];
const CONDITIONS = ['Acceptable', 'Used', 'Like New', 'Unpacked'];
const MAX_USERNAME_LENGTH = 24;
const MAX_BIO_LENGTH = 280;
const MAX_LISTING_TITLE_LENGTH = 80;
const MAX_LISTING_DESCRIPTION_LENGTH = 2000;
const MAX_SHIPPING_DETAILS_LENGTH = 280;
const MAX_MESSAGE_LENGTH = 2000;
const OAUTH_STATE_COOKIE = 'oauth_state';
const OAUTH_ACTION_COOKIE = 'oauth_action';
const OAUTH_LINK_COOKIE = 'oauth_link';
const RESERVED_PROFILE_PATHS = new Set([
  'marketplace',
  'listings',
  'auth',
  'profile',
  'settings',
  'messages',
  'orders',
  'dashboard',
  'favorites',
  'chess',
  'terms',
  'thread',
  'orders',
  'uploads',
  'admin',
  'reset-password',
  'forgot-password',
  'sign-in',
  'register',
  'link-google'
]);

const cloudinaryConfig = {
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
};
const isCloudinaryConfigured = Boolean(
  cloudinaryConfig.cloud_name && cloudinaryConfig.api_key && cloudinaryConfig.api_secret
);

if (isCloudinaryConfigured) {
  cloudinary.config(cloudinaryConfig);
}

const uploadDir = process.env.UPLOAD_DIR
  ? path.resolve(process.env.UPLOAD_DIR)
  : path.join(__dirname, 'public', 'uploads');
if (!isCloudinaryConfigured && !fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const isProduction = process.env.NODE_ENV === 'production';
const storage = isCloudinaryConfigured || isProduction
  ? multer.memoryStorage()
  : multer.diskStorage({
      destination: uploadDir,
      filename: (req, file, cb) => {
        const timestamp = Date.now();
        const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '-');
        cb(null, `${timestamp}-${safeName}`);
      }
    });

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    if (file.mimetype && file.mimetype.startsWith('image/')) {
      return cb(null, true);
    }
    const error = new Error('Only image files are allowed.');
    error.status = 400;
    return cb(error);
  }
});

const uploadListingImage = upload.single('image');
const uploadAvatarImage = upload.single('avatar');
const uploadSettingsImages = upload.fields([
  { name: 'avatar', maxCount: 1 },
  { name: 'background', maxCount: 1 }
]);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
if (!isCloudinaryConfigured) {
  app.use('/uploads', express.static(uploadDir));
}

ensureSessionsTable().catch((error) => {
  console.error('Failed to ensure sessions table exists:', error);
});
ensureUserAuthColumns().catch((error) => {
  console.error('Failed to ensure auth columns exist:', error);
});
ensureChessTables().catch((error) => {
  console.error('Failed to ensure chess tables exist:', error);
});
ensureAdminAuditTable().catch((error) => {
  console.error('Failed to ensure admin audit table exists:', error);
});
ensureListingEngagementTables().catch((error) => {
  console.error('Failed to ensure listing engagement tables exist:', error);
});

function formatPrice(cents) {
  return `$${(cents / 100).toFixed(2)}`;
}

function normalizeText(value, maxLength) {
  if (!value) return '';
  const trimmed = value.trim().replace(/\s+/g, ' ');
  if (typeof maxLength === 'number') {
    return trimmed.slice(0, maxLength);
  }
  return trimmed;
}

function isValidHexColor(value) {
  return /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(value);
}

async function incrementListingView(listingId) {
  await query(
    `INSERT INTO listing_engagement (listing_id, view_count, click_count)
     VALUES ($1, 1, 0)
     ON CONFLICT (listing_id)
     DO UPDATE SET view_count = listing_engagement.view_count + 1, updated_at = NOW()`,
    [listingId]
  );
}

async function incrementListingClick(listingId) {
  await query(
    `INSERT INTO listing_engagement (listing_id, view_count, click_count)
     VALUES ($1, 0, 1)
     ON CONFLICT (listing_id)
     DO UPDATE SET click_count = listing_engagement.click_count + 1, updated_at = NOW()`,
    [listingId]
  );
}

async function ensureSessionsTable() {
  await query(
    `CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`
  );
}

async function ensureUserAuthColumns() {
  await query('ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT');
  await query('ALTER TABLE users ADD COLUMN IF NOT EXISTS google_email TEXT');
  await query('ALTER TABLE users ADD COLUMN IF NOT EXISTS steam_id TEXT');
  await query('ALTER TABLE users ADD COLUMN IF NOT EXISTS steam_profile_url TEXT');
  await query('ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_background_url TEXT');
  await query('ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_background_color TEXT');
  await query('ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE');
  await query('ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE');
  await query('CREATE UNIQUE INDEX IF NOT EXISTS users_google_id_unique ON users (google_id)');
  await query('CREATE UNIQUE INDEX IF NOT EXISTS users_google_email_unique ON users (google_email)');
  await query('CREATE UNIQUE INDEX IF NOT EXISTS users_steam_id_unique ON users (steam_id)');
}

async function ensureChessTables() {
  await query(
    `CREATE TABLE IF NOT EXISTS chess_invites (
      id SERIAL PRIMARY KEY,
      inviter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      invitee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`
  );
  await query(
    `CREATE TABLE IF NOT EXISTS chess_matches (
      id SERIAL PRIMARY KEY,
      white_player_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      black_player_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`
  );
}

async function ensureAdminAuditTable() {
  await query(
    `CREATE TABLE IF NOT EXISTS admin_audit_logs (
      id SERIAL PRIMARY KEY,
      admin_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id INTEGER,
      details TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`
  );
}

async function ensureListingEngagementTables() {
  await query(
    `CREATE TABLE IF NOT EXISTS listing_engagement (
      listing_id INTEGER PRIMARY KEY REFERENCES listings(id) ON DELETE CASCADE,
      view_count INTEGER NOT NULL DEFAULT 0,
      click_count INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`
  );
  await query(
    `CREATE TABLE IF NOT EXISTS listing_favorites (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (user_id, listing_id)
    )`
  );
  await query(
    'CREATE INDEX IF NOT EXISTS listing_favorites_listing_idx ON listing_favorites (listing_id)'
  );
  await query(
    'CREATE INDEX IF NOT EXISTS listing_favorites_user_idx ON listing_favorites (user_id)'
  );
}

function hashSessionToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashSessionToken(token);
  await query(
    `INSERT INTO sessions (user_id, token_hash, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
    [userId, tokenHash]
  );
  return token;
}

function resolveCookieSecure(req) {
  if (process.env.COOKIE_SECURE === 'true') return true;
  if (process.env.COOKIE_SECURE === 'false') return false;
  return process.env.NODE_ENV === 'production' && Boolean(req.secure);
}

function setTempCookie(req, res, name, value, maxAgeMs) {
  res.cookie(name, value, {
    httpOnly: true,
    sameSite: 'lax',
    secure: resolveCookieSecure(req),
    maxAge: maxAgeMs
  });
}

function clearTempCookie(req, res, name) {
  res.clearCookie(name, {
    httpOnly: true,
    sameSite: 'lax',
    secure: resolveCookieSecure(req)
  });
}

function encodeTempPayload(payload) {
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

function decodeTempPayload(value) {
  if (!value) return null;
  try {
    return JSON.parse(Buffer.from(value, 'base64').toString('utf-8'));
  } catch (error) {
    return null;
  }
}

function getGoogleConfig(req) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  const redirectUri =
    process.env.GOOGLE_REDIRECT_URI || `${req.protocol}://${req.get('host')}/auth/google/callback`;
  return { clientId, clientSecret, redirectUri };
}

async function exchangeGoogleCode(config, code) {
  const params = new URLSearchParams({
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: config.redirectUri,
    grant_type: 'authorization_code'
  });
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Google token exchange failed: ${errorText}`);
  }
  return response.json();
}

async function fetchGoogleProfile(accessToken) {
  const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Google profile request failed: ${errorText}`);
  }
  return response.json();
}

async function generateUniqueUsername(baseName) {
  const sanitized = baseName.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase() || 'player';
  let candidate = sanitized.slice(0, 18) || 'player';
  let suffix = 0;
  while (true) {
    const { rows } = await query('SELECT id FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1', [candidate]);
    if (!rows.length) {
      return candidate;
    }
    suffix += 1;
    candidate = `${sanitized.slice(0, 16)}${suffix}`;
  }
}

function setSessionCookie(req, res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    maxAge: SESSION_MAX_AGE_MS,
    sameSite: 'lax',
    secure: resolveCookieSecure(req),
    path: '/'
  });
}

function clearSessionCookie(req, res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    sameSite: 'lax',
    secure: resolveCookieSecure(req),
    path: '/'
  });
}

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function isValidEmail(email) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
}

function generateResetCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function getResetCodeExpiry() {
  return new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60 * 1000);
}

function createMailer() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return null;
  }
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT || 587) === 465,
    connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT_MS || 10000),
    greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT_MS || 10000),
    socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT_MS || 15000),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

async function sendResetEmail({ email, code }) {
  const transporter = createMailer();
  if (!transporter) {
    const error = new Error('Email service is not configured.');
    error.status = 500;
    throw error;
  }
  await transporter.sendMail({
    from: EMAIL_FROM,
    to: email,
    subject: 'Sellar password reset code',
    text: `Your Sellar reset code is ${code}. It expires in ${RESET_CODE_TTL_MINUTES} minutes.`,
    html: `<p>Your Sellar reset code is <strong>${code}</strong>. It expires in ${RESET_CODE_TTL_MINUTES} minutes.</p>`
  });
}

async function uploadImage(file) {
  if (!file) {
    return null;
  }
  if (!isCloudinaryConfigured) {
    const error = new Error(
      'Cloudinary is not configured for uploads. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET.'
    );
    error.status = 500;
    console.error('Cloudinary configuration error:', error.message);
    throw error;
  }
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'safeswap', resource_type: 'image' },
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload failed:', error);
          return reject(error);
        }
        return resolve(result.secure_url);
      }
    );
    streamifier.createReadStream(file.buffer).pipe(stream);
  });
}

function handleUpload(uploadFn, onError) {
  return (req, res, next) => {
    uploadFn(req, res, (error) => {
      if (!error) {
        return next();
      }
      const message =
        error.code === 'LIMIT_FILE_SIZE' ? 'Image must be smaller than 5MB.' : error.message || 'Upload failed.';
      return onError(req, res, message, next);
    });
  };
}

function isEmailLike(value) {
  return Boolean(value && value.includes('@'));
}

function pickMergedUsername(primaryUsername, secondaryUsername) {
  if (!primaryUsername) return secondaryUsername;
  if (!secondaryUsername) return primaryUsername;
  if (isEmailLike(primaryUsername) && !isEmailLike(secondaryUsername)) {
    return secondaryUsername;
  }
  return primaryUsername;
}

async function mergeUsers(primaryUser, secondaryUser, { passwordHash } = {}) {
  const finalUsername = pickMergedUsername(primaryUser.username, secondaryUser.username);
  const finalPasswordHash = passwordHash || primaryUser.password_hash;
  await query('UPDATE users SET username = $1, password_hash = $2 WHERE id = $3', [
    finalUsername,
    finalPasswordHash,
    primaryUser.id
  ]);
  await query('UPDATE listings SET seller_id = $1 WHERE seller_id = $2', [primaryUser.id, secondaryUser.id]);
  await query('UPDATE orders SET buyer_id = $1 WHERE buyer_id = $2', [primaryUser.id, secondaryUser.id]);
  await query('UPDATE threads SET buyer_id = $1 WHERE buyer_id = $2', [primaryUser.id, secondaryUser.id]);
  await query('UPDATE threads SET seller_id = $1 WHERE seller_id = $2', [primaryUser.id, secondaryUser.id]);
  await query('UPDATE messages SET sender_id = $1 WHERE sender_id = $2', [primaryUser.id, secondaryUser.id]);
  await query('DELETE FROM users WHERE id = $1', [secondaryUser.id]);
}

async function getUserBySession(token) {
  if (!token) return null;
  const tokenHash = hashSessionToken(token);
  const { rows } = await query(
    `SELECT users.* FROM users
     JOIN sessions ON users.id = sessions.user_id
     WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW()
     LIMIT 1`,
    [tokenHash]
  );
  return rows[0] || null;
}

async function refreshUserSession(req, res) {
  const token = req.cookies[SESSION_COOKIE];
  if (!token) {
    return null;
  }
  const user = await getUserBySession(token);
  if (user) {
    res.locals.currentUser = user;
  }
  return user;
}

async function requireAuth(req, res, next) {
  const user = await refreshUserSession(req, res);
  if (!user) {
    return res.redirect('/auth/sign-in');
  }
  next();
}

function isAdminUser(user) {
  return (
    user &&
    user.username === 'Admin' &&
    user.email &&
    user.email.toLowerCase() === 'mariusjon101@gmail.com'
  );
}

function isReservedProfilePath(username) {
  if (!username) {
    return true;
  }
  return RESERVED_PROFILE_PATHS.has(username.toLowerCase());
}

function requireAdmin(req, res, next) {
  if (!isAdminUser(res.locals.currentUser)) {
    return res.status(403).render('pages/error', { message: 'You do not have access to this page.' });
  }
  next();
}

async function getProfilePayload(userId) {
  const { rows: userRows } = await query('SELECT * FROM users WHERE id = $1', [userId]);
  const user = userRows[0];
  const { rows: listingRows } = await query(
    'SELECT COUNT(*) as count FROM listings WHERE seller_id = $1',
    [userId]
  );
  const listingCount = Number(listingRows[0].count);
  const { rows: salesRows } = await query('SELECT COUNT(*) as count FROM orders WHERE seller_id = $1', [userId]);
  const salesCount = Number(salesRows[0].count);
  const { rows: listings } = await query(
    'SELECT * FROM listings WHERE seller_id = $1 ORDER BY created_at DESC LIMIT 6',
    [userId]
  );
  return { user, listingCount, salesCount, listings };
}

async function getPublicProfilePayload(username) {
  const trimmedUsername = (username || '').trim();
  if (!trimmedUsername) {
    return null;
  }
  const { rows: userRows } = await query(
    'SELECT * FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1',
    [trimmedUsername]
  );
  const user = userRows[0];
  if (!user) {
    return null;
  }
  const { rows: listingRows } = await query(
    'SELECT COUNT(*) as count FROM listings WHERE seller_id = $1',
    [user.id]
  );
  const listingCount = Number(listingRows[0].count);
  const { rows: salesRows } = await query('SELECT COUNT(*) as count FROM orders WHERE seller_id = $1', [user.id]);
  const salesCount = Number(salesRows[0].count);
  const { rows: listings } = await query(
    `SELECT listings.*, users.username AS seller_name
     FROM listings
     JOIN users ON listings.seller_id = users.id
     WHERE listings.seller_id = $1
     ORDER BY listings.created_at DESC
     LIMIT 8`,
    [user.id]
  );
  return { user, listingCount, salesCount, listings };
}

async function getSettingsPayload(userId) {
  const { rows: userRows } = await query('SELECT * FROM users WHERE id = $1', [userId]);
  const user = userRows[0];
  const { rows: listings } = await query(
    'SELECT * FROM listings WHERE seller_id = $1 ORDER BY created_at DESC',
    [userId]
  );
  return { user, listings };
}

async function getUserDashboardPayload(userId) {
  const { rows: listings } = await query(
    `SELECT listings.*,
            COALESCE(engagement.view_count, 0) AS view_count,
            COALESCE(engagement.click_count, 0) AS click_count,
            COUNT(favorites.user_id) AS favorite_count
     FROM listings
     LEFT JOIN listing_engagement AS engagement ON engagement.listing_id = listings.id
     LEFT JOIN listing_favorites AS favorites ON favorites.listing_id = listings.id
     WHERE listings.seller_id = $1
     GROUP BY listings.id, engagement.view_count, engagement.click_count
     ORDER BY listings.created_at DESC`,
    [userId]
  );

  const stats = listings.reduce(
    (totals, listing) => {
      totals.views += Number(listing.view_count || 0);
      totals.clicks += Number(listing.click_count || 0);
      totals.favorites += Number(listing.favorite_count || 0);
      return totals;
    },
    { views: 0, clicks: 0, favorites: 0 }
  );

  return { listings, stats };
}

async function getAdminDashboardPayload() {
  const { rows: users } = await query(
    'SELECT id, username, email, created_at FROM users ORDER BY created_at DESC'
  );
  const { rows: listings } = await query(
    `SELECT listings.*, users.username AS seller_name
     FROM listings
     JOIN users ON listings.seller_id = users.id
     ORDER BY listings.created_at DESC`
  );
  return { users, listings };
}

app.use(asyncHandler(async (req, res, next) => {
  await refreshUserSession(req, res);
  res.locals.currentPath = req.path;
  res.locals.isActivePath = (pathPrefix) => req.path === pathPrefix || req.path.startsWith(`${pathPrefix}/`);
  res.locals.isAdmin = isAdminUser(res.locals.currentUser);
  next();
}));

app.get(
  '/',
  asyncHandler(async (req, res) => {
    const { rows: statsRows } = await query(
      `SELECT
        (SELECT COUNT(*) FROM users) AS users_count,
        (SELECT COUNT(*) FROM listings) AS listings_count,
        (SELECT COUNT(*) FROM orders) AS orders_count`
    );
    const stats = statsRows[0];
    const { rows: latestListings } = await query(
      `SELECT listings.*, users.username AS seller_name
       FROM listings
       JOIN users ON listings.seller_id = users.id
       ORDER BY listings.created_at DESC
       LIMIT 6`
    );
    const { rows: trendingListings } = await query(
      `SELECT listings.*, users.username AS seller_name, COUNT(orders.id) AS order_count
       FROM listings
       JOIN users ON listings.seller_id = users.id
       LEFT JOIN orders ON orders.listing_id = listings.id
       GROUP BY listings.id, users.username
       ORDER BY COUNT(orders.id) DESC, listings.created_at DESC
       LIMIT 6`
    );
    res.render('pages/landing', {
      stats,
      categories: CATEGORIES,
      latestListings,
      trendingListings,
      formatPrice
    });
  })
);

app.get('/terms', (req, res) => {
  res.render('pages/terms');
});

app.get('/auth/register', (req, res) => {
  res.render('pages/register', { error: null, form: {} });
});

app.post(
  '/auth/register',
  asyncHandler(async (req, res) => {
    const username = (req.body.username || '').trim();
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword || req.body.passwordConfirm;
    if (!username || !email || !password || !confirmPassword) {
      return res.render('pages/register', {
        error: 'All fields are required.',
        form: { username, email }
      });
    }
    if (!isValidEmail(email)) {
      return res.render('pages/register', {
        error: 'Please enter a valid email.',
        form: { username, email }
      });
    }
    if (password.length < 8) {
      return res.render('pages/register', {
        error: 'Password must be at least 8 characters.',
        form: { username, email }
      });
    }
    if (password !== confirmPassword) {
      return res.render('pages/register', {
        error: 'Passwords do not match.',
        form: { username, email }
      });
    }
    const { rows: existingUsers } = await query('SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [
      email
    ]);
    if (existingUsers.length) {
      return res.render('pages/register', {
        error: 'That email is already registered.',
        form: { username, email }
      });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const { rows } = await query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [username, email, passwordHash]
    );
    const userId = rows[0].id;
    const token = await createSession(userId);
    setSessionCookie(req, res, token);
    return res.redirect('/marketplace');
  })
);

app.get('/auth/sign-in', (req, res) => {
  res.render('pages/sign-in', { error: null, identifier: '' });
});

app.post(
  '/auth/sign-in',
  asyncHandler(async (req, res) => {
    const identifier = (req.body.identifier || req.body.login || '').trim();
    const password = req.body.password;
    if (!identifier || !password) {
      return res.render('pages/sign-in', { error: 'All fields are required.', identifier });
    }
    let user = null;
    if (isValidEmail(identifier)) {
      const { rows } = await query('SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [identifier]);
      user = rows[0];
    } else {
      const { rows } = await query('SELECT * FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1', [identifier]);
      user = rows[0];
    }
    if (!user) {
      return res.render('pages/sign-in', { error: 'Invalid credentials.', identifier });
    }
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.render('pages/sign-in', { error: 'Invalid credentials.', identifier });
    }
    const token = await createSession(user.id);
    setSessionCookie(req, res, token);
    return res.redirect('/marketplace');
  })
);

app.get(
  '/auth/google',
  asyncHandler(async (req, res) => {
    const config = getGoogleConfig(req);
    if (!config) {
      return res.status(500).render('pages/error', { message: 'Google login is not configured.' });
    }
    const action = req.query.action === 'link' ? 'link' : 'signin';
    if (action === 'link') {
      const currentUser = await refreshUserSession(req, res);
      if (!currentUser) {
        return res.redirect('/auth/sign-in');
      }
    }
    const state = crypto.randomBytes(16).toString('hex');
    setTempCookie(req, res, OAUTH_STATE_COOKIE, state, 10 * 60 * 1000);
    setTempCookie(req, res, OAUTH_ACTION_COOKIE, action, 10 * 60 * 1000);
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      state,
      prompt: 'select_account'
    });
    return res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
  })
);

app.get(
  '/auth/google/callback',
  asyncHandler(async (req, res) => {
    const config = getGoogleConfig(req);
    if (!config) {
      return res.status(500).render('pages/error', { message: 'Google login is not configured.' });
    }
    if (req.query.error) {
      return res.status(400).render('pages/error', { message: 'Google sign-in was cancelled.' });
    }
    const stateCookie = req.cookies[OAUTH_STATE_COOKIE];
    const actionCookie = req.cookies[OAUTH_ACTION_COOKIE];
    if (!stateCookie || stateCookie !== req.query.state) {
      return res.status(400).render('pages/error', { message: 'Invalid Google sign-in state.' });
    }
    clearTempCookie(req, res, OAUTH_STATE_COOKIE);
    clearTempCookie(req, res, OAUTH_ACTION_COOKIE);

    const tokenResponse = await exchangeGoogleCode(config, req.query.code);
    const profile = await fetchGoogleProfile(tokenResponse.access_token);
    const googleId = profile.id;
    const googleEmail = (profile.email || '').toLowerCase();

    if (!googleId || !googleEmail) {
      return res.status(400).render('pages/error', { message: 'Google profile data was incomplete.' });
    }

    const action = actionCookie === 'link' ? 'link' : 'signin';
    if (action === 'link') {
      const currentUser = await refreshUserSession(req, res);
      if (!currentUser) {
        return res.redirect('/auth/sign-in');
      }
      const { rows: existingGoogle } = await query('SELECT id FROM users WHERE google_id = $1 LIMIT 1', [googleId]);
      if (existingGoogle.length && existingGoogle[0].id !== currentUser.id) {
        const { user, listings } = await getSettingsPayload(currentUser.id);
        return res.render('pages/settings', {
          user,
          listings,
          formatPrice,
          error: 'That Google account is already linked to another user.',
          success: null
        });
      }
      const { rows: emailOwner } = await query('SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [
        googleEmail
      ]);
      if (emailOwner.length && emailOwner[0].id !== currentUser.id) {
        const { user, listings } = await getSettingsPayload(currentUser.id);
        return res.render('pages/settings', {
          user,
          listings,
          formatPrice,
          error: 'That Gmail belongs to a different account. Sign in to that account to link it.',
          success: null
        });
      }
      await query('UPDATE users SET google_id = $1, google_email = $2 WHERE id = $3', [
        googleId,
        googleEmail,
        currentUser.id
      ]);
      if (currentUser) {
        currentUser.google_id = googleId;
        currentUser.google_email = googleEmail;
      }
      const { user, listings } = await getSettingsPayload(currentUser.id);
      return res.render('pages/settings', {
        user,
        listings,
        formatPrice,
        error: null,
        success: 'Google account linked successfully.'
      });
    }

    const { rows: googleUsers } = await query('SELECT * FROM users WHERE google_id = $1 LIMIT 1', [googleId]);
    if (googleUsers.length) {
      const token = await createSession(googleUsers[0].id);
      setSessionCookie(req, res, token);
      return res.redirect('/marketplace');
    }

    const { rows: existingEmailUsers } = await query('SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [
      googleEmail
    ]);
    if (existingEmailUsers.length) {
      const linkPayload = encodeTempPayload({
        googleId,
        googleEmail,
        name: profile.name,
        picture: profile.picture,
        issuedAt: Date.now()
      });
      setTempCookie(req, res, OAUTH_LINK_COOKIE, linkPayload, 10 * 60 * 1000);
      return res.render('pages/link-google', { email: googleEmail, error: null });
    }

    const username = await generateUniqueUsername(profile.given_name || profile.name || googleEmail.split('@')[0]);
    const passwordHash = await bcrypt.hash(crypto.randomBytes(24).toString('hex'), 10);
    const { rows: newUsers } = await query(
      'INSERT INTO users (username, email, password_hash, google_id, google_email, avatar_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
      [username, googleEmail, passwordHash, googleId, googleEmail, profile.picture || null]
    );
    const token = await createSession(newUsers[0].id);
    setSessionCookie(req, res, token);
    return res.redirect('/marketplace');
  })
);

app.post(
  '/auth/google/link',
  asyncHandler(async (req, res) => {
    const payload = decodeTempPayload(req.cookies[OAUTH_LINK_COOKIE]);
    if (!payload || Date.now() - payload.issuedAt > 10 * 60 * 1000) {
      clearTempCookie(req, res, OAUTH_LINK_COOKIE);
      return res.redirect('/auth/sign-in');
    }
    const password = req.body.password;
    if (!password) {
      return res.render('pages/link-google', { email: payload.googleEmail, error: 'Password is required.' });
    }
    const { rows } = await query('SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [
      payload.googleEmail
    ]);
    const user = rows[0];
    if (!user) {
      clearTempCookie(req, res, OAUTH_LINK_COOKIE);
      return res.redirect('/auth/sign-in');
    }
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.render('pages/link-google', { email: payload.googleEmail, error: 'Incorrect password.' });
    }
    const { rows: existingGoogle } = await query('SELECT id FROM users WHERE google_id = $1 LIMIT 1', [
      payload.googleId
    ]);
    if (existingGoogle.length && existingGoogle[0].id !== user.id) {
      clearTempCookie(req, res, OAUTH_LINK_COOKIE);
      return res.render('pages/link-google', { email: payload.googleEmail, error: 'Google account already linked.' });
    }
    await query('UPDATE users SET google_id = $1, google_email = $2 WHERE id = $3', [
      payload.googleId,
      payload.googleEmail,
      user.id
    ]);
    clearTempCookie(req, res, OAUTH_LINK_COOKIE);
    const token = await createSession(user.id);
    setSessionCookie(req, res, token);
    return res.redirect('/marketplace');
  })
);

app.post('/auth/logout', (req, res) => {
  clearSessionCookie(req, res);
  return res.redirect('/');
});

app.get('/auth/forgot-password', (req, res) => {
  res.render('pages/forgot-password', { error: null, success: null });
});

app.post(
  '/auth/forgot-password',
  asyncHandler(async (req, res) => {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email || !isValidEmail(email)) {
      return res.render('pages/forgot-password', { 
        error: 'Please enter a valid email.', 
        success: null 
      });
    }
    
    let debugCode = null;
    let successMessage = 'If that email exists, we sent a 6-digit reset code. Enter it below to reset your password.';
    
    const { rows } = await query('SELECT id, email FROM users WHERE email = $1', [email]);
    const user = rows[0];
    
    if (user) {
      const code = generateResetCode();
      const codeHash = await bcrypt.hash(code, 10);
      
      await query('UPDATE password_reset_codes SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL', [
        user.id
      ]);
      await query(
        `INSERT INTO password_reset_codes (user_id, code_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, codeHash, getResetCodeExpiry()]
      );
      
      try {
        await sendResetEmail({ email: user.email, code });
      } catch (mailError) {
        console.error('Password reset email failed:', mailError);
        
        if (process.env.NODE_ENV !== 'production') {
          debugCode = code;
          successMessage = 'Email delivery is not configured. Use the reset code below to continue.';
        }
      }
    }
    
    return res.render('pages/reset-password', {
      error: null,
      success: successMessage,
      email,
      debugCode
    });
  })
);

app.get('/auth/reset-password', (req, res) => {
  res.render('pages/reset-password', { error: null, success: null, email: req.query.email || '', debugCode: null });
});

app.post(
  '/auth/reset-password',
  asyncHandler(async (req, res) => {
    const email = (req.body.email || '').trim().toLowerCase();
    const code = (req.body.code || '').trim();
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;
    
    if (!email || !isValidEmail(email)) {
      return res.render('pages/reset-password', { 
        error: 'Please enter a valid email.', 
        success: null, 
        email,
        debugCode: null 
      });
    }
    if (!code || !/^\d{6}$/.test(code)) {
      return res.render('pages/reset-password', { 
        error: 'Enter the 6-digit code from your email.', 
        success: null, 
        email,
        debugCode: null 
      });
    }
    if (!password || password.length < 8) {
      return res.render('pages/reset-password', {
        error: 'Password must be at least 8 characters.',
        success: null,
        email,
        debugCode: null
      });
    }
    if (password !== confirmPassword) {
      return res.render('pages/reset-password', { 
        error: 'Passwords do not match.', 
        success: null, 
        email,
        debugCode: null 
      });
    }
    
    const { rows } = await query('SELECT id FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) {
      return res.render('pages/reset-password', { 
        error: 'Invalid reset details.', 
        success: null, 
        email,
        debugCode: null 
      });
    }
    
    const { rows: codeRows } = await query(
      `SELECT id, code_hash, expires_at
       FROM password_reset_codes
       WHERE user_id = $1 AND used_at IS NULL
       ORDER BY created_at DESC
       LIMIT 1`,
      [user.id]
    );
    const resetRow = codeRows[0];
    if (!resetRow) {
      return res.render('pages/reset-password', { 
        error: 'Reset code is invalid or expired.', 
        success: null, 
        email,
        debugCode: null 
      });
    }
    if (resetRow.expires_at && new Date(resetRow.expires_at).getTime() < Date.now()) {
      return res.render('pages/reset-password', { 
        error: 'Reset code is expired.', 
        success: null, 
        email,
        debugCode: null 
      });
    }
    const codeValid = await bcrypt.compare(code, resetRow.code_hash);
    if (!codeValid) {
      return res.render('pages/reset-password', { 
        error: 'Reset code is invalid.', 
        success: null, 
        email,
        debugCode: null 
      });
    }
    
    const newHash = await bcrypt.hash(password, 10);
    await query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]);
    await query('UPDATE password_reset_codes SET used_at = NOW() WHERE id = $1', [resetRow.id]);
    
    return res.render('pages/reset-password', {
      error: null,
      success: 'Password updated successfully! You can now sign in with your new password.',
      email,
      debugCode: null
    });
  })
);

app.get(
  '/marketplace',
  asyncHandler(async (req, res) => {
    const search = (req.query.search || '').trim();
    const category = req.query.category || '';
    const condition = req.query.condition || '';
    let queryStr = `SELECT listings.*, users.username AS seller_name
                    FROM listings
                    JOIN users ON listings.seller_id = users.id
                    WHERE 1=1`;
    const params = [];
    if (search) {
      params.push(`%${search}%`);
      queryStr += ` AND (listings.title ILIKE $${params.length} OR listings.description ILIKE $${params.length})`;
    }
    if (category && CATEGORIES.includes(category)) {
      params.push(category);
      queryStr += ` AND listings.category = $${params.length}`;
    }
    if (condition && CONDITIONS.includes(condition)) {
      params.push(condition);
      queryStr += ` AND listings.condition = $${params.length}`;
    }
    queryStr += ` ORDER BY listings.created_at DESC`;
    const { rows: listings } = await query(queryStr, params);
    res.render('pages/marketplace', {
      listings,
      formatPrice,
      categories: CATEGORIES,
      conditions: CONDITIONS,
      selectedCategory: category,
      selectedCondition: condition,
      search
    });
  })
);

app.get(
  '/listings/new',
  requireAuth,
  (req, res) => {
    res.render('pages/create-listing', {
      error: null,
      categories: CATEGORIES,
      conditions: CONDITIONS,
      form: {}
    });
  }
);

app.post(
  '/listings/new',
  requireAuth,
  handleUpload(uploadListingImage, (req, res, message, next) => {
    return res.render('pages/create-listing', {
      error: message,
      categories: CATEGORIES,
      conditions: CONDITIONS,
      form: req.body
    });
  }),
  asyncHandler(async (req, res) => {
    const title = normalizeText(req.body.title, MAX_LISTING_TITLE_LENGTH);
    const description = normalizeText(req.body.description, MAX_LISTING_DESCRIPTION_LENGTH);
    const price = (req.body.price || '').trim();
    const category = req.body.category || '';
    const condition = req.body.condition || '';
    const shippingDetails = normalizeText(req.body.shippingDetails, MAX_SHIPPING_DETAILS_LENGTH);
    if (!title || !description || !price || !category || !condition) {
      return res.render('pages/create-listing', {
        error: 'All fields are required.',
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    if (title.length > MAX_LISTING_TITLE_LENGTH || description.length > MAX_LISTING_DESCRIPTION_LENGTH) {
      return res.render('pages/create-listing', {
        error: `Title must be under ${MAX_LISTING_TITLE_LENGTH} characters and description under ${MAX_LISTING_DESCRIPTION_LENGTH} characters.`,
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    if (!CATEGORIES.includes(category)) {
      return res.render('pages/create-listing', {
        error: 'Please select a valid category.',
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    if (!CONDITIONS.includes(condition)) {
      return res.render('pages/create-listing', {
        error: 'Please select a valid condition.',
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    const priceCents = Math.round(Number(price) * 100);
    if (Number.isNaN(priceCents) || priceCents <= 0) {
      return res.render('pages/create-listing', {
        error: 'Price must be a positive number.',
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    if (!req.file) {
      return res.render('pages/create-listing', {
        error: 'Please upload an image for your listing.',
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    let imageUrl;
    try {
      imageUrl = await uploadImage(req.file);
    } catch (error) {
      return res.render('pages/create-listing', {
        error: 'Image upload failed. Please try again.',
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    await query(
      `INSERT INTO listings (seller_id, title, description, price_cents, category, condition, image_url, shipping_details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [res.locals.currentUser.id, title, description, priceCents, category, condition, imageUrl, shippingDetails || null]
    );
    return res.redirect('/marketplace');
  })
);

app.get(
  '/listings/:id/edit',
  requireAuth,
  asyncHandler(async (req, res) => {
    const listingId = req.params.id;
    const userId = res.locals.currentUser.id;
    const { rows } = await query('SELECT * FROM listings WHERE id = $1 AND seller_id = $2', [listingId, userId]);
    const listing = rows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    res.render('pages/edit-listing', {
      error: null,
      listing,
      categories: CATEGORIES,
      conditions: CONDITIONS,
      form: {
        title: listing.title,
        description: listing.description,
        price: (listing.price_cents / 100).toFixed(2),
        category: listing.category,
        condition: listing.condition,
        shippingDetails: listing.shipping_details
      }
    });
  })
);

app.post(
  '/listings/:id/edit',
  requireAuth,
  handleUpload(uploadListingImage, async (req, res, message, next) => {
    try {
      const listingId = req.params.id;
      const userId = res.locals.currentUser.id;
      const { rows } = await query('SELECT * FROM listings WHERE id = $1 AND seller_id = $2', [listingId, userId]);
      const listing = rows[0];
      if (!listing) {
        return res.status(404).render('pages/error', { message: 'Listing not found.' });
      }
      return res.render('pages/edit-listing', {
        error: message,
        listing,
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    } catch (error) {
      return next(error);
    }
  }),
  asyncHandler(async (req, res) => {
    const listingId = req.params.id;
    const userId = res.locals.currentUser.id;
    const { rows } = await query('SELECT * FROM listings WHERE id = $1 AND seller_id = $2', [listingId, userId]);
    const listing = rows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }

    const title = normalizeText(req.body.title, MAX_LISTING_TITLE_LENGTH);
    const description = normalizeText(req.body.description, MAX_LISTING_DESCRIPTION_LENGTH);
    const price = (req.body.price || '').trim();
    const category = req.body.category || '';
    const condition = req.body.condition || '';
    const shippingDetails = normalizeText(req.body.shippingDetails, MAX_SHIPPING_DETAILS_LENGTH);
    if (!title || !description || !price || !category || !condition) {
      return res.render('pages/edit-listing', {
        error: 'All fields are required.',
        listing,
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    if (title.length > MAX_LISTING_TITLE_LENGTH || description.length > MAX_LISTING_DESCRIPTION_LENGTH) {
      return res.render('pages/edit-listing', {
        error: `Title must be under ${MAX_LISTING_TITLE_LENGTH} characters and description under ${MAX_LISTING_DESCRIPTION_LENGTH} characters.`,
        listing,
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    if (!CATEGORIES.includes(category)) {
      return res.render('pages/edit-listing', {
        error: 'Please select a valid category.',
        listing,
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    if (!CONDITIONS.includes(condition)) {
      return res.render('pages/edit-listing', {
        error: 'Please select a valid condition.',
        listing,
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }
    const priceCents = Math.round(Number(price) * 100);
    if (Number.isNaN(priceCents) || priceCents <= 0) {
      return res.render('pages/edit-listing', {
        error: 'Price must be a positive number.',
        listing,
        categories: CATEGORIES,
        conditions: CONDITIONS,
        form: req.body
      });
    }

    let imageUrl = listing.image_url;
    if (req.file) {
      try {
        imageUrl = await uploadImage(req.file);
      } catch (error) {
        return res.render('pages/edit-listing', {
          error: 'Image upload failed. Please try again.',
          listing,
          categories: CATEGORIES,
          conditions: CONDITIONS,
          form: req.body
        });
      }
    }

    await query(
      `UPDATE listings
       SET title = $1,
           description = $2,
           price_cents = $3,
           category = $4,
           condition = $5,
           image_url = $6,
           shipping_details = $7
       WHERE id = $8 AND seller_id = $9`,
      [title, description, priceCents, category, condition, imageUrl, shippingDetails || null, listingId, userId]
    );
    return res.redirect(`/listings/${listingId}`);
  })
);

app.post(
  '/listings/:id/delete',
  requireAuth,
  asyncHandler(async (req, res) => {
    const listingId = req.params.id;
    const userId = res.locals.currentUser.id;
    const { rows } = await query('SELECT id FROM listings WHERE id = $1 AND seller_id = $2', [listingId, userId]);
    const listing = rows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    await query('DELETE FROM listings WHERE id = $1 AND seller_id = $2', [listingId, userId]);
    return res.redirect('/settings');
  })
);

app.get(
  '/listings/:id',
  asyncHandler(async (req, res) => {
    const listingId = req.params.id;
    const { rows } = await query(
      `SELECT listings.*, users.username AS seller_name, users.id AS seller_id, users.avatar_url AS seller_avatar
       FROM listings
       JOIN users ON listings.seller_id = users.id
       WHERE listings.id = $1`,
      [listingId]
    );
    const listing = rows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    if (!res.locals.currentUser || res.locals.currentUser.id !== listing.seller_id) {
      await incrementListingView(listing.id);
    }
    const { rows: favoriteCountRows } = await query(
      'SELECT COUNT(*) AS count FROM listing_favorites WHERE listing_id = $1',
      [listing.id]
    );
    const favoriteCount = Number(favoriteCountRows[0].count || 0);
    let isFavorited = false;
    if (res.locals.currentUser) {
      const { rows: favoriteRows } = await query(
        'SELECT 1 FROM listing_favorites WHERE listing_id = $1 AND user_id = $2 LIMIT 1',
        [listing.id, res.locals.currentUser.id]
      );
      isFavorited = Boolean(favoriteRows[0]);
    }
    res.render('pages/listing-detail', { listing, formatPrice, favoriteCount, isFavorited });
  })
);

app.post(
  '/listings/:id/favorite',
  requireAuth,
  asyncHandler(async (req, res) => {
    const listingId = req.params.id;
    const { rows } = await query('SELECT * FROM listings WHERE id = $1', [listingId]);
    const listing = rows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    if (listing.seller_id === res.locals.currentUser.id) {
      return res.status(400).render('pages/error', { message: 'You cannot favorite your own listing.' });
    }
    const { rows: favoriteRows } = await query(
      'SELECT 1 FROM listing_favorites WHERE user_id = $1 AND listing_id = $2',
      [res.locals.currentUser.id, listing.id]
    );
    if (favoriteRows[0]) {
      await query('DELETE FROM listing_favorites WHERE user_id = $1 AND listing_id = $2', [
        res.locals.currentUser.id,
        listing.id
      ]);
    } else {
      await query('INSERT INTO listing_favorites (user_id, listing_id) VALUES ($1, $2)', [
        res.locals.currentUser.id,
        listing.id
      ]);
    }
    return res.redirect(req.get('referer') || `/listings/${listing.id}`);
  })
);

app.post(
  '/listings/:id/buy',
  requireAuth,
  asyncHandler(async (req, res) => {
    const listingId = req.params.id;
    const buyerId = res.locals.currentUser.id;
    const { rows } = await query('SELECT * FROM listings WHERE id = $1', [listingId]);
    const listing = rows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    if (listing.seller_id === buyerId) {
      return res.status(400).render('pages/error', { message: 'You cannot buy your own listing.' });
    }
    await incrementListingClick(listing.id);
    const { rows: existingOrders } = await query(
      'SELECT id FROM orders WHERE listing_id = $1 AND buyer_id = $2 LIMIT 1',
      [listingId, buyerId]
    );
    if (existingOrders.length) {
      return res.redirect(`/orders`);
    }
    await query('INSERT INTO orders (listing_id, buyer_id, seller_id, status) VALUES ($1, $2, $3, $4)', [
      listingId,
      buyerId,
      listing.seller_id,
      'pending'
    ]);
    return res.redirect('/orders');
  })
);

app.get(
  '/orders',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = res.locals.currentUser.id;
    const { rows: orders } = await query(
      `SELECT orders.*, listings.title, listings.image_url, listings.price_cents,
              buyer.username AS buyer_name, seller.username AS seller_name
       FROM orders
       JOIN listings ON orders.listing_id = listings.id
       JOIN users AS buyer ON orders.buyer_id = buyer.id
       JOIN users AS seller ON orders.seller_id = seller.id
       WHERE orders.buyer_id = $1 OR orders.seller_id = $1
       ORDER BY orders.created_at DESC`,
      [userId]
    );
    const buyerOrders = orders.filter((order) => order.buyer_id === userId);
    const sellerOrders = orders.filter((order) => order.seller_id === userId);
    res.render('pages/orders', { buyerOrders, sellerOrders, formatPrice });
  })
);

app.get(
  '/orders/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const orderId = req.params.id;
    const userId = res.locals.currentUser.id;
    const { rows } = await query(
      `SELECT orders.*, listings.title, listings.description, listings.image_url, listings.price_cents,
              listings.category, listings.condition, listings.shipping_details,
              buyer.username AS buyer_name, buyer.email AS buyer_email,
              seller.username AS seller_name, seller.email AS seller_email
       FROM orders
       JOIN listings ON orders.listing_id = listings.id
       JOIN users AS buyer ON orders.buyer_id = buyer.id
       JOIN users AS seller ON orders.seller_id = seller.id
       WHERE orders.id = $1`,
      [orderId]
    );
    const order = rows[0];
    if (!order) {
      return res.status(404).render('pages/error', { message: 'Order not found.' });
    }
    if (order.buyer_id !== userId && order.seller_id !== userId) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this order.' });
    }
    res.render('pages/order-detail', { order, formatPrice });
  })
);

app.post(
  '/orders/:id/ship',
  requireAuth,
  asyncHandler(async (req, res) => {
    const orderId = req.params.id;
    const userId = res.locals.currentUser.id;
    const { rows } = await query('SELECT * FROM orders WHERE id = $1 AND seller_id = $2', [orderId, userId]);
    const order = rows[0];
    if (!order) {
      return res.status(404).render('pages/error', { message: 'Order not found.' });
    }
    const trackingCode = (req.body.trackingCode || '').trim();
    await query(
      'UPDATE orders SET status = $1, tracking_code = $2, shipped_at = NOW() WHERE id = $3',
      ['shipped', trackingCode || null, orderId]
    );
    return res.redirect(`/orders/${orderId}`);
  })
);

app.post(
  '/orders/:id/complete',
  requireAuth,
  asyncHandler(async (req, res) => {
    const orderId = req.params.id;
    const userId = res.locals.currentUser.id;
    const { rows } = await query('SELECT * FROM orders WHERE id = $1 AND buyer_id = $2', [orderId, userId]);
    const order = rows[0];
    if (!order) {
      return res.status(404).render('pages/error', { message: 'Order not found.' });
    }
    await query(
      'UPDATE orders SET status = $1, delivered_at = NOW(), confirmed_at = NOW() WHERE id = $2',
      ['completed', orderId]
    );
    return res.redirect(`/orders/${orderId}`);
  })
);

app.get(
  '/messages',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = res.locals.currentUser.id;
    const { rows: threads } = await query(
      `SELECT threads.*,
              buyer.username AS buyer_name,
              seller.username AS seller_name,
              listings.title AS listing_title,
              listings.image_url AS listing_image,
              (SELECT COUNT(*) FROM messages WHERE messages.thread_id = threads.id AND messages.is_read = false AND messages.sender_id != $1) AS unread_count,
              (SELECT body FROM messages WHERE messages.thread_id = threads.id ORDER BY messages.created_at DESC LIMIT 1) AS latest_message,
              (SELECT created_at FROM messages WHERE messages.thread_id = threads.id ORDER BY messages.created_at DESC LIMIT 1) AS latest_at
       FROM threads
       JOIN users AS buyer ON threads.buyer_id = buyer.id
       JOIN users AS seller ON threads.seller_id = seller.id
       JOIN listings ON threads.listing_id = listings.id
       WHERE threads.buyer_id = $1 OR threads.seller_id = $1
       ORDER BY COALESCE(
         (SELECT created_at FROM messages WHERE messages.thread_id = threads.id ORDER BY messages.created_at DESC LIMIT 1),
         threads.created_at
       ) DESC`,
      [userId]
    );
    res.render('pages/messages', { threads });
  })
);

app.post(
  '/messages/new',
  requireAuth,
  asyncHandler(async (req, res) => {
    const listingId = req.body.listing_id;
    const rawBody = (req.body.body || '').trim();
    if (!rawBody) {
      return res.redirect(`/listings/${listingId}`);
    }
    if (rawBody.length > MAX_MESSAGE_LENGTH) {
      return res.status(400).render('pages/error', { message: 'Message is too long.' });
    }
    const body = normalizeText(rawBody, MAX_MESSAGE_LENGTH);
    const { rows: listingRows } = await query('SELECT * FROM listings WHERE id = $1', [listingId]);
    const listing = listingRows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    if (listing.seller_id === res.locals.currentUser.id) {
      return res.status(400).render('pages/error', { message: 'You cannot message yourself.' });
    }
    await incrementListingClick(listing.id);
    const { rows: existingThreads } = await query(
      'SELECT id FROM threads WHERE listing_id = $1 AND buyer_id = $2 LIMIT 1',
      [listingId, res.locals.currentUser.id]
    );
    let threadId;
    if (existingThreads.length) {
      threadId = existingThreads[0].id;
    } else {
      const { rows: newThreads } = await query(
        'INSERT INTO threads (listing_id, buyer_id, seller_id) VALUES ($1, $2, $3) RETURNING id',
        [listingId, res.locals.currentUser.id, listing.seller_id]
      );
      threadId = newThreads[0].id;
    }
    await query('INSERT INTO messages (thread_id, sender_id, body) VALUES ($1, $2, $3)', [
      threadId,
      res.locals.currentUser.id,
      body
    ]);
    return res.redirect(`/messages/${threadId}`);
  })
);

app.get(
  '/messages/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const threadId = req.params.id;
    const { rows } = await query(
      `SELECT threads.*,
              buyer.username AS buyer_name,
              seller.username AS seller_name,
              listings.title AS listing_title,
              listings.image_url AS listing_image,
              listings.price_cents AS listing_price
       FROM threads
       JOIN users AS buyer ON threads.buyer_id = buyer.id
       JOIN users AS seller ON threads.seller_id = seller.id
       JOIN listings ON threads.listing_id = listings.id
       WHERE threads.id = $1`,
      [threadId]
    );
    const thread = rows[0];
    if (!thread) {
      return res.status(404).render('pages/error', { message: 'Thread not found.' });
    }
    if (thread.buyer_id !== res.locals.currentUser.id && thread.seller_id !== res.locals.currentUser.id) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this thread.' });
    }
    await query(
      `UPDATE messages SET is_read = true
       WHERE thread_id = $1 AND sender_id != $2`,
      [threadId, res.locals.currentUser.id]
    );
    const { rows: messages } = await query(
      `SELECT messages.*, users.username AS sender_name, users.avatar_url AS sender_avatar
       FROM messages
       JOIN users ON messages.sender_id = users.id
       WHERE thread_id = $1
       ORDER BY created_at ASC`,
      [threadId]
    );
    res.render('pages/thread', { thread, messages, formatPrice });
  })
);

app.post(
  '/messages/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const threadId = req.params.id;
    const rawBody = (req.body.body || '').trim();
    if (!rawBody) {
      return res.redirect(`/messages/${threadId}`);
    }
    if (rawBody.length > MAX_MESSAGE_LENGTH) {
      return res.status(400).render('pages/error', { message: 'Message is too long.' });
    }
    const body = normalizeText(rawBody, MAX_MESSAGE_LENGTH);
    const { rows } = await query('SELECT * FROM threads WHERE id = $1', [threadId]);
    const thread = rows[0];
    if (!thread) {
      return res.status(404).render('pages/error', { message: 'Thread not found.' });
    }
    if (thread.buyer_id !== res.locals.currentUser.id && thread.seller_id !== res.locals.currentUser.id) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this thread.' });
    }
    await query('INSERT INTO messages (thread_id, sender_id, body) VALUES ($1, $2, $3)', [
      threadId,
      res.locals.currentUser.id,
      body
    ]);
    return res.redirect(`/messages/${threadId}`);
  })
);

app.get(
  '/profile',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { user, listingCount, salesCount, listings } = await getProfilePayload(res.locals.currentUser.id);
    res.render('pages/profile', {
      user,
      listingCount,
      salesCount,
      listings,
      formatPrice,
      error: null,
      success: null
    });
  })
);

app.post(
  '/profile/avatar',
  requireAuth,
  (req, res) => res.redirect('/settings')
);

app.get(
  '/settings',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { user, listings } = await getSettingsPayload(res.locals.currentUser.id);
    res.render('pages/settings', { user, listings, formatPrice, error: null, success: null });
  })
);

app.post(
  '/settings/profile',
  requireAuth,
  (req, res, next) => {
    uploadSettingsImages(req, res, async (error) => {
      if (!error) {
        return next();
      }
      const message =
        error.code === 'LIMIT_FILE_SIZE' ? 'Image must be smaller than 5MB.' : error.message || 'Upload failed.';
      const { user, listings } = await getSettingsPayload(res.locals.currentUser.id);
      return res.render('pages/settings', { user, listings, formatPrice, error: message, success: null });
    });
  },
  asyncHandler(async (req, res) => {
    const username = normalizeText(req.body.username, MAX_USERNAME_LENGTH);
    const rawBio = (req.body.bio || '').trim();
    const bio = normalizeText(rawBio, MAX_BIO_LENGTH);
    const profileBackgroundColor = (req.body.profile_background_color || '').trim();
    let error = null;
    let success = null;

    const { rows: currentRows } = await query(
      'SELECT avatar_url, profile_background_url, profile_background_color FROM users WHERE id = $1',
      [res.locals.currentUser.id]
    );
    const currentProfile = currentRows[0] || {};

    if (!username) {
      error = 'Username is required.';
    } else if (username.length > MAX_USERNAME_LENGTH) {
      error = `Username must be under ${MAX_USERNAME_LENGTH} characters.`;
    } else if (rawBio.length > MAX_BIO_LENGTH) {
      error = `Bio must be under ${MAX_BIO_LENGTH} characters.`;
    } else {
      const { rows: existingUsers } = await query(
        'SELECT id FROM users WHERE LOWER(username) = LOWER($1) AND id != $2 LIMIT 1',
        [username, res.locals.currentUser.id]
      );
      if (existingUsers.length) {
        error = 'That username is already in use.';
      }
    }

    if (!error && profileBackgroundColor && !isValidHexColor(profileBackgroundColor)) {
      error = 'Background color must be a valid hex value.';
    }

    const clearAvatar = req.body.clear_avatar === 'true';
    const clearBackground = req.body.clear_background === 'true';

    let avatarUrl = clearAvatar ? null : currentProfile.avatar_url || null;
    const avatarFile = req.files?.avatar?.[0];
    if (!error && avatarFile && !clearAvatar) {
      try {
        avatarUrl = await uploadImage(avatarFile);
      } catch (uploadError) {
        error = uploadError.message || 'Avatar upload failed. Please try again.';
      }
    }

    let backgroundUrl = clearBackground ? null : currentProfile.profile_background_url || null;
    const backgroundFile = req.files?.background?.[0];
    if (!error && backgroundFile && !clearBackground) {
      try {
        backgroundUrl = await uploadImage(backgroundFile);
      } catch (uploadError) {
        error = uploadError.message || 'Background upload failed. Please try again.';
      }
    }

    const backgroundColorValue = clearBackground ? null : profileBackgroundColor || null;

    if (!error) {
      await query(
        `UPDATE users
         SET username = $1,
             bio = $2,
             avatar_url = $3,
             profile_background_url = $4,
             profile_background_color = $5
         WHERE id = $6`,
        [username, bio, avatarUrl, backgroundUrl, backgroundColorValue, res.locals.currentUser.id]
      );
      if (res.locals.currentUser) {
        res.locals.currentUser.username = username;
        res.locals.currentUser.bio = bio;
        res.locals.currentUser.avatar_url = avatarUrl;
        res.locals.currentUser.profile_background_url = backgroundUrl;
        res.locals.currentUser.profile_background_color = backgroundColorValue;
      }
      success = 'Profile updated successfully.';
    }

    const { user, listings } = await getSettingsPayload(res.locals.currentUser.id);
    res.render('pages/settings', { user, listings, formatPrice, error, success });
  })
);

app.post(
  '/settings',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { action } = req.body;
    let error = null;
    let success = null;

    if (action === 'password') {
      const { currentPassword, newPassword, confirmPassword } = req.body;
      if (!currentPassword || !newPassword || !confirmPassword) {
        error = 'All password fields are required.';
      } else if (newPassword.length < 8) {
        error = 'New password must be at least 8 characters.';
      } else if (newPassword !== confirmPassword) {
        error = 'New password confirmation does not match.';
      } else {
        const { rows } = await query('SELECT password_hash FROM users WHERE id = $1', [
          res.locals.currentUser.id
        ]);
        const isValid = await bcrypt.compare(currentPassword, rows[0].password_hash);
        if (!isValid) {
          error = 'Current password is incorrect.';
        } else {
          const newHash = await bcrypt.hash(newPassword, 10);
          await query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, res.locals.currentUser.id]);
          success = 'Password updated successfully.';
        }
      }
    }

    if (action === 'email') {
      error = 'Email updates are currently disabled. Contact support if you need help.';
    }

    if (action === 'notifications') {
      const notificationEnabled = req.body.notification_enabled === 'on';
      const marketingEnabled = req.body.marketing_enabled === 'on';
      await query('UPDATE users SET notification_enabled = $1, marketing_enabled = $2 WHERE id = $3', [
        notificationEnabled,
        marketingEnabled,
        res.locals.currentUser.id
      ]);
      success = 'Notification preferences saved.';
    }

    if (action === 'unlink_google') {
      await query('UPDATE users SET google_id = NULL, google_email = NULL WHERE id = $1', [
        res.locals.currentUser.id
      ]);
      if (res.locals.currentUser) {
        res.locals.currentUser.google_id = null;
        res.locals.currentUser.google_email = null;
      }
      success = 'Google account unlinked.';
    }

    if (action === 'steam') {
      const steamProfileUrl = (req.body.steam_profile_url || '').trim();
      const steamId = (req.body.steam_id || '').trim();
      if (!steamProfileUrl && !steamId) {
        await query('UPDATE users SET steam_id = NULL, steam_profile_url = NULL WHERE id = $1', [
          res.locals.currentUser.id
        ]);
        if (res.locals.currentUser) {
          res.locals.currentUser.steam_id = null;
          res.locals.currentUser.steam_profile_url = null;
        }
        success = 'Steam account cleared.';
      } else {
        await query('UPDATE users SET steam_id = $1, steam_profile_url = $2 WHERE id = $3', [
          steamId || null,
          steamProfileUrl || null,
          res.locals.currentUser.id
        ]);
        if (res.locals.currentUser) {
          res.locals.currentUser.steam_id = steamId || null;
          res.locals.currentUser.steam_profile_url = steamProfileUrl || null;
        }
        success = 'Steam account linked.';
      }
    }

    const { user, listings } = await getSettingsPayload(res.locals.currentUser.id);
    res.render('pages/settings', { user, listings, formatPrice, error, success });
  })
);

app.get(
  '/dashboard/insights',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { listings, stats } = await getUserDashboardPayload(res.locals.currentUser.id);
    res.render('pages/user-dashboard', { listings, stats, formatPrice });
  })
);

app.get(
  '/favorites',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = res.locals.currentUser.id;
    const { rows: listings } = await query(
      `SELECT listings.*, users.username AS seller_name
       FROM listing_favorites
       JOIN listings ON listing_favorites.listing_id = listings.id
       JOIN users ON listings.seller_id = users.id
       WHERE listing_favorites.user_id = $1
       ORDER BY listing_favorites.created_at DESC`,
      [userId]
    );
    res.render('pages/favorites', { listings, formatPrice });
  })
);

app.get(
  '/dashboard',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const { users, listings } = await getAdminDashboardPayload();
    res.render('pages/admin-dashboard', { users, listings, formatPrice, error: null, success: null });
  })
);

app.post(
  '/dashboard/users/:id/update',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const userId = Number(req.params.id);
    if (!Number.isInteger(userId)) {
      return res.status(400).render('pages/error', { message: 'Invalid user id.' });
    }

    const username = (req.body.username || '').trim();
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';

    let error = null;
    const updates = [];
    const values = [];

    if (username) {
      const { rows: existingUsers } = await query(
        'SELECT id FROM users WHERE LOWER(username) = LOWER($1) AND id != $2 LIMIT 1',
        [username, userId]
      );
      if (existingUsers.length) {
        error = 'That username is already in use.';
      } else {
        values.push(username);
        updates.push(`username = $${values.length}`);
      }
    }

    if (!error && email) {
      if (!isValidEmail(email)) {
        error = 'Please enter a valid email.';
      } else {
        const { rows: existingEmails } = await query(
          'SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id != $2 LIMIT 1',
          [email, userId]
        );
        if (existingEmails.length) {
          error = 'That email is already in use.';
        } else {
          values.push(email);
          updates.push(`email = $${values.length}`);
        }
      }
    }

    if (!error && password) {
      if (password.length < 8) {
        error = 'Password must be at least 8 characters.';
      } else {
        const passwordHash = await bcrypt.hash(password, 10);
        values.push(passwordHash);
        updates.push(`password_hash = $${values.length}`);
      }
    }

    if (!error && updates.length === 0) {
      error = 'Provide at least one field to update.';
    }

    if (error) {
      const { users, listings } = await getAdminDashboardPayload();
      return res.render('pages/admin-dashboard', { users, listings, formatPrice, error, success: null });
    }

    values.push(userId);
    await query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length}`, values);
    return res.redirect('/dashboard');
  })
);

app.post(
  '/dashboard/users/:id/delete',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const userId = Number(req.params.id);
    if (!Number.isInteger(userId)) {
      return res.status(400).render('pages/error', { message: 'Invalid user id.' });
    }
    const { rows } = await query('SELECT username, email FROM users WHERE id = $1', [userId]);
    const targetUser = rows[0];
    if (!targetUser) {
      return res.status(404).render('pages/error', { message: 'User not found.' });
    }
    if (isAdminUser(targetUser)) {
      const { users, listings } = await getAdminDashboardPayload();
      return res.render('pages/admin-dashboard', {
        users,
        listings,
        formatPrice,
        error: 'The primary admin account cannot be deleted.',
        success: null
      });
    }
    await query('DELETE FROM users WHERE id = $1', [userId]);
    return res.redirect('/dashboard');
  })
);

app.post(
  '/dashboard/listings/:id/delete',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const listingId = Number(req.params.id);
    if (!Number.isInteger(listingId)) {
      return res.status(400).render('pages/error', { message: 'Invalid listing id.' });
    }
    const { rows } = await query('SELECT id FROM listings WHERE id = $1', [listingId]);
    if (!rows[0]) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    await query('DELETE FROM listings WHERE id = $1', [listingId]);
    return res.redirect('/dashboard');
  })
);

app.get(
  '/chess',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = res.locals.currentUser.id;
    const { rows: incomingInvites } = await query(
      `SELECT chess_invites.*, users.username AS inviter_name
       FROM chess_invites
       JOIN users ON chess_invites.inviter_id = users.id
       WHERE chess_invites.invitee_id = $1 AND chess_invites.status = 'pending'
       ORDER BY chess_invites.created_at DESC`,
      [userId]
    );
    const { rows: outgoingInvites } = await query(
      `SELECT chess_invites.*, users.username AS invitee_name
       FROM chess_invites
       JOIN users ON chess_invites.invitee_id = users.id
       WHERE chess_invites.inviter_id = $1 AND chess_invites.status = 'pending'
       ORDER BY chess_invites.created_at DESC`,
      [userId]
    );
    const { rows: matches } = await query(
      `SELECT chess_matches.*,
              white.username AS white_name,
              black.username AS black_name
       FROM chess_matches
       JOIN users AS white ON chess_matches.white_player_id = white.id
       JOIN users AS black ON chess_matches.black_player_id = black.id
       WHERE chess_matches.white_player_id = $1 OR chess_matches.black_player_id = $1
       ORDER BY chess_matches.created_at DESC`,
      [userId]
    );
    res.render('pages/chess', { incomingInvites, outgoingInvites, matches });
  })
);

app.post(
  '/chess/invite',
  requireAuth,
  asyncHandler(async (req, res) => {
    const username = (req.body.username || '').trim();
    if (!username) {
      return res.redirect('/chess');
    }
    const { rows: users } = await query('SELECT id FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1', [username]);
    const invitee = users[0];
    if (!invitee) {
      return res.redirect('/chess');
    }
    if (invitee.id === res.locals.currentUser.id) {
      return res.redirect('/chess');
    }
    const { rows: existing } = await query(
      `SELECT id FROM chess_invites
       WHERE inviter_id = $1 AND invitee_id = $2 AND status = 'pending'
       LIMIT 1`,
      [res.locals.currentUser.id, invitee.id]
    );
    if (!existing.length) {
      await query('INSERT INTO chess_invites (inviter_id, invitee_id) VALUES ($1, $2)', [
        res.locals.currentUser.id,
        invitee.id
      ]);
    }
    return res.redirect('/chess');
  })
);

app.post(
  '/chess/invite/:id/accept',
  requireAuth,
  asyncHandler(async (req, res) => {
    const inviteId = req.params.id;
    const { rows } = await query(
      'SELECT * FROM chess_invites WHERE id = $1 AND invitee_id = $2 AND status = $3',
      [inviteId, res.locals.currentUser.id, 'pending']
    );
    const invite = rows[0];
    if (!invite) {
      return res.redirect('/chess');
    }
    const assignWhiteToInvitee = Math.random() >= 0.5;
    const whitePlayerId = assignWhiteToInvitee ? invite.invitee_id : invite.inviter_id;
    const blackPlayerId = assignWhiteToInvitee ? invite.inviter_id : invite.invitee_id;
    await query('UPDATE chess_invites SET status = $1 WHERE id = $2', ['accepted', inviteId]);
    await query('INSERT INTO chess_matches (white_player_id, black_player_id) VALUES ($1, $2)', [
      whitePlayerId,
      blackPlayerId
    ]);
    return res.redirect('/chess');
  })
);

app.post(
  '/chess/invite/:id/decline',
  requireAuth,
  asyncHandler(async (req, res) => {
    const inviteId = req.params.id;
    await query('UPDATE chess_invites SET status = $1 WHERE id = $2 AND invitee_id = $3', [
      'declined',
      inviteId,
      res.locals.currentUser.id
    ]);
    return res.redirect('/chess');
  })
);

app.get(
  '/chess/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const matchId = req.params.id;
    const userId = res.locals.currentUser.id;
    const { rows } = await query(
      `SELECT chess_matches.*,
              white.username AS white_name,
              black.username AS black_name
       FROM chess_matches
       JOIN users AS white ON chess_matches.white_player_id = white.id
       JOIN users AS black ON chess_matches.black_player_id = black.id
       WHERE chess_matches.id = $1`,
      [matchId]
    );
    const match = rows[0];
    if (!match) {
      return res.status(404).render('pages/error', { message: 'Match not found.' });
    }
    if (match.white_player_id !== userId && match.black_player_id !== userId) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this match.' });
    }
    const opponentName = match.white_player_id === userId ? match.black_name : match.white_name;
    res.render('pages/chess-match', { match, opponentName });
  })
);

app.get(
  '/:username',
  asyncHandler(async (req, res) => {
    const username = (req.params.username || '').trim();
    if (!username || username.includes('.') || isReservedProfilePath(username)) {
      return res.status(404).render('pages/error', { message: 'User not found.' });
    }
    const profilePayload = await getPublicProfilePayload(username);
    if (!profilePayload) {
      return res.status(404).render('pages/error', { message: 'User not found.' });
    }
    const isSelf = res.locals.currentUser && res.locals.currentUser.id === profilePayload.user.id;
    return res.render('pages/public-profile', {
      ...profilePayload,
      formatPrice,
      isSelf
    });
  })
);

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }
  
  if (process.env.NODE_ENV === 'production') {
    console.error({
      timestamp: new Date().toISOString(),
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method,
      userId: res.locals.currentUser?.id,
      ip: req.ip
    });
  } else {
    console.error('Server error:', error);
  }
  
  const message =
    error.code === '42P01'
      ? 'The database is still warming up. Please retry in a moment.'
      : error.message || 'Something went wrong. Please try again.';
  return res.status(error.status || 500).render('pages/error', { message });
});

app.listen(PORT, () => {
  console.log(`Marketplace app running on http://localhost:${PORT}`);
});
