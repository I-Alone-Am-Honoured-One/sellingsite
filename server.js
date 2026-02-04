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

const isCloudinaryConfigured = Boolean(
  process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET
);

if (isCloudinaryConfigured) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
}

const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!isCloudinaryConfigured && !fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = isCloudinaryConfigured
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

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

ensureSessionsTable().catch((error) => {
  console.error('Failed to ensure sessions table exists:', error);
});

function formatPrice(cents) {
  return `$${(cents / 100).toFixed(2)}`;
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
    return `/uploads/${file.filename}`;
  }
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'safeswap', resource_type: 'image' },
      (error, result) => {
        if (error) {
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

async function getProfilePayload(userId) {
  const { rows: userRows } = await query('SELECT * FROM users WHERE id = $1', [userId]);
  const user = userRows[0];
  const { rows: listingRows } = await query(
    'SELECT COUNT(*) as count FROM listings WHERE seller_id = $1',
    [userId]
  );
  const listingCount = Number(listingRows[0].count);
  const { rows: orderRows } = await query('SELECT COUNT(*) as count FROM orders WHERE buyer_id = $1', [userId]);
  const orderCount = Number(orderRows[0].count);
  const { rows: listings } = await query(
    'SELECT * FROM listings WHERE seller_id = $1 ORDER BY created_at DESC LIMIT 6',
    [userId]
  );
  return { user, listingCount, orderCount, listings };
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

app.use(asyncHandler(async (req, res, next) => {
  await refreshUserSession(req, res);
  res.locals.currentPath = req.path;
  res.locals.isActivePath = (pathPrefix) => req.path === pathPrefix || req.path.startsWith(`${pathPrefix}/`);
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
    const { title, description, price, category, condition, shippingDetails } = req.body;
    if (!title || !description || !price || !category || !condition || !shippingDetails) {
      return res.render('pages/create-listing', {
        error: 'All fields are required.',
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
      [res.locals.currentUser.id, title, description, priceCents, category, condition, imageUrl, shippingDetails]
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

    const { title, description, price, category, condition, shippingDetails } = req.body;
    if (!title || !description || !price || !category || !condition || !shippingDetails) {
      return res.render('pages/edit-listing', {
        error: 'All fields are required.',
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
      [title, description, priceCents, category, condition, imageUrl, shippingDetails, listingId, userId]
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
    res.render('pages/listing-detail', { listing, formatPrice });
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
    const body = (req.body.body || '').trim();
    if (!body) {
      return res.redirect(`/listings/${listingId}`);
    }
    const { rows: listingRows } = await query('SELECT * FROM listings WHERE id = $1', [listingId]);
    const listing = listingRows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    if (listing.seller_id === res.locals.currentUser.id) {
      return res.status(400).render('pages/error', { message: 'You cannot message yourself.' });
    }
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
    const body = (req.body.body || '').trim();
    if (!body) {
      return res.redirect(`/messages/${threadId}`);
    }
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
    const { user, listingCount, orderCount, listings } = await getProfilePayload(res.locals.currentUser.id);
    res.render('pages/profile', {
      user,
      listingCount,
      orderCount,
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
    uploadAvatarImage(req, res, async (error) => {
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
    const username = (req.body.username || '').trim();
    const bio = (req.body.bio || '').trim();
    let error = null;
    let success = null;

    if (!username) {
      error = 'Username is required.';
    } else {
      const { rows: existingUsers } = await query(
        'SELECT id FROM users WHERE LOWER(username) = LOWER($1) AND id != $2 LIMIT 1',
        [username, res.locals.currentUser.id]
      );
      if (existingUsers.length) {
        error = 'That username is already in use.';
      }
    }

    let avatarUrl = null;
    if (!error && req.file) {
      try {
        avatarUrl = await uploadImage(req.file);
      } catch (uploadError) {
        error = 'Avatar upload failed. Please try again.';
      }
    }

    if (!error) {
      if (avatarUrl) {
        await query('UPDATE users SET username = $1, bio = $2, avatar_url = $3 WHERE id = $4', [
          username,
          bio,
          avatarUrl,
          res.locals.currentUser.id
        ]);
      } else {
        await query('UPDATE users SET username = $1, bio = $2 WHERE id = $3', [
          username,
          bio,
          res.locals.currentUser.id
        ]);
      }
      if (res.locals.currentUser) {
        res.locals.currentUser.username = username;
        res.locals.currentUser.bio = bio;
        if (avatarUrl) {
          res.locals.currentUser.avatar_url = avatarUrl;
        }
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
      const email = (req.body.email || '').trim().toLowerCase();
      if (!email || !isValidEmail(email)) {
        error = 'Please enter a valid email.';
      } else {
        try {
          await query('UPDATE users SET email = $1 WHERE id = $2', [email, res.locals.currentUser.id]);
          success = 'Email updated successfully.';
        } catch (updateError) {
          error = 'That email is already in use.';
        }
      }
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

    const { user, listings } = await getSettingsPayload(res.locals.currentUser.id);
    res.render('pages/settings', { user, listings, formatPrice, error, success });
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
