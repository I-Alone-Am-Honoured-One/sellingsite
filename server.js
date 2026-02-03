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
const { query } = require('./db');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const EMAIL_FROM = process.env.EMAIL_FROM || 'mariusjon000@gmail.com';
const RESET_CODE_TTL_MINUTES = 15;
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_COOKIE = 'session';
const SECURE_SESSION_COOKIE = 'session_secure';
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

function isSecureRequest(req) {
  return req.secure || req.headers['x-forwarded-proto'] === 'https';
}

function buildSessionCookieOptions({ sameSite, secure }) {
  return {
    httpOnly: true,
    sameSite,
    secure,
    maxAge: SESSION_MAX_AGE_MS,
    path: '/'
  };
}

function setSessionCookie(res, req, token) {
  res.cookie(SESSION_COOKIE, token, buildSessionCookieOptions({ sameSite: 'lax', secure: false }));
  if (isSecureRequest(req)) {
    res.cookie(SECURE_SESSION_COOKIE, token, buildSessionCookieOptions({ sameSite: 'none', secure: true }));
  } else {
    res.clearCookie(SECURE_SESSION_COOKIE, buildSessionCookieOptions({ sameSite: 'none', secure: true }));
  }
}

function clearSessionCookie(res, req) {
  res.clearCookie(SESSION_COOKIE, buildSessionCookieOptions({ sameSite: 'lax', secure: false }));
  res.clearCookie(SECURE_SESSION_COOKIE, buildSessionCookieOptions({ sameSite: 'none', secure: true }));
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
    subject: 'NeonSwap password reset code',
    text: `Your NeonSwap reset code is ${code}. It expires in ${RESET_CODE_TTL_MINUTES} minutes.`,
    html: `<p>Your NeonSwap reset code is <strong>${code}</strong>. It expires in ${RESET_CODE_TTL_MINUTES} minutes.</p>`
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
      return onError(req, res, message);
    });
  };
}

async function hydrateUser(req, res, next) {
  const token = req.cookies[SECURE_SESSION_COOKIE] || req.cookies[SESSION_COOKIE];
  if (!token) {
    res.locals.currentUser = null;
    return next();
  }
  try {
    const tokenHash = hashSessionToken(token);
    const { rows } = await query(
      `SELECT users.id, users.username, users.email, users.avatar_url, sessions.expires_at
       FROM sessions
       JOIN users ON sessions.user_id = users.id
       WHERE sessions.token_hash = $1
       LIMIT 1`,
      [tokenHash]
    );
    const session = rows[0];
    if (!session) {
      clearSessionCookie(res, req);
      res.locals.currentUser = null;
      return next();
    }
    if (session.expires_at && new Date(session.expires_at).getTime() < Date.now()) {
      await query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
      clearSessionCookie(res, req);
      res.locals.currentUser = null;
      return next();
    }
    res.locals.currentUser = {
      id: session.id,
      username: session.username,
      email: session.email,
      avatar_url: session.avatar_url
    };
  } catch (error) {
    res.locals.currentUser = null;
    clearSessionCookie(res, req);
  }
  return next();
}

function requireAuth(req, res, next) {
  if (!res.locals.currentUser) {
    return res.redirect('/auth/sign-in');
  }
  return next();
}

app.use(hydrateUser);

app.get('/healthz', (req, res) => {
  res.json({ status: 'ok' });
});

app.get(
  '/',
  asyncHandler(async (req, res) => {
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
    const { rows: statsRows } = await query(
      `SELECT
        (SELECT COUNT(*) FROM listings) AS listings_count,
        (SELECT COUNT(*) FROM users) AS users_count,
        (SELECT COUNT(*) FROM orders) AS orders_count`
    );
    res.render('pages/landing', {
      latestListings,
      trendingListings,
      stats: statsRows[0],
      formatPrice,
      categories: CATEGORIES
    });
  })
);

app.get(
  '/marketplace',
  asyncHandler(async (req, res) => {
    const search = req.query.search ? `%${req.query.search}%` : null;
    const category = CATEGORIES.includes(req.query.category) ? req.query.category : null;
    const condition = CONDITIONS.includes(req.query.condition) ? req.query.condition : null;
    const { rows: listings } = await query(
      `SELECT listings.*, users.username AS seller_name
       FROM listings
       JOIN users ON listings.seller_id = users.id
       WHERE ($1::text IS NULL OR listings.title ILIKE $1 OR listings.description ILIKE $1)
         AND ($2::text IS NULL OR listings.category = $2)
         AND ($3::text IS NULL OR listings.condition = $3)
       ORDER BY listings.created_at DESC`,
      [search, category, condition]
    );
    res.render('pages/marketplace', {
      listings,
      formatPrice,
      search: req.query.search || '',
      categories: CATEGORIES,
      conditions: CONDITIONS,
      selectedCategory: category,
      selectedCondition: condition
    });
  })
);

app.get('/listings/new', requireAuth, (req, res) => {
  res.render('pages/create-listing', { error: null, categories: CATEGORIES, conditions: CONDITIONS, form: {} });
});

app.post(
  '/listings',
  requireAuth,
  handleUpload(uploadListingImage, (req, res, message) =>
    res.render('pages/create-listing', {
      error: message,
      categories: CATEGORIES,
      conditions: CONDITIONS,
      form: req.body
    })
  ),
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
  '/listings/:id',
  asyncHandler(async (req, res) => {
    const listingId = req.params.id;
    const { rows } = await query(
      `SELECT listings.*, users.username AS seller_name, users.id AS seller_id
       FROM listings
       JOIN users ON listings.seller_id = users.id
       WHERE listings.id = $1`,
      [listingId]
    );
    const listing = rows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    res.render('pages/listing-detail', { listing, formatPrice, currentUser: res.locals.currentUser });
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
      return res.redirect(`/listings/${listingId}`);
    }
    const orderResult = await query(
      `INSERT INTO orders (listing_id, buyer_id, seller_id, status)
       VALUES ($1, $2, $3, 'PAID')
       RETURNING id`,
      [listingId, buyerId, listing.seller_id]
    );
    const orderId = orderResult.rows[0].id;
    await query(
      `INSERT INTO threads (listing_id, order_id, buyer_id, seller_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (listing_id, buyer_id, seller_id) DO UPDATE SET order_id = EXCLUDED.order_id
       RETURNING id`,
      [listingId, orderId, buyerId, listing.seller_id]
    );
    return res.redirect(`/orders/${orderId}`);
  })
);

app.post(
  '/listings/:id/message',
  requireAuth,
  asyncHandler(async (req, res) => {
    const listingId = req.params.id;
    const { rows } = await query('SELECT * FROM listings WHERE id = $1', [listingId]);
    const listing = rows[0];
    if (!listing) {
      return res.status(404).render('pages/error', { message: 'Listing not found.' });
    }
    if (listing.seller_id === res.locals.currentUser.id) {
      return res.redirect(`/listings/${listingId}`);
    }
    const threadResult = await query(
      `INSERT INTO threads (listing_id, buyer_id, seller_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (listing_id, buyer_id, seller_id) DO UPDATE SET listing_id = EXCLUDED.listing_id
       RETURNING id`,
      [listingId, res.locals.currentUser.id, listing.seller_id]
    );
    return res.redirect(`/messages/${threadResult.rows[0].id}`);
  })
);

app.get('/auth/register', (req, res) => {
  res.render('pages/register', { error: null });
});

app.post(
  '/auth/register',
  asyncHandler(async (req, res) => {
    const username = (req.body.username || '').trim();
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password;
    if (!username || !email || !password) {
      return res.render('pages/register', { error: 'All fields are required.' });
    }
    if (!isValidEmail(email)) {
      return res.render('pages/register', { error: 'Please enter a valid email.' });
    }
    if (password.length < 8) {
      return res.render('pages/register', { error: 'Password must be at least 8 characters.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    try {
      const { rows } = await query(
        'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
        [username, email, passwordHash]
      );
      const token = await createSession(rows[0].id);
      setSessionCookie(res, req, token);
      return res.redirect('/');
    } catch (error) {
      return res.render('pages/register', { error: 'Username or email already in use.' });
    }
  })
);

app.get('/auth/sign-in', (req, res) => {
  res.render('pages/sign-in', { error: null });
});

app.post(
  '/auth/sign-in',
  asyncHandler(async (req, res) => {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password;
    if (!email || !password) {
      return res.render('pages/sign-in', { error: 'Email and password required.' });
    }
    const { rows } = await query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) {
      return res.render('pages/sign-in', { error: 'Invalid credentials.' });
    }
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.render('pages/sign-in', { error: 'Invalid credentials.' });
    }
    const token = await createSession(user.id);
    setSessionCookie(res, req, token);
    return res.redirect('/');
  })
);

app.post('/auth/logout', (req, res) => {
  const token = req.cookies[SECURE_SESSION_COOKIE] || req.cookies[SESSION_COOKIE];
  if (token) {
    const tokenHash = hashSessionToken(token);
    query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]).catch(() => {});
  }
  clearSessionCookie(res, req);
  res.redirect('/');
});

app.get('/auth/forgot-password', (req, res) => {
  res.render('pages/forgot-password', { error: null, success: null });
});

app.post(
  '/auth/forgot-password',
  asyncHandler(async (req, res) => {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email || !isValidEmail(email)) {
      return res.render('pages/forgot-password', { error: 'Please enter a valid email.', success: null });
    }
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
      await sendResetEmail({ email: user.email, code });
    }
    return res.render('pages/forgot-password', {
      error: null,
      success: 'If that email exists, we sent a 6-digit reset code.'
    });
  })
);

app.get('/auth/reset-password', (req, res) => {
  res.render('pages/reset-password', { error: null, success: null, email: req.query.email || '' });
});

app.post(
  '/auth/reset-password',
  asyncHandler(async (req, res) => {
    const email = (req.body.email || '').trim().toLowerCase();
    const code = (req.body.code || '').trim();
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;
    if (!email || !isValidEmail(email)) {
      return res.render('pages/reset-password', { error: 'Please enter a valid email.', success: null, email });
    }
    if (!code || !/^\d{6}$/.test(code)) {
      return res.render('pages/reset-password', { error: 'Enter the 6-digit code from your email.', success: null, email });
    }
    if (!password || password.length < 8) {
      return res.render('pages/reset-password', {
        error: 'Password must be at least 8 characters.',
        success: null,
        email
      });
    }
    if (password !== confirmPassword) {
      return res.render('pages/reset-password', { error: 'Passwords do not match.', success: null, email });
    }
    const { rows } = await query('SELECT id FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) {
      return res.render('pages/reset-password', { error: 'Invalid reset details.', success: null, email });
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
      return res.render('pages/reset-password', { error: 'Reset code is invalid or expired.', success: null, email });
    }
    if (resetRow.expires_at && new Date(resetRow.expires_at).getTime() < Date.now()) {
      return res.render('pages/reset-password', { error: 'Reset code is expired.', success: null, email });
    }
    const codeValid = await bcrypt.compare(code, resetRow.code_hash);
    if (!codeValid) {
      return res.render('pages/reset-password', { error: 'Reset code is invalid.', success: null, email });
    }
    const newHash = await bcrypt.hash(password, 10);
    await query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]);
    await query('UPDATE password_reset_codes SET used_at = NOW() WHERE id = $1', [resetRow.id]);
    return res.render('pages/reset-password', {
      error: null,
      success: 'Password updated. You can now sign in.',
      email
    });
  })
);

async function autoConfirmExpiredOrders(userId) {
  await query(
    `UPDATE orders
     SET status = 'CONFIRMED', confirmed_at = NOW()
     WHERE status = 'DELIVERED'
       AND delivered_at IS NOT NULL
       AND delivered_at < NOW() - INTERVAL '24 hours'
       AND (buyer_id = $1 OR seller_id = $1)`,
    [userId]
  );
}

app.get(
  '/orders',
  requireAuth,
  asyncHandler(async (req, res) => {
    await autoConfirmExpiredOrders(res.locals.currentUser.id);
    const { rows: buyerOrders } = await query(
      `SELECT orders.*, listings.title, listings.image_url, listings.price_cents, users.username AS seller_name
       FROM orders
       JOIN listings ON orders.listing_id = listings.id
       JOIN users ON orders.seller_id = users.id
       WHERE orders.buyer_id = $1
       ORDER BY orders.created_at DESC`,
      [res.locals.currentUser.id]
    );
    const { rows: sellerOrders } = await query(
      `SELECT orders.*, listings.title, listings.image_url, listings.price_cents, users.username AS buyer_name
       FROM orders
       JOIN listings ON orders.listing_id = listings.id
       JOIN users ON orders.buyer_id = users.id
       WHERE orders.seller_id = $1
       ORDER BY orders.created_at DESC`,
      [res.locals.currentUser.id]
    );
    res.render('pages/orders', { buyerOrders, sellerOrders, formatPrice });
  })
);

app.get(
  '/orders/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    await autoConfirmExpiredOrders(res.locals.currentUser.id);
    const orderId = req.params.id;
    const { rows } = await query(
      `SELECT orders.*, listings.title, listings.image_url, listings.price_cents, listings.shipping_details,
              buyer.username AS buyer_name, seller.username AS seller_name
       FROM orders
       JOIN listings ON orders.listing_id = listings.id
       JOIN users buyer ON orders.buyer_id = buyer.id
       JOIN users seller ON orders.seller_id = seller.id
       WHERE orders.id = $1`,
      [orderId]
    );
    const order = rows[0];
    if (!order) {
      return res.status(404).render('pages/error', { message: 'Order not found.' });
    }
    if (order.buyer_id !== res.locals.currentUser.id && order.seller_id !== res.locals.currentUser.id) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this order.' });
    }
    const now = Date.now();
    const deliveredAt = order.delivered_at ? new Date(order.delivered_at).getTime() : null;
    const remainingMs = deliveredAt ? Math.max(0, deliveredAt + 24 * 60 * 60 * 1000 - now) : null;
    res.render('pages/order-detail', { order, formatPrice, currentUser: res.locals.currentUser, remainingMs });
  })
);

app.post(
  '/orders/:id/ship',
  requireAuth,
  asyncHandler(async (req, res) => {
    const orderId = req.params.id;
    const trackingCode = req.body.trackingCode || 'No tracking provided';
    const { rows } = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
    const order = rows[0];
    if (!order) {
      return res.status(404).render('pages/error', { message: 'Order not found.' });
    }
    if (order.seller_id !== res.locals.currentUser.id) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this order.' });
    }
    await query(
      `UPDATE orders
       SET status = 'SHIPPED', tracking_code = $1, shipped_at = NOW()
       WHERE id = $2`,
      [trackingCode, orderId]
    );
    return res.redirect(`/orders/${orderId}`);
  })
);

app.post(
  '/orders/:id/deliver',
  requireAuth,
  asyncHandler(async (req, res) => {
    const orderId = req.params.id;
    const { rows } = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
    const order = rows[0];
    if (!order) {
      return res.status(404).render('pages/error', { message: 'Order not found.' });
    }
    if (order.seller_id !== res.locals.currentUser.id) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this order.' });
    }
    await query(
      `UPDATE orders
       SET status = 'DELIVERED', delivered_at = NOW()
       WHERE id = $1`,
      [orderId]
    );
    return res.redirect(`/orders/${orderId}`);
  })
);

app.post(
  '/orders/:id/confirm',
  requireAuth,
  asyncHandler(async (req, res) => {
    const orderId = req.params.id;
    const { rows } = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
    const order = rows[0];
    if (!order) {
      return res.status(404).render('pages/error', { message: 'Order not found.' });
    }
    if (order.buyer_id !== res.locals.currentUser.id) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this order.' });
    }
    await query(
      `UPDATE orders
       SET status = 'CONFIRMED', confirmed_at = NOW()
       WHERE id = $1`,
      [orderId]
    );
    return res.redirect(`/orders/${orderId}`);
  })
);

app.post(
  '/orders/:id/dispute',
  requireAuth,
  asyncHandler(async (req, res) => {
    const orderId = req.params.id;
    const { rows } = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
    const order = rows[0];
    if (!order) {
      return res.status(404).render('pages/error', { message: 'Order not found.' });
    }
    if (order.buyer_id !== res.locals.currentUser.id) {
      return res.status(403).render('pages/error', { message: 'You do not have access to this order.' });
    }
    await query(
      `UPDATE orders
       SET status = 'DISPUTED', disputed_at = NOW()
       WHERE id = $1`,
      [orderId]
    );
    return res.redirect(`/orders/${orderId}`);
  })
);

app.get(
  '/messages',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { rows: threads } = await query(
      `SELECT threads.*, listings.title AS listing_title,
              latest.body AS latest_message,
              latest.created_at AS latest_at,
              SUM(CASE WHEN messages.is_read = false AND messages.sender_id != $1 THEN 1 ELSE 0 END) AS unread_count
       FROM threads
       LEFT JOIN listings ON threads.listing_id = listings.id
       LEFT JOIN LATERAL (
         SELECT body, created_at
         FROM messages
         WHERE messages.thread_id = threads.id
         ORDER BY created_at DESC
         LIMIT 1
       ) latest ON true
       LEFT JOIN messages ON messages.thread_id = threads.id
       WHERE threads.buyer_id = $1 OR threads.seller_id = $1
       GROUP BY threads.id, listings.title, latest.body, latest.created_at
       ORDER BY COALESCE(latest.created_at, threads.created_at) DESC`,
      [res.locals.currentUser.id]
    );
    res.render('pages/messages', { threads });
  })
);

app.get(
  '/messages/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const threadId = req.params.id;
    const { rows } = await query(
      `SELECT threads.*, listings.title AS listing_title,
              buyer.username AS buyer_name,
              seller.username AS seller_name
       FROM threads
       LEFT JOIN listings ON threads.listing_id = listings.id
       JOIN users buyer ON threads.buyer_id = buyer.id
       JOIN users seller ON threads.seller_id = seller.id
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
      `SELECT messages.*, users.username AS sender_name
       FROM messages
       JOIN users ON messages.sender_id = users.id
       WHERE thread_id = $1
       ORDER BY created_at ASC`,
      [threadId]
    );
    res.render('pages/thread', { thread, messages });
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
    const userId = res.locals.currentUser.id;
    const { rows: users } = await query(
      'SELECT id, username, email, avatar_url FROM users WHERE id = $1',
      [userId]
    );
    const { rows: listingStats } = await query('SELECT COUNT(*) FROM listings WHERE seller_id = $1', [userId]);
    const { rows: orderStats } = await query(
      'SELECT COUNT(*) FROM orders WHERE buyer_id = $1 OR seller_id = $1',
      [userId]
    );
    res.render('pages/profile', {
      user: users[0],
      listingCount: Number(listingStats[0]?.count || 0),
      orderCount: Number(orderStats[0]?.count || 0),
      error: null,
      success: null
    });
  })
);

app.post(
  '/profile/avatar',
  requireAuth,
  (req, res, next) => {
    uploadAvatarImage(req, res, async (error) => {
      if (!error) {
        return next();
      }
      const message =
        error.code === 'LIMIT_FILE_SIZE' ? 'Image must be smaller than 5MB.' : error.message || 'Upload failed.';
      const userId = res.locals.currentUser.id;
      const { rows: users } = await query('SELECT id, username, email, avatar_url FROM users WHERE id = $1', [
        userId
      ]);
      const { rows: listingStats } = await query('SELECT COUNT(*) FROM listings WHERE seller_id = $1', [userId]);
      const { rows: orderStats } = await query(
        'SELECT COUNT(*) FROM orders WHERE buyer_id = $1 OR seller_id = $1',
        [userId]
      );
      return res.render('pages/profile', {
        user: users[0],
        listingCount: Number(listingStats[0]?.count || 0),
        orderCount: Number(orderStats[0]?.count || 0),
        error: message,
        success: null
      });
    });
  },
  asyncHandler(async (req, res) => {
    if (!req.file) {
      const userId = res.locals.currentUser.id;
      const { rows: users } = await query('SELECT id, username, email, avatar_url FROM users WHERE id = $1', [
        userId
      ]);
      const { rows: listingStats } = await query('SELECT COUNT(*) FROM listings WHERE seller_id = $1', [userId]);
      const { rows: orderStats } = await query(
        'SELECT COUNT(*) FROM orders WHERE buyer_id = $1 OR seller_id = $1',
        [userId]
      );
      return res.render('pages/profile', {
        user: users[0],
        listingCount: Number(listingStats[0]?.count || 0),
        orderCount: Number(orderStats[0]?.count || 0),
        error: 'Please upload an avatar image.',
        success: null
      });
    }
    let avatarUrl;
    try {
      avatarUrl = await uploadImage(req.file);
    } catch (error) {
      const userId = res.locals.currentUser.id;
      const { rows: users } = await query('SELECT id, username, email, avatar_url FROM users WHERE id = $1', [
        userId
      ]);
      const { rows: listingStats } = await query('SELECT COUNT(*) FROM listings WHERE seller_id = $1', [userId]);
      const { rows: orderStats } = await query(
        'SELECT COUNT(*) FROM orders WHERE buyer_id = $1 OR seller_id = $1',
        [userId]
      );
      return res.render('pages/profile', {
        user: users[0],
        listingCount: Number(listingStats[0]?.count || 0),
        orderCount: Number(orderStats[0]?.count || 0),
        error: 'Avatar upload failed. Please try again.',
        success: null
      });
    }
    await query('UPDATE users SET avatar_url = $1 WHERE id = $2', [avatarUrl, res.locals.currentUser.id]);
    res.redirect('/profile');
  })
);

app.get(
  '/settings',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { rows } = await query(
      'SELECT email, notification_enabled, marketing_enabled FROM users WHERE id = $1',
      [res.locals.currentUser.id]
    );
    res.render('pages/settings', { user: rows[0], error: null, success: null });
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

    const { rows } = await query(
      'SELECT email, notification_enabled, marketing_enabled FROM users WHERE id = $1',
      [res.locals.currentUser.id]
    );
    res.render('pages/settings', { user: rows[0], error, success });
  })
);

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }
  const message =
    error.code === '42P01'
      ? 'The database is still warming up. Please retry in a moment.'
      : error.message || 'Something went wrong. Please try again.';
  return res.status(500).render('pages/error', { message });
});

app.listen(PORT, () => {
  console.log(`Marketplace app running on http://localhost:${PORT}`);
});
