require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { query } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


function formatPrice(cents) {
  return `$${(cents / 100).toFixed(2)}`;
}

function createToken(user) {
  return jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, {
    expiresIn: '7d'
  });
}

async function hydrateUser(req, res, next) {
  const token = req.cookies.session;
  if (!token) {
    res.locals.currentUser = null;
    return next();
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await query('SELECT id, username, email FROM users WHERE id = $1', [payload.id]);
    res.locals.currentUser = rows[0] || null;
  } catch (error) {
    res.locals.currentUser = null;
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

app.get('/', async (req, res) => {
  const { rows: listings } = await query(
    'SELECT listings.*, users.username AS seller_name FROM listings JOIN users ON listings.seller_id = users.id ORDER BY listings.created_at DESC LIMIT 6'
  );
  res.render('pages/landing', { listings, formatPrice });
});

app.get('/marketplace', async (req, res) => {
  const search = req.query.search ? `%${req.query.search}%` : null;
  const { rows: listings } = await query(
    `SELECT listings.*, users.username AS seller_name
     FROM listings
     JOIN users ON listings.seller_id = users.id
     WHERE ($1::text IS NULL OR listings.title ILIKE $1 OR listings.description ILIKE $1 OR listings.category ILIKE $1)
     ORDER BY listings.created_at DESC`,
    [search]
  );
  res.render('pages/marketplace', { listings, formatPrice, search: req.query.search || '' });
});

app.get('/listings/new', requireAuth, (req, res) => {
  res.render('pages/create-listing', { error: null });
});

app.post('/listings', requireAuth, async (req, res) => {
  const { title, description, price, category, condition, imageUrl, shippingDetails } = req.body;
  if (!title || !description || !price || !category || !condition || !imageUrl || !shippingDetails) {
    return res.render('pages/create-listing', { error: 'All fields are required.' });
  }
  const priceCents = Math.round(Number(price) * 100);
  if (Number.isNaN(priceCents) || priceCents <= 0) {
    return res.render('pages/create-listing', { error: 'Price must be a positive number.' });
  }
  await query(
    `INSERT INTO listings (seller_id, title, description, price_cents, category, condition, image_url, shipping_details)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [res.locals.currentUser.id, title, description, priceCents, category, condition, imageUrl, shippingDetails]
  );
  return res.redirect('/marketplace');
});

app.get('/listings/:id', async (req, res) => {
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
    return res.status(404).send('Listing not found');
  }
  res.render('pages/listing-detail', { listing, formatPrice, currentUser: res.locals.currentUser });
});

app.post('/listings/:id/buy', requireAuth, async (req, res) => {
  const listingId = req.params.id;
  const buyerId = res.locals.currentUser.id;
  const { rows } = await query('SELECT * FROM listings WHERE id = $1', [listingId]);
  const listing = rows[0];
  if (!listing) {
    return res.status(404).send('Listing not found');
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
});

app.post('/listings/:id/message', requireAuth, async (req, res) => {
  const listingId = req.params.id;
  const { rows } = await query('SELECT * FROM listings WHERE id = $1', [listingId]);
  const listing = rows[0];
  if (!listing) {
    return res.status(404).send('Listing not found');
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
});

app.get('/auth/register', (req, res) => {
  res.render('pages/register', { error: null });
});

app.post('/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.render('pages/register', { error: 'All fields are required.' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  try {
    const { rows } = await query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, passwordHash]
    );
    const token = createToken(rows[0]);
    res.cookie('session', token, { httpOnly: true, sameSite: 'lax' });
    return res.redirect('/');
  } catch (error) {
    return res.render('pages/register', { error: 'Username or email already in use.' });
  }
});

app.get('/auth/sign-in', (req, res) => {
  res.render('pages/sign-in', { error: null });
});

app.post('/auth/sign-in', async (req, res) => {
  const { email, password } = req.body;
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
  const token = createToken(user);
  res.cookie('session', token, { httpOnly: true, sameSite: 'lax' });
  return res.redirect('/');
});

app.post('/auth/logout', (req, res) => {
  res.clearCookie('session');
  res.redirect('/');
});

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

app.get('/orders', requireAuth, async (req, res) => {
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
});

app.get('/orders/:id', requireAuth, async (req, res) => {
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
    return res.status(404).send('Order not found');
  }
  if (order.buyer_id !== res.locals.currentUser.id && order.seller_id !== res.locals.currentUser.id) {
    return res.status(403).send('Forbidden');
  }
  const now = Date.now();
  const deliveredAt = order.delivered_at ? new Date(order.delivered_at).getTime() : null;
  const remainingMs = deliveredAt ? Math.max(0, deliveredAt + 24 * 60 * 60 * 1000 - now) : null;
  res.render('pages/order-detail', { order, formatPrice, currentUser: res.locals.currentUser, remainingMs });
});

app.post('/orders/:id/ship', requireAuth, async (req, res) => {
  const orderId = req.params.id;
  const trackingCode = req.body.trackingCode || 'No tracking provided';
  const { rows } = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
  const order = rows[0];
  if (!order) {
    return res.status(404).send('Order not found');
  }
  if (order.seller_id !== res.locals.currentUser.id) {
    return res.status(403).send('Forbidden');
  }
  await query(
    `UPDATE orders
     SET status = 'SHIPPED', tracking_code = $1, shipped_at = NOW()
     WHERE id = $2`,
    [trackingCode, orderId]
  );
  return res.redirect(`/orders/${orderId}`);
});

app.post('/orders/:id/deliver', requireAuth, async (req, res) => {
  const orderId = req.params.id;
  const { rows } = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
  const order = rows[0];
  if (!order) {
    return res.status(404).send('Order not found');
  }
  if (order.seller_id !== res.locals.currentUser.id) {
    return res.status(403).send('Forbidden');
  }
  await query(
    `UPDATE orders
     SET status = 'DELIVERED', delivered_at = NOW()
     WHERE id = $1`,
    [orderId]
  );
  return res.redirect(`/orders/${orderId}`);
});

app.post('/orders/:id/confirm', requireAuth, async (req, res) => {
  const orderId = req.params.id;
  const { rows } = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
  const order = rows[0];
  if (!order) {
    return res.status(404).send('Order not found');
  }
  if (order.buyer_id !== res.locals.currentUser.id) {
    return res.status(403).send('Forbidden');
  }
  await query(
    `UPDATE orders
     SET status = 'CONFIRMED', confirmed_at = NOW()
     WHERE id = $1`,
    [orderId]
  );
  return res.redirect(`/orders/${orderId}`);
});

app.post('/orders/:id/dispute', requireAuth, async (req, res) => {
  const orderId = req.params.id;
  const { rows } = await query('SELECT * FROM orders WHERE id = $1', [orderId]);
  const order = rows[0];
  if (!order) {
    return res.status(404).send('Order not found');
  }
  if (order.buyer_id !== res.locals.currentUser.id) {
    return res.status(403).send('Forbidden');
  }
  await query(
    `UPDATE orders
     SET status = 'DISPUTED', disputed_at = NOW()
     WHERE id = $1`,
    [orderId]
  );
  return res.redirect(`/orders/${orderId}`);
});

app.get('/messages', requireAuth, async (req, res) => {
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
     ORDER BY latest.created_at DESC NULLS LAST`,
    [res.locals.currentUser.id]
  );
  res.render('pages/messages', { threads });
});

app.get('/messages/:id', requireAuth, async (req, res) => {
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
    return res.status(404).send('Thread not found');
  }
  if (thread.buyer_id !== res.locals.currentUser.id && thread.seller_id !== res.locals.currentUser.id) {
    return res.status(403).send('Forbidden');
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
});

app.post('/messages/:id', requireAuth, async (req, res) => {
  const threadId = req.params.id;
  const { body } = req.body;
  if (!body) {
    return res.redirect(`/messages/${threadId}`);
  }
  const { rows } = await query('SELECT * FROM threads WHERE id = $1', [threadId]);
  const thread = rows[0];
  if (!thread) {
    return res.status(404).send('Thread not found');
  }
  if (thread.buyer_id !== res.locals.currentUser.id && thread.seller_id !== res.locals.currentUser.id) {
    return res.status(403).send('Forbidden');
  }
  await query(
    'INSERT INTO messages (thread_id, sender_id, body) VALUES ($1, $2, $3)',
    [threadId, res.locals.currentUser.id, body]
  );
  return res.redirect(`/messages/${threadId}`);
});

app.listen(PORT, () => {
  console.log(`Marketplace app running on http://localhost:${PORT}`);
});
