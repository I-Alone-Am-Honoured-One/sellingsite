# SafeSwap Marketplace

## Product pitch
SafeSwap is a buyer-to-buyer marketplace inspired by Eneba + Vinted that protects every transaction through escrow-style payments. Buyers pay through the platform, sellers ship quickly, and buyers have a 24‑hour confirmation window after delivery to confirm or dispute the order—automatic release happens after the window closes.

This MVP focuses on trust, transparency, and speed: real-time messaging between buyers and sellers, clear order statuses, and simple listing creation so anyone can start selling in minutes.

## Feature list
### MVP (implemented)
- User registration + sign-in with hashed passwords and JWT session cookies.
- Landing page with “About” steps, new listings, and CTA to marketplace.
- Marketplace browsing + search.
- Listing details with buy + message actions.
- Create listing flow with title, description, price, category, condition, image URL, and shipping details.
- Order lifecycle: PAID → SHIPPED → DELIVERED → CONFIRMED / DISPUTED.
- Seller order actions (mark shipped, add tracking, mark delivered).
- Buyer order actions (confirm received, report issue).
- 24‑hour auto-confirm rule after delivery.
- Messaging inbox, 1:1 threads, unread indicator, chat view.

### Nice-to-have
- Stripe payment integration instead of mock purchase.
- File upload for listing images.
- Dispute resolution dashboard for admins.
- Push/email notifications on order status changes.

## Database schema
### users
- id (PK)
- username (unique)
- email (unique)
- password_hash
- created_at

### listings
- id (PK)
- seller_id (FK users)
- title
- description
- price_cents
- category
- condition
- image_url
- shipping_details
- created_at

### orders
- id (PK)
- listing_id (FK listings)
- buyer_id (FK users)
- seller_id (FK users)
- status
- tracking_code
- paid_at
- shipped_at
- delivered_at
- confirmed_at
- disputed_at
- created_at

### threads
- id (PK)
- listing_id (FK listings)
- order_id (FK orders)
- buyer_id (FK users)
- seller_id (FK users)
- created_at

### messages
- id (PK)
- thread_id (FK threads)
- sender_id (FK users)
- body
- created_at
- is_read

## API + page routes
### Auth
- GET /auth/register
- POST /auth/register
- GET /auth/sign-in
- POST /auth/sign-in
- POST /auth/logout

### Listings
- GET /marketplace
- GET /listings/:id
- GET /listings/new
- POST /listings
- POST /listings/:id/buy
- POST /listings/:id/message

### Orders
- GET /orders
- GET /orders/:id
- POST /orders/:id/ship
- POST /orders/:id/deliver
- POST /orders/:id/confirm
- POST /orders/:id/dispute

### Messaging
- GET /messages
- GET /messages/:id
- POST /messages/:id

### Landing
- GET /

## Page list + UI flow
1. Landing → Marketplace CTA → Marketplace browse/search → Listing detail.
2. Listing detail → Buy now → Order detail (buyer) → Confirm/dispute.
3. Listing detail → Message seller → Inbox thread → Chat.
4. Create listing → New listing appears on landing + marketplace.
5. Orders page: buyer/seller tabs for all order states.

## Security basics
- Validation on required fields + numeric price.
- Auth guard on protected pages/actions.
- Passwords hashed with bcrypt.
- JWT stored in HTTP-only cookie.
- Suggested: rate limit login endpoints and add CSRF protection for production.

## Step-by-step build plan
1. Configure database + run `db/schema.sql`.
2. Set environment variables (`DATABASE_URL`, `JWT_SECRET`).
3. Install dependencies: `npm install`.
4. Start the server: `npm run dev`.
5. Register users, create listings, and test order + messaging flows.
