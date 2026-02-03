# Sellar Marketplace

## Product pitch
Sellar is a gamer-first marketplace with escrow-style protection. Buyers pay through the platform, sellers ship quickly, and buyers have a 24‑hour confirmation window after delivery to confirm or dispute the order—automatic release happens after the window closes.

## Feature list
### MVP (implemented)
- User registration + sign-in with hashed passwords and JWT session cookies.
- Dark-mode, neon marketplace UI with reusable layout + component styles.
- Landing page with hero, categories, stats, testimonials, FAQ, and multiple listing sections.
- Marketplace browsing + search + category/condition filters.
- Listing details with buy + message actions.
- Create listing flow with category + condition dropdowns and image uploads.
- Order lifecycle: PAID → SHIPPED → DELIVERED → CONFIRMED / DISPUTED.
- Seller order actions (mark shipped, add tracking, mark delivered).
- Buyer order actions (confirm received, report issue).
- 24‑hour auto-confirm rule after delivery.
- Messaging inbox, 1:1 threads, unread indicator, chat view.
- Profile + settings pages with avatar uploads and notification preferences.
- Health check route for Render (`/healthz`).

### Nice-to-have
- Stripe payment integration instead of mock purchase.
- Dispute resolution dashboard for admins.
- Push/email notifications on order status changes.

## Required environment variables
- `DATABASE_URL`
- `JWT_SECRET`
- `CLOUDINARY_CLOUD_NAME` (optional for uploads)
- `CLOUDINARY_API_KEY` (optional for uploads)
- `CLOUDINARY_API_SECRET` (optional for uploads)
- `DATABASE_SSL` (optional, set to `true` when needed)

## Local development
1. Configure the database and run `db/schema.sql`.
2. Apply migrations in `db/migrations` as needed.
3. Install dependencies: `npm install`.
4. Start the server: `npm run dev`.
5. Visit `http://localhost:3000`.

## Render deployment
1. Set `DATABASE_URL`, `JWT_SECRET`, and Cloudinary vars in Render.
2. Ensure `DATABASE_SSL=true` if your database requires SSL.
3. Use `npm install` then `npm start` as the build/start commands.
4. Render can use `/healthz` for health checks.

## Database schema
### users
- id (PK)
- username (unique)
- email (unique)
- password_hash
- avatar_url
- notification_enabled
- marketing_enabled
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

### Profile + settings
- GET /profile
- POST /profile/avatar
- GET /settings
- POST /settings

### Health
- GET /healthz

## Quick test checklist
- Register and sign in.
- Upload an avatar from the profile page.
- Create a listing with an image upload.
- Message a seller and verify unread count in inbox.
- Buy a listing and update order status.
- Confirm delivery and see status timeline updates.
