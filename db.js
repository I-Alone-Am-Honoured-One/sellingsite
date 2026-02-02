const { Pool } = require('pg');

const shouldUseSsl =
  process.env.DATABASE_SSL === 'true' ||
  process.env.NODE_ENV === 'production' ||
  (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: shouldUseSsl ? { rejectUnauthorized: false } : false
});

async function query(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

module.exports = { pool, query };
