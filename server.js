// server.js
import express from 'express';
import pg from 'pg';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

const { Pool } = pg;
dotenv.config();

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

function generateToken(userId) {
  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
  const expiry = new Date(Date.now() + 86400000).toISOString();
  return { token, token_expiry: expiry };
}

async function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, phone_number, first_name, last_name, date_of_birth } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const userId = uuidv4();
    const now = new Date().toISOString();

    await pool.query(`INSERT INTO users (user_id, username, email, phone_number, hashed_password, first_name, last_name, date_of_birth, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [userId, username, email, phone_number, hashedPassword, first_name, last_name, date_of_birth, now, now]);

    await pool.query(`INSERT INTO wallets (wallet_id, user_id, balance, currency, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6)`,
      [uuidv4(), userId, 1000.00, 'INR', now, now]);

    const { token, token_expiry } = generateToken(userId);

    return res.json({
      user: { id: userId, username, email, phone_number, first_name, last_name, created_at: now, updated_at: now },
      token,
      token_expiry
    });
  } catch (err) {
    return res.status(400).json({ error: 'Registration failed', details: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body;
  try {
    const userResult = await pool.query(`SELECT * FROM users WHERE username = $1 OR email = $1`, [identifier]);
    const user = userResult.rows[0];

    if (!user || !(await bcrypt.compare(password, user.hashed_password))) {
      return res.status(401).json({ error: 'Invalid credentials', details: 'Incorrect username/email or password', timestamp: new Date().toISOString() });
    }

    const { token, token_expiry } = generateToken(user.user_id);

    return res.json({
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        phone_number: user.phone_number
      },
      token,
      token_expiry
    });
  } catch (err) {
    return res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

app.get('/api/wallet', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM wallets WHERE user_id = $1`, [req.userId]);
    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve wallet', message: err.message, status_code: 500 });
  }
});

app.post('/api/payment/initiate', authenticate, async (req, res) => {
  const { recipient_id, amount, currency, description, transaction_type, timestamp } = req.body;
  const sender_id = req.userId;
  const now = new Date().toISOString();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const senderBalance = await client.query(`SELECT balance FROM wallets WHERE user_id = $1`, [sender_id]);
    if (parseFloat(senderBalance.rows[0].balance) < amount) throw new Error('Insufficient funds');

    await client.query(`UPDATE wallets SET balance = balance - $1 WHERE user_id = $2`, [amount, sender_id]);
    await client.query(`UPDATE wallets SET balance = balance + $1 WHERE user_id = $2`, [amount, recipient_id]);

    const transaction_id = uuidv4();
    await client.query(`INSERT INTO transactions (transaction_id, sender_user_id, receiver_user_id, amount, currency, status, server_timestamp, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, 'SYNCED', $6, $6, $6)`,
      [transaction_id, sender_id, recipient_id, amount, currency, now]);

    await client.query('COMMIT');

    return res.json({
      payment_id: transaction_id,
      status: 'SYNCED',
      sender_transaction_id: transaction_id,
      recipient_transaction_id: transaction_id,
      created_at: now,
      updated_at: now
    });
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(400).json({ error: 'Payment failed', message: err.message, status_code: 400, timestamp: new Date().toISOString() });
  } finally {
    client.release();
  }
});

app.post('/api/offline/sync', authenticate, async (req, res) => {
  const { device_id, transactions } = req.body;
  const sender_id = req.userId;

  const client = await pool.connect();
  const now = new Date().toISOString();
  const synced = [];
  const failed = [];

  try {
    await client.query('BEGIN');

    for (const tx of transactions) {
      const exists = await client.query(`SELECT transaction_id FROM transactions WHERE encrypted_data = $1`, [tx.encrypted_data]);
      if (exists.rows.length > 0) {
        synced.push({ local_transaction_id: tx.local_transaction_id, server_transaction_id: exists.rows[0].transaction_id, status: 'ALREADY_SYNCED' });
        continue;
      }

      const receiverResult = await client.query(`SELECT user_id FROM users WHERE username = $1 OR email = $1 OR phone_number = $1`, [tx.recipient_identifier]);
      if (receiverResult.rows.length === 0) {
        failed.push({ local_transaction_id: tx.local_transaction_id, error: 'Recipient not found', reason: 'No user with identifier' });
        continue;
      }

      const receiver_id = receiverResult.rows[0].user_id;
      const transaction_id = uuidv4();

      const senderBalance = await client.query(`SELECT balance FROM wallets WHERE user_id = $1`, [sender_id]);
      if (parseFloat(senderBalance.rows[0].balance) < tx.amount) {
        failed.push({ local_transaction_id: tx.local_transaction_id, error: 'Insufficient funds', reason: 'Sender has insufficient balance' });
        continue;
      }

      await client.query(`UPDATE wallets SET balance = balance - $1 WHERE user_id = $2`, [tx.amount, sender_id]);
      await client.query(`UPDATE wallets SET balance = balance + $1 WHERE user_id = $2`, [tx.amount, receiver_id]);

      await client.query(`INSERT INTO transactions (transaction_id, sender_user_id, receiver_user_id, amount, currency, status, server_timestamp, created_at, updated_at, encrypted_data)
        VALUES ($1, $2, $3, $4, $5, 'SYNCED', $6, $6, $6, $7)`,
        [transaction_id, sender_id, receiver_id, tx.amount, tx.currency, now, tx.encrypted_data]);

      synced.push({ local_transaction_id: tx.local_transaction_id, server_transaction_id: transaction_id, status: 'SYNCED' });
    }

    await client.query('COMMIT');
    return res.json({ sync_id: uuidv4(), synced_transaction_details: synced, failed_transactions: failed, sync_completed_at: new Date().toISOString() });
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(500).json({ error: 'Sync failed', message: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM transactions WHERE sender_user_id = $1 OR receiver_user_id = $1 ORDER BY created_at DESC`, [req.userId]);
    return res.json(result.rows);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve transactions', message: err.message });
  }
});
app.get('/api/user/by-phone', authenticate, async (req, res) => {
  const { phone_number } = req.query;

  if (!phone_number) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  try {
    const result = await pool.query(
      `SELECT user_id, username FROM users WHERE phone_number = $1`,
      [phone_number]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve user', message: err.message });
  }
});


app.listen(3000, () => console.log('Server running on port 3000'));
