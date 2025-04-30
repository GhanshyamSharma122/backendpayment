// server.js

import express from 'express';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
app.use(express.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Middleware to authenticate token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Helper: format user for response
const formatUser = (user) => ({
  id: user.user_id,
  username: user.username,
  email: user.email,
  phone_number: user.phone_number,
  first_name: user.first_name,
  last_name: user.last_name,
  created_at: user.created_at,
  updated_at: user.updated_at,
});

// 4.1.1 Register User
app.post('/api/auth/register', async (req, res) => {
  const {
    username,
    email,
    password,
    phone_number,
    first_name,
    last_name,
    date_of_birth,
  } = req.body;

  if (!username || !email || !password || !phone_number) {
    return res.status(400).json({
      error: 'Invalid input',
      details: { field: 'required', message: 'Missing required fields' },
      timestamp: new Date().toISOString(),
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, email, phone_number, hashed_password, first_name, last_name, date_of_birth)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [username, email, phone_number, hashedPassword, first_name, last_name, date_of_birth]
    );

    const user = result.rows[0];

    await pool.query(
      `INSERT INTO wallets (user_id) VALUES ($1)`,
      [user.user_id]
    );

    const token = jwt.sign({ user_id: user.user_id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      user: formatUser(user),
      token,
      token_expiry: new Date(Date.now() + 3600000).toISOString(),
    });
  } catch (err) {
    res.status(400).json({
      error: 'Registration failed',
      details: { field: 'unknown', message: err.message },
      timestamp: new Date().toISOString(),
    });
  }
});

// 4.1.2 Login User
app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body;

  try {
    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 OR username = $1`,
      [identifier]
    );

    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.hashed_password))) {
      return res.status(401).json({
        error: 'Invalid credentials',
        details: 'Incorrect email/username or password',
        timestamp: new Date().toISOString(),
      });
    }

    const token = jwt.sign({ user_id: user.user_id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        phone_number: user.phone_number,
      },
      token,
      token_expiry: new Date(Date.now() + 3600000).toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: 'Login error', details: err.message });
  }
});

// 4.2.1 Get Wallet Balance
app.get('/api/wallet', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM wallets WHERE user_id = $1`,
      [req.user.user_id]
    );

    const wallet = result.rows[0];
    if (!wallet) return res.status(404).json({ error: 'Wallet not found' });

    res.json(wallet);
  } catch (err) {
    res.status(500).json({ error: 'Database error', message: err.message });
  }
});

// 4.3.1 Initiate Payment
app.post('/api/payment/initiate', authenticateToken, async (req, res) => {
  const {
    sender_id,
    recipient_id,
    amount,
    currency,
    description,
    transaction_type,
    timestamp,
  } = req.body;

  try {
    const result = await pool.query(
      `INSERT INTO transactions (sender_user_id, receiver_user_id, amount, currency, description, transaction_type, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'SYNCED')
       RETURNING *`,
      [sender_id, recipient_id, amount, currency, description, transaction_type]
    );

    res.json({
      payment_id: result.rows[0].transaction_id,
      status: result.rows[0].status,
      sender_transaction_id: result.rows[0].transaction_id,
      recipient_transaction_id: result.rows[0].transaction_id,
      created_at: result.rows[0].created_at,
      updated_at: result.rows[0].updated_at,
    });
  } catch (err) {
    res.status(500).json({
      error: 'Payment failed',
      message: err.message,
      status_code: 500,
      transaction_attempt_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
    });
  }
});

// 5. Sync Offline Transactions and Update Balances
app.post('/api/payment/sync', async (req, res) => {
  const { transactions } = req.body;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const tx of transactions) {
      const {
        sender_id,
        recipient_id,
        amount,
        currency,
        timestamp,
        status = 'SYNCED',
        transaction_type = 'TRANSFER',
        description = ''
      } = tx;

      const senderRes = await client.query(
        'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
        [sender_id]
      );
      const senderBalance = parseFloat(senderRes.rows[0]?.balance ?? 0);
      if (senderBalance < amount) throw new Error(`Insufficient balance for user ${sender_id}`);

      const recipientRes = await client.query(
        'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
        [recipient_id]
      );
      if (recipientRes.rows.length === 0) throw new Error(`Recipient wallet not found for ${recipient_id}`);

      await client.query(
        'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2',
        [amount, sender_id]
      );
      await client.query(
        'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2',
        [amount, recipient_id]
      );

      await client.query(
        `INSERT INTO transactions (
          sender_user_id, receiver_user_id, amount, currency, status,
          transaction_type, server_timestamp, description, created_at, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),NOW())`,
        [sender_id, recipient_id, amount, currency, status, transaction_type, timestamp, description]
      );
    }

    await client.query('COMMIT');
    res.json({ message: 'Transactions synced and balances updated.' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: 'Sync failed', message: err.message });
  } finally {
    client.release();
  }
});

// 6. Get All Transactions for a User
app.get('/api/transactions/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    const result = await pool.query(
      `SELECT * FROM transactions
       WHERE sender_user_id = $1 OR receiver_user_id = $1
       ORDER BY server_timestamp DESC`,
      [userId]
    );

    res.json({
      user_id: userId,
      transaction_count: result.rowCount,
      transactions: result.rows
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve transactions', message: err.message });
  }
});
