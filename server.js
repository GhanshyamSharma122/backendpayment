import express from 'express';
import dotenv from 'dotenv';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import cors from 'cors';

dotenv.config();

const { Pool } = pg;

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// Authenticate Middleware
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Register User
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, phone_number, first_name, last_name, date_of_birth } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(`
      INSERT INTO users (phone_number, email, hashed_password, created_at, updated_at)
      VALUES ($1, $2, $3, NOW(), NOW())
      RETURNING user_id, phone_number, email, created_at, updated_at
    `, [phone_number, email, hashed]);

    const user = result.rows[0];
    await pool.query(`INSERT INTO wallets (user_id, balance, created_at, updated_at) VALUES ($1, 0, NOW(), NOW())`, [user.user_id]);

    const token = jwt.sign({ user_id: user.user_id }, JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({
      user: {
        id: user.user_id,
        username,
        email: user.email,
        phone_number: user.phone_number,
        first_name,
        last_name,
        created_at: user.created_at,
        updated_at: user.updated_at
      },
      token,
      token_expiry: new Date(Date.now() + 3600000).toISOString()
    });
  } catch (err) {
    console.error(err);
    res.status(400).json({
      error: 'Registration failed',
      details: { field: 'unknown', message: err.message },
      timestamp: new Date().toISOString()
    });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body;
  try {
    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 OR phone_number = $1`,
      [identifier]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.hashed_password))) {
      return res.status(401).json({
        error: 'Invalid credentials',
        details: 'Username or password is incorrect',
        timestamp: new Date().toISOString()
      });
    }

    const token = jwt.sign({ user_id: user.user_id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({
      user: {
        id: user.user_id,
        username: identifier,
        email: user.email,
        phone_number: user.phone_number
      },
      token,
      token_expiry: new Date(Date.now() + 3600000).toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// Get Wallet Balance
app.get('/api/wallet', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM wallets WHERE user_id = $1`,
      [req.user.user_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Wallet not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Could not retrieve wallet', message: err.message });
  }
});

// Initiate Payment
app.post('/api/payment/initiate', async (req, res) => {
  const {
    sender_id,
    recipient_id,
    amount,
    currency,
    description,
    transaction_type,
    timestamp
  } = req.body;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const senderRes = await client.query(
      'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [sender_id]
    );
    if (senderRes.rows.length === 0) throw new Error('Sender wallet not found');
    const senderBalance = parseFloat(senderRes.rows[0].balance);
    if (senderBalance < amount) throw new Error('Insufficient balance');

    const recipientRes = await client.query(
      'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [recipient_id]
    );
    if (recipientRes.rows.length === 0) throw new Error('Recipient wallet not found');

    await client.query(
      'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2',
      [amount, sender_id]
    );
    await client.query(
      'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2',
      [amount, recipient_id]
    );

    const result = await client.query(
      `INSERT INTO transactions (sender_user_id, receiver_user_id, amount, currency, status, server_timestamp, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
       RETURNING transaction_id`,
      [sender_id, recipient_id, amount, currency, 'SYNCED', timestamp || new Date().toISOString()]
    );

    await client.query('COMMIT');

    res.json({
      payment_id: result.rows[0].transaction_id,
      status: 'SYNCED',
      sender_transaction_id: result.rows[0].transaction_id,
      recipient_transaction_id: result.rows[0].transaction_id,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({
      error: 'Transaction Failed',
      message: err.message,
      status_code: 400,
      transaction_attempt_id: crypto.randomUUID(),
      timestamp: new Date().toISOString()
    });
  } finally {
    client.release();
  }
});

// Get All Transactions by User ID
app.get('/api/transactions/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      `SELECT * FROM transactions WHERE sender_user_id = $1 OR receiver_user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions', message: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
