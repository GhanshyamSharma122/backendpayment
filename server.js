import express from 'express';
import pg from 'pg';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios'; // Added for making HTTP requests to EmailJS API

const { Pool } = pg;
dotenv.config();

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Be cautious with this in production
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_fallback'; // Use a fallback for safety

// --- EmailJS Configuration (from .env) ---
const EMAILJS_SERVICE_ID = process.env.EMAILJS_SERVICE_ID;
const EMAILJS_TEMPLATE_ID = process.env.EMAILJS_TEMPLATE_ID;
const EMAILJS_PUBLIC_KEY = process.env.EMAILJS_PUBLIC_KEY; // This is your User ID / Public Key
const EMAILJS_ACCESS_TOKEN = process.env.EMAILJS_PRIVATE_KEY; // This is your Private Key / Access Token

function generateToken(userId) {
  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
  const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  return { token, token_expiry: expiry };
}

async function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized', message: 'No token provided.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token', message: 'Token is not valid or has expired.' });
  }
}

// --- HTML Formatting Helper for Email ---
function formatTransactionsForEmailHtmlOnServer(transactions, userName, appName, recipientEmail) {
    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        try {
            const date = new Date(dateString);
            return date.toLocaleString('en-US', { 
            month: 'short', day: 'numeric', year: 'numeric', 
            hour: 'numeric', minute: '2-digit', hour12: true 
            });
        } catch (e) { return dateString; }
    };
    const htmlEscape = (text) => String(text ?? '').replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>').replace(/"/g, '"').replace(/'/g, ''');

    let transactionRowsHtml = transactions.map(tx => {
        const isIncoming = tx.type === 'incoming'; // 'type' is now determined before calling this function
        const amount = parseFloat(tx.amount || 0).toFixed(2);
        const amountDisplay = `${isIncoming ? '+' : '-'}${htmlEscape(tx.currency)}${amount}`;
        return `
        <tr>
            <td>${formatDate(tx.date)}</td>
            <td>${htmlEscape(tx.party_name)}</td>
            <td>${htmlEscape(tx.type_display)}</td>
            <td style="color:${isIncoming ? 'green' : 'red'}; font-weight: bold;">${amountDisplay}</td>
            <td>${htmlEscape(tx.description) || '-'}</td>
        </tr>`;
    }).join('');

    if (transactions.length === 0) {
        transactionRowsHtml = "<tr><td colspan='5' style='text-align:center;'>No transactions to display.</td></tr>";
    }
  
    return `
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Transaction History</title><style>
            body {font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; color: #333; line-height: 1.6;}
            .container {background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); max-width: 750px; margin: 20px auto; border: 1px solid #e0e0e0;}
            .header {text-align: center; padding-bottom: 20px; border-bottom: 2px solid #007bff; margin-bottom: 25px;}
            .header h1 {margin: 0; color: #0056b3; font-size: 28px;}
            .greeting p {font-size: 1.15em; margin-bottom: 20px; color: #444;}
            .content-info p {font-size: 1em; color: #555; margin-bottom: 25px;}
            table {width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.95em; box-shadow: 0 2px 5px rgba(0,0,0,0.05);}
            th, td {border: 1px solid #ddd; padding: 12px 15px; text-align: left;}
            th {background-color: #007bff; color: #ffffff; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;}
            tr:nth-child(even) {background-color: #f2f7fc;}
            tr:hover {background-color: #e9eff5;}
            .footer {text-align: center; margin-top: 35px; padding-top: 20px; border-top: 1px solid #eee; font-size: 0.9em; color: #888;}
            .footer p {margin: 6px 0;}
        </style></head>
        <body><div class="container">
        <div class="header"><h1>Transaction History</h1></div>
        <div class="greeting"><p>Dear ${htmlEscape(userName)},</p></div>
        <div class="content-info"><p>Please find your recent transaction summary from ${htmlEscape(appName)} below. This report was requested to be sent to ${htmlEscape(recipientEmail)}.</p></div>
        <h3>Transaction Details:</h3>
        <table><thead><tr><th>Date</th><th>Party</th><th>Type</th><th>Amount</th><th>Description</th></tr></thead>
        <tbody>${transactionRowsHtml}</tbody></table>
        <div class="footer"><p>Thank you for using ${htmlEscape(appName)}!</p><p>© ${new Date().getFullYear()} ${htmlEscape(appName)}. All rights reserved.</p></div>
        </div></body></html>
    `;
}


// --- Your existing API Endpoints ---
// (app.post('/api/auth/register', ...), app.post('/api/auth/login', ...), etc.)
// I will paste them below for completeness, then add the new email endpoint.

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
    console.error("Registration Error:", err);
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
      user: { id: user.user_id, username: user.username, email: user.email, phone_number: user.phone_number },
      token,
      token_expiry
    });
  } catch (err) {
    console.error("Login Error:", err);
    return res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

app.get('/api/wallet', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM wallets WHERE user_id = $1`, [req.userId]);
    return res.json(result.rows[0] || { balance: 0, currency: 'INR' }); // Return default if no wallet
  } catch (err) {
    console.error("Get Wallet Error:", err);
    return res.status(500).json({ error: 'Failed to retrieve wallet', message: err.message, status_code: 500 });
  }
});

app.post('/api/payment/initiate', authenticate, async (req, res) => {
  const { recipient_id, amount, currency, description, transaction_type } = req.body; // Removed timestamp from body
  const sender_id = req.userId;
  const now = new Date().toISOString();

  if (!recipient_id || !amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Invalid payment details', message: 'Recipient ID and valid amount are required.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const senderWallet = await client.query(`SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE`, [sender_id]);
    if (!senderWallet.rows[0] || parseFloat(senderWallet.rows[0].balance) < parseFloat(amount)) {
      throw new Error('Insufficient funds');
    }
    const recipientWallet = await client.query(`SELECT user_id FROM wallets WHERE user_id = $1 FOR UPDATE`, [recipient_id]);
    if (recipientWallet.rows.length === 0) {
        throw new Error('Recipient wallet not found.');
    }

    await client.query(`UPDATE wallets SET balance = balance - $1 WHERE user_id = $2`, [amount, sender_id]);
    await client.query(`UPDATE wallets SET balance = balance + $1 WHERE user_id = $2`, [amount, recipient_id]);

    const transaction_id = uuidv4();
    await client.query(
      `INSERT INTO transactions (
         transaction_id, sender_user_id, receiver_user_id, amount, currency, status, server_timestamp, created_at, updated_at, transaction_type, description
       )
       VALUES ($1, $2, $3, $4, $5, 'COMPLETED', $6, $6, $6, $7, $8)`, // Changed status to COMPLETED
      [transaction_id, sender_id, recipient_id, amount, currency || 'INR', now, transaction_type || 'TRANSFER', description || '']
    );
    await client.query('COMMIT');
    return res.json({
      payment_id: transaction_id, status: 'COMPLETED', created_at: now, updated_at: now
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Payment Initiation Error:", err);
    return res.status(400).json({ error: 'Payment failed', message: err.message, status_code: 400, timestamp: new Date().toISOString() });
  } finally {
    client.release();
  }
});

app.post('/api/wallet/topup', authenticate, async (req, res) => {
  const { amount, currency = 'INR' } = req.body;
  const userId = req.userId;
  if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Invalid top-up amount' });
  }
  const now = new Date().toISOString();
  try {
    const result = await pool.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = $2 WHERE user_id = $3 RETURNING wallet_id, user_id, balance, currency, updated_at`,
      [amount, now, userId]
    );
    const transactionId = uuidv4();
    await pool.query(
      `INSERT INTO transactions (transaction_id, sender_user_id, receiver_user_id, amount, currency, status, server_timestamp, created_at, updated_at, transaction_type, description)
       VALUES ($1, $2, $3, $4, $5, 'COMPLETED', $6, $6, $6, 'TOP_UP', 'Wallet top-up')`, // Changed status to COMPLETED
      [transactionId, null, userId, amount, currency, now] // sender_user_id is NULL for top-up
    );
    return res.status(200).json({
      message: 'Balance topped up successfully', wallet: result.rows[0], transaction_id: transactionId, updated_at: now
    });
  } catch (err) {
    console.error('Top-up failed:', err);
    return res.status(500).json({ error: 'Failed to top up wallet', message: err.message });
  }
});

app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    // Modified query to fetch party names directly
    const result = await pool.query(
      `SELECT 
         t.transaction_id,
         t.sender_user_id,
         s_user.first_name AS sender_first_name,
         s_user.last_name AS sender_last_name,
         s_user.username AS sender_username,
         t.receiver_user_id,
         r_user.first_name AS receiver_first_name,
         r_user.last_name AS receiver_last_name,
         r_user.username AS receiver_username,
         t.amount,
         t.currency,
         t.status,
         t.server_timestamp,
         t.created_at,
         t.updated_at,
         t.transaction_type,
         t.description
       FROM transactions t
       LEFT JOIN users s_user ON t.sender_user_id = s_user.user_id
       LEFT JOIN users r_user ON t.receiver_user_id = r_user.user_id
       WHERE t.sender_user_id = $1 OR t.receiver_user_id = $1 
       ORDER BY t.created_at DESC`, 
      [req.userId]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Get Transactions Error:", err);
    return res.status(500).json({ error: 'Failed to retrieve transactions', message: err.message });
  }
});

app.post('/api/contacts', authenticate, async (req, res) => {
  const { name, phoneNumber } = req.body;
  const owner_user_id = req.userId;
  if (!name || !phoneNumber) {
    return res.status(400).json({ error: 'Name and phone number are required.' });
  }
  try {
    const newContactResult = await pool.query(
      `INSERT INTO user_contacts (owner_user_id, contact_name, contact_phone_number) VALUES ($1, $2, $3) RETURNING id, contact_name, contact_phone_number, created_at`,
      [owner_user_id, name, phoneNumber]
    );
    res.status(201).json(newContactResult.rows[0]);
  } catch (err) {
    if (err.code === '23505') { //Handles unique constraint violation (e.g. duplicate phone number)
      return res.status(409).json({ error: 'Contact with this phone number already exists for you.', details: err.detail });
    }
    console.error('Error adding contact:', err);
    return res.status(500).json({ error: 'Failed to add contact.', details: err.message });
  }
});

app.get('/api/contacts', authenticate, async (req, res) => {
  const owner_user_id = req.userId;
  try {
    const contactsResult = await pool.query(
      `SELECT id, contact_name, contact_phone_number, created_at FROM user_contacts WHERE owner_user_id = $1 ORDER BY contact_name ASC`,
      [owner_user_id]
    );
    res.json(contactsResult.rows);
  } catch (err) {
    console.error('Error fetching contacts:', err);
    return res.status(500).json({ error: 'Failed to retrieve contacts.', details: err.message });
  }
});

app.delete('/api/contacts/:contactId', authenticate, async (req, res) => {
  const { contactId } = req.params;
  const owner_user_id = req.userId;
  try {
    const deleteResult = await pool.query(
      `DELETE FROM user_contacts WHERE id = $1 AND owner_user_id = $2 RETURNING id`,
      [contactId, owner_user_id]
    );
    if (deleteResult.rowCount === 0) {
      return res.status(404).json({ error: 'Contact not found or you do not have permission to delete it.' });
    }
    res.status(200).json({ message: 'Contact deleted successfully.', id: contactId });
  } catch (err) {
    console.error('Error deleting contact:', err);
    return res.status(500).json({ error: 'Failed to delete contact.', details: err.message });
  }
});

app.get('/api/user/by-phone', authenticate, async (req, res) => {
  const { phone_number } = req.query;
  if (!phone_number) {
    return res.status(400).json({ error: 'Phone number is required' });
  }
  try {
    const result = await pool.query(
      `SELECT user_id AS id, username, first_name, last_name, email, phone_number AS original_phone_number FROM users WHERE phone_number = $1`,
      [phone_number]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("Error in /api/user/by-phone:", err);
    return res.status(500).json({ error: 'Failed to retrieve user', message: err.message });
  }
});

app.get('/api/user/:userId', authenticate, async (req, res) => {
  const { userId: requestedUserId } = req.params; // Renamed to avoid conflict with req.userId
  try {
    const result = await pool.query(
      `SELECT user_id as id, username, first_name, last_name FROM users WHERE user_id = $1`,
      [requestedUserId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("Error fetching user by id:", err);
    return res.status(500).json({ error: 'Failed to retrieve user details', message: err.message });
  }
});


// === NEW ENDPOINT for sending transaction history email VIA EMAILJS REST API ===
app.post('/api/emailjs/send-transaction-history', authenticate, async (req, res) => {
  const userId = req.userId;
  const { recipient_email } = req.body;

  // Check for essential EmailJS config from .env
  if (!EMAILJS_SERVICE_ID || !EMAILJS_TEMPLATE_ID || !EMAILJS_PUBLIC_KEY || !EMAILJS_ACCESS_TOKEN) {
    console.error("EmailJS environment variables not configured properly on the server.");
    return res.status(500).json({ error: 'Email service configuration error on server.' });
  }

  if (!recipient_email) {
    return res.status(400).json({ error: 'Recipient email is required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient_email)) {
      return res.status(400).json({ error: 'Invalid recipient email format.' });
  }

  try {
    const userResult = await pool.query('SELECT first_name, last_name FROM users WHERE user_id = $1', [userId]);
    const user = userResult.rows[0];
    const userNameForEmail = user ? `${user.first_name || ''} ${user.last_name || ''}`.trim() : 'Valued Customer';
    const appName = "Payment App"; 

    const transactionsResult = await pool.query(
      `SELECT 
         t.transaction_id, t.sender_user_id, t.receiver_user_id, t.amount, t.currency, t.status, 
         t.server_timestamp, t.created_at, t.transaction_type, t.description,
         s.first_name as sender_first_name, s.last_name as sender_last_name, s.username as sender_username,
         r.first_name as receiver_first_name, r.last_name as receiver_last_name, r.username as receiver_username
       FROM transactions t
       LEFT JOIN users s ON t.sender_user_id = s.user_id
       LEFT JOIN users r ON t.receiver_user_id = r.user_id
       WHERE t.sender_user_id = $1 OR t.receiver_user_id = $1 
       ORDER BY t.created_at DESC`, 
      [userId]
    );

    const processedTransactions = transactionsResult.rows.map(tx => {
        const isIncoming = tx.receiver_user_id === userId;
        let partyName = "Unknown User";
        if (tx.transaction_type === 'TOP_UP') {
            partyName = "Wallet Top-up";
        } else if (isIncoming) {
            partyName = (tx.sender_first_name || tx.sender_last_name) ? `${tx.sender_first_name || ''} ${tx.sender_last_name || ''}`.trim() : (tx.sender_username || (tx.sender_user_id ? tx.sender_user_id.substring(0,8) + "..." : "System/External"));
        } else { // Outgoing or self-transfer
            partyName = (tx.receiver_first_name || tx.receiver_last_name) ? `${tx.receiver_first_name || ''} ${tx.receiver_last_name || ''}`.trim() : (tx.receiver_username || (tx.receiver_user_id ? tx.receiver_user_id.substring(0,8) + "..." : "System/External"));
            if (tx.sender_user_id === tx.receiver_user_id) partyName = "Yourself (Transfer)";
        }
        
        let typeDisplay = tx.transaction_type === 'TOP_UP' ? 'Top-up' : (isIncoming ? 'Received' : 'Sent');

        return {
            date: tx.server_timestamp || tx.created_at,
            party_name: partyName,
            type: isIncoming && tx.transaction_type !== 'TOP_UP' ? 'incoming' : 'outgoing', // for styling
            type_display: typeDisplay, // for display text
            amount: tx.amount,
            currency: tx.currency || 'INR',
            description: tx.description,
        };
    });

    const emailHtmlContent = formatTransactionsForEmailHtmlOnServer(processedTransactions, userNameForEmail, appName, recipient_email);

    const emailJsParams = {
      service_id: EMAILJS_SERVICE_ID,
      template_id: EMAILJS_TEMPLATE_ID,
      user_id: EMAILJS_PUBLIC_KEY, 
      accessToken: EMAILJS_ACCESS_TOKEN, 
      template_params: {
        'to_email': recipient_email,
        'user_name': userNameForEmail,
        'transaction_summary': emailHtmlContent,
        'app_name': appName,
        'title': `Your Transaction History from ${appName}`, 
      }
    };
    
    const emailJsApiUrl = 'https://api.emailjs.com/api/v1.0/email/send';
    
    console.log("Attempting to send email via EmailJS API with params:", JSON.stringify(emailJsParams, null, 2));


    const emailJsResponse = await axios.post(emailJsApiUrl, emailJsParams, {
      headers: { 'Content-Type': 'application/json' }
    });

    console.log("EmailJS API Response Status:", emailJsResponse.status);
    console.log("EmailJS API Response Data:", emailJsResponse.data);


    if (emailJsResponse.status === 200 && emailJsResponse.data === 'OK') {
        return res.status(200).json({ message: `Transaction history sent to ${recipient_email} successfully via EmailJS.` });
    } else {
        console.error('EmailJS API responded with non-OK:', emailJsResponse.status, emailJsResponse.data);
        return res.status(500).json({ error: 'Failed to send email via EmailJS API.', details: emailJsResponse.data || "Unknown EmailJS API error" });
    }

  } catch (err) {
    console.error('Error processing /api/emailjs/send-transaction-history:', err.isAxiosError && err.response ? JSON.stringify(err.response.data, null, 2) : err.message);
    const errorDetails = err.isAxiosError && err.response ? { status: err.response.status, data: err.response.data } : { message: err.message };
    return res.status(err.response?.status || 500).json({ error: 'Failed to send transaction history email.', details: errorDetails });
  }
});


// --- Fallback for undefined routes ---
app.use((req, res) => {
  res.status(404).json({ error: "Not Found", message: `The requested URL ${req.originalUrl} was not found on this server.` });
});

// --- Global error handler ---
app.use((err, req, res, next) => {
  console.error("Global Error Handler:", err.stack || err);
  res.status(500).json({ error: "Internal Server Error", message: err.message || "Something went wrong!" });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
