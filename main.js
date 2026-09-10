require('dotenv').config();
const express = require('express');
const { google } = require('googleapis');
const cors = require('cors');
const crypto = require('crypto');
const redis = require('redis');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

const app = express();
app.use(cors());
app.use(express.json());

const SCOPES = ["https://www.googleapis.com/auth/drive.file"];

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// Initialize Redis Client
const redisClient = redis.createClient({
  url: process.env.REDIS_URL
});
redisClient.on('error', (err) => console.error('Redis Client Error', err));
redisClient.connect().then(() => console.log('Connected to Redis'));

// Adding Redis client with the rate limiter
const store = new RedisStore({
  sendCommand: (...args) => redisClient.sendCommand(args),
});

// All the rate limiter definition
const generateUrlLimiter = rateLimit({
  store: store,
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Please wait 15 minutes.' }
});

const pollingLimiter = rateLimit({
  store: store,
  windowMs: 5 * 60 * 1000,
  max: 200, 
  message: { error: 'Rate limit exceeded.' }
});

const refreshLimiter = rateLimit({
  store: store,
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many refresh requests.' }
});

// Generate URL and start session
app.get('/auth/google/url', generateUrlLimiter, async (req, res) => {
  const sessionId = crypto.randomBytes(16).toString('hex');

  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
    state: sessionId 
  });

  await redisClient.set(sessionId, JSON.stringify({ status: 'pending' }), { EX: 300 });

  res.json({ url, sessionId });
});

// Callback from Google
app.get('/auth/google/callback', async (req, res) => {
  const { code, state: sessionId } = req.query;

  if (!code || !sessionId) {
    return res.status(400).send('Invalid request.');
  }

  try {
    const sessionData = await redisClient.get(sessionId);
    if (!sessionData) {
      return res.status(400).send('Session expired or invalid.');
    }

    const { tokens } = await oauth2Client.getToken(code);
    await redisClient.set(sessionId, JSON.stringify({ status: 'completed', tokens }), { EX: 300 });

    // Success response
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f8f9fa; color: #202124; }
          .container { text-align: center; padding: 40px; background: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
          h2 { color: #1a73e8; margin-bottom: 10px; }
          p { font-size: 16px; margin-bottom: 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Authentication successful.</h2>
          <p>You can now close the window.</p>
        </div>
        <script>
          // Attempt to automatically close the tab (may be blocked by some browsers)
          setTimeout(() => { window.close(); }, 3000);
        </script>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('Exchange error:', error);
    res.status(500).send('Authentication exchange failed.');
  }
});

// Polling endpoint for Electron
app.get('/auth/google/status', pollingLimiter, async (req, res) => {
  const { sessionId } = req.query;

  const isValidHex = /^[0-9a-fA-F]{32}$/.test(sessionId);
  if (!sessionId || !isValidHex) {
    return res.status(400).json({ error: 'Invalid session format' });
  }
  
  if (!sessionId) return res.status(400).json({ error: 'Missing sessionId' });

  try {
    const sessionStr = await redisClient.get(sessionId);
    
    if (!sessionStr) {
      return res.status(404).json({ error: 'Session not found or expired' });
    }

    const session = JSON.parse(sessionStr);

    if (session.status === 'completed') {
      await redisClient.del(sessionId); 
      return res.json({ status: 'completed', tokens: session.tokens });
    }

    res.json({ status: 'pending' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/google/refresh', refreshLimiter, async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Missing refreshToken' });
  }

  try {
    // Temporary client instance to refresh credentials
    const client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET
    );

    client.setCredentials({ refresh_token: refreshToken });

    // New tokens from Google
    const { credentials } = await client.refreshAccessToken();

    res.json({
      access_token: credentials.access_token,
      refresh_token: credentials.refresh_token || refreshToken,
      expiry_date: credentials.expiry_date
    });
  } catch (error) {
    console.error('Refresh error:', error.response?.data || error.message);
    
    // Google returns 'invalid_grant' when the refresh token is expired or revoked
    const isRevokedOrExpired = error.response?.data?.error === 'invalid_grant';
    
    res.status(isRevokedOrExpired ? 401 : 500).json({
      error: isRevokedOrExpired ? 'REFRESH_TOKEN_EXPIRED' : 'Failed to refresh token'
    });
  }
});

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));