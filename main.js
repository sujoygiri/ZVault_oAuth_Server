require('dotenv').config();
const express = require('express');
const { google } = require('googleapis');
const cors = require('cors');
const crypto = require('crypto');
const redis = require('redis');

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

// Endpoint 1: Generate URL and start session
app.get('/auth/google/url', async (req, res) => {
  const sessionId = crypto.randomBytes(16).toString('hex');

  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
    state: sessionId 
  });

  // Store pending status in Redis with a 5-minute expiration (300 seconds)
  await redisClient.set(sessionId, JSON.stringify({ status: 'pending' }), { EX: 300 });

  res.json({ url, sessionId });
});

// Endpoint 2: Callback from Google
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
    
    // Update Redis with the tokens and mark as completed
    await redisClient.set(sessionId, JSON.stringify({ status: 'completed', tokens }), { EX: 300 });

    // Success response shown in the user's default browser
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

// Endpoint 3: Polling endpoint for Electron
app.get('/auth/google/status', async (req, res) => {
  const { sessionId } = req.query;
  
  if (!sessionId) return res.status(400).json({ error: 'Missing sessionId' });

  try {
    const sessionStr = await redisClient.get(sessionId);
    
    if (!sessionStr) {
      return res.status(404).json({ error: 'Session not found or expired' });
    }

    const session = JSON.parse(sessionStr);

    if (session.status === 'completed') {
      // Clean up Redis immediately after successful retrieval
      await redisClient.del(sessionId); 
      return res.json({ status: 'completed', tokens: session.tokens });
    }

    res.json({ status: 'pending' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));