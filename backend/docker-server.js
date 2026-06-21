/**
 * docker-server.js
 * Lightweight Express adapter for running PhishGuard backend
 * outside of Vercel (Docker, Railway, Fly.io, etc.)
 *
 * Mounts each API handler as an Express route, simulating Vercel's
 * serverless function interface.
 */

import express from 'express';
import { default as safeBrowsingHandler } from './api/safebrowsing.js';
import { default as phishTankHandler } from './api/phishtank.js';
import { default as whoisHandler } from './api/whois.js';
import { default as reportHandler } from './api/report.js';

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Wrap Vercel-style handlers for Express
function wrapHandler(handler) {
  return async (req, res) => {

    try {
      await handler(req, res);
    } catch (err) {
      console.error('Handler error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  };
}

// Health check
app.get('/health', (_, res) => res.json({ status: 'ok', service: 'phishguard-backend' }));

// API routes
app.post('/api/safebrowsing', wrapHandler(safeBrowsingHandler));
app.options('/api/safebrowsing', wrapHandler(safeBrowsingHandler));

app.post('/api/phishtank', wrapHandler(phishTankHandler));
app.options('/api/phishtank', wrapHandler(phishTankHandler));

app.get('/api/whois', wrapHandler(whoisHandler));
app.options('/api/whois', wrapHandler(whoisHandler));

app.post('/api/report', wrapHandler(reportHandler));
app.options('/api/report', wrapHandler(reportHandler));

// 404
app.use((_, res) => res.status(404).json({ error: 'Not found' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`[PhishGuard Backend] Running on port ${PORT}`);
});
