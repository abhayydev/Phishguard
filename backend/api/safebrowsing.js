/**
 * api/safebrowsing.js
 * Vercel serverless function — Google Safe Browsing API proxy.
 *
 * Proxies requests from the PhishGuard extension to the Google Safe Browsing
 * API v4, keeping the API key server-side and out of the extension bundle.
 *
 * Environment variables required:
 *   SAFE_BROWSING_API_KEY — Google Cloud API key with Safe Browsing API enabled
 *
 * POST /api/safebrowsing
 * Body: { url: string }
 * Response: { checked: boolean, threat: boolean, threatType?: string }
 */

'use strict';

const SAFE_BROWSING_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

const ALLOWED_ORIGINS = [
  // Chrome extension origins are chrome-extension://EXTENSION_ID
  // We allow all extension origins since the ID changes per install
  /^chrome-extension:\/\//,
  /^moz-extension:\/\//,
];

/**
 * CORS check — only allow extension origins.
 */
function isAllowedOrigin(origin) {
  if (!origin) return false;
  return ALLOWED_ORIGINS.some(pattern => pattern.test(origin));
}

export default async function handler(req, res) {
  const origin = req.headers.origin || '';

  // CORS headers for extension access
  if (isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const apiKey = process.env.SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ checked: false, error: 'Safe Browsing API key not configured' });
  }

  const { url } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid url parameter' });
  }

  // Validate URL format before forwarding
  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  try {
    const response = await fetch(`${SAFE_BROWSING_URL}?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: {
          clientId: 'phishguard-extension',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('[SafeBrowsing] API error:', response.status, errText);
      return res.status(502).json({ checked: false, error: `Upstream error: ${response.status}` });
    }

    const data = await response.json();
    const matches = data.matches || [];

    return res.status(200).json({
      checked: true,
      threat: matches.length > 0,
      threatType: matches[0]?.threatType || null,
      matches: matches.length > 0 ? matches : undefined,
    });
  } catch (err) {
    console.error('[SafeBrowsing] Fetch error:', err.message);
    return res.status(500).json({ checked: false, error: 'Internal server error' });
  }
}
