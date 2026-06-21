/**
 * api/phishtank.js
 * Vercel serverless function — PhishTank API proxy.
 *
 * Proxies URL checks to PhishTank's checkurl API, keeping the
 * API key server-side. PhishTank rate-limits requests by IP and
 * app_key — proxying ensures the extension uses one shared key.
 *
 * Environment variables:
 *   PHISHTANK_API_KEY — Optional PhishTank app key (increases rate limit)
 *
 * POST /api/phishtank
 * Body: { url: string }
 * Response: { checked: boolean, inDatabase: boolean, phish?: boolean }
 */

'use strict';

const PHISHTANK_URL = 'https://checkurl.phishtank.com/checkurl/';

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (/^(chrome|moz)-extension:\/\//.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { url } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  try { new URL(url); } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  try {
    const formData = new URLSearchParams();
    formData.append('url', encodeURIComponent(url));
    formData.append('format', 'json');

    const apiKey = process.env.PHISHTANK_API_KEY;
    if (apiKey) formData.append('app_key', apiKey);

    const response = await fetch(PHISHTANK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'PhishGuard/1.0.0 (phishing-prevention-extension)',
      },
      body: formData.toString(),
    });

    if (!response.ok) {
      return res.status(502).json({ checked: false, error: `PhishTank error: ${response.status}` });
    }

    const data = await response.json();
    const results = data.results || {};

    return res.status(200).json({
      checked: true,
      inDatabase: results.in_database === true,
      phish: results.valid === true,
      phishId: results.phish_id || null,
      detailPage: results.phish_detail_page || null,
    });
  } catch (err) {
    console.error('[PhishTank] Error:', err.message);
    return res.status(500).json({ checked: false, error: 'Internal server error' });
  }
}
