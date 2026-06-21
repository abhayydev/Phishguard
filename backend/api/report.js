/**
 * api/report.js
 * Vercel serverless function — phishing report submission endpoint.
 *
 * Accepts user-submitted phishing reports from the PhishGuard extension.
 * Optionally forwards reports to PhishTank or stores them (e.g., in a DB).
 *
 * For this reference implementation, reports are logged server-side.
 * In production, connect to a database (e.g., Vercel Postgres, PlanetScale).
 *
 * POST /api/report
 * Body: { url, notes?, classification?, score? }
 * Response: { ok: boolean, reportId: string }
 */

'use strict';

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (/^(chrome|moz)-extension:\/\//.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { url, notes, classification, score } = req.body || {};

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  // Validate URL
  try { new URL(url); } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const reportId = `rpt_${Date.now()}_${Math.random().toString(36).substr(2, 8)}`;

  // In production: save to database here
  // Example with Vercel Postgres:
  // await sql`INSERT INTO reports (id, url, notes, classification, score, created_at)
  //           VALUES (${reportId}, ${url}, ${notes}, ${classification}, ${score}, NOW())`;

  console.log('[PhishGuard Report]', JSON.stringify({
    reportId,
    url,
    notes: notes?.substring(0, 500),
    classification,
    score,
    timestamp: new Date().toISOString(),
  }));

  // Optionally submit to PhishTank
  if (process.env.PHISHTANK_SUBMIT_KEY) {
    try {
      const form = new URLSearchParams();
      form.append('url', url);
      form.append('app_key', process.env.PHISHTANK_SUBMIT_KEY);
      // Note: PhishTank submission API requires separate registration
      // This is a placeholder for the submission flow
    } catch (err) {
      console.warn('[PhishGuard Report] PhishTank submission failed:', err.message);
    }
  }

  return res.status(200).json({ ok: true, reportId });
}
