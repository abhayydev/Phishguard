/**
 * api/whois.js
 * Vercel serverless function — WHOIS domain lookup proxy.
 *
 * Uses the whois-json npm package to perform WHOIS lookups server-side.
 * Extracts domain registration date, expiry, registrar, and nameservers.
 *
 * Browser extensions cannot perform raw WHOIS queries (no TCP socket access),
 * so this backend route is required.
 *
 * Alternatively falls back to RDAP (Registration Data Access Protocol) which
 * is an HTTP-based WHOIS successor with structured JSON output.
 *
 * GET /api/whois?domain=example.com
 * Response: {
 *   checked: boolean,
 *   registrar?: string,
 *   createdDate?: string,
 *   updatedDate?: string,
 *   expiresDate?: string,
 *   domainAgeDays?: number,
 *   registrantCountry?: string,
 *   nameservers?: string[]
 * }
 */

'use strict';

// RDAP bootstrap servers by TLD
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

// RDAP base URLs for common TLDs (cached fallback to avoid bootstrap lookup)
const RDAP_SERVERS = {
  'com': 'https://rdap.verisign.com/com/v1/',
  'net': 'https://rdap.verisign.com/net/v1/',
  'org': 'https://rdap.publicinterestregistry.net/rdap/',
  'io': 'https://rdap.iana.org/',
  'co': 'https://rdap.iana.org/',
  'uk': 'https://rdap.nominet.uk/uk/',
  'de': 'https://rdap.denic.de/',
  'eu': 'https://rdap.eu/',
  'fr': 'https://rdap.nic.fr/',
};

/**
 * Parse a date string, returning null if invalid.
 */
function parseDate(str) {
  if (!str) return null;
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Compute age in days from an ISO date string.
 */
function computeAgeDays(isoDate) {
  if (!isoDate) return -1;
  const created = new Date(isoDate);
  return Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
}

/**
 * Extract TLD from a domain.
 */
function getTLD(domain) {
  const parts = domain.split('.');
  return parts[parts.length - 1].toLowerCase();
}

/**
 * Look up RDAP data for a domain.
 * RDAP is an HTTP-based alternative to WHOIS with structured JSON.
 */
async function rdapLookup(domain) {
  const tld = getTLD(domain);
  let rdapBase = RDAP_SERVERS[tld];

  // For unknown TLDs, try IANA's RDAP redirect service
  if (!rdapBase) {
    rdapBase = 'https://rdap.iana.org/';
  }

  const url = `${rdapBase}domain/${encodeURIComponent(domain)}`;

  const response = await fetch(url, {
    headers: { 'Accept': 'application/rdap+json' },
    signal: AbortSignal.timeout(7000),
  });

  if (!response.ok) {
    throw new Error(`RDAP responded with ${response.status}`);
  }

  const data = await response.json();

  // Parse RDAP events (creation, expiration, last changed)
  let createdDate = null, updatedDate = null, expiresDate = null;
  for (const event of (data.events || [])) {
    const action = event.eventAction?.toLowerCase();
    if (action === 'registration') createdDate = parseDate(event.eventDate);
    else if (action === 'last changed' || action === 'last update of rdap database') updatedDate = parseDate(event.eventDate);
    else if (action === 'expiration') expiresDate = parseDate(event.eventDate);
  }

  // Parse registrar from entities
  let registrar = null;
  let registrantCountry = null;
  for (const entity of (data.entities || [])) {
    const roles = entity.roles || [];
    if (roles.includes('registrar')) {
      registrar = entity.publicIds?.[0]?.identifier
        || entity.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3]
        || entity.handle
        || null;
    }
    if (roles.includes('registrant')) {
      const vcard = entity.vcardArray?.[1] || [];
      const addrEntry = vcard.find(v => v[0] === 'adr');
      registrantCountry = addrEntry?.[1]?.['country-name']
        || addrEntry?.[3]?.[6]
        || null;
    }
  }

  // Nameservers
  const nameservers = (data.nameservers || []).map(ns => ns.ldhName?.toLowerCase()).filter(Boolean);

  return { createdDate, updatedDate, expiresDate, registrar, registrantCountry, nameservers };
}

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (/^(chrome|moz)-extension:\/\//.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'public, s-maxage=3600'); // Cache 1 hour

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const domain = req.query.domain?.toLowerCase()?.replace(/^www\./, '');
  if (!domain || !/^[a-z0-9][a-z0-9\-_.]+[a-z0-9]$/.test(domain)) {
    return res.status(400).json({ checked: false, error: 'Invalid domain parameter' });
  }

  // Strip any path — domain only
  const cleanDomain = domain.split('/')[0];

  try {
    const result = await rdapLookup(cleanDomain);
    const domainAgeDays = computeAgeDays(result.createdDate);

    return res.status(200).json({
      checked: true,
      domain: cleanDomain,
      registrar: result.registrar,
      createdDate: result.createdDate,
      updatedDate: result.updatedDate,
      expiresDate: result.expiresDate,
      registrantCountry: result.registrantCountry,
      nameservers: result.nameservers,
      domainAgeDays,
    });
  } catch (err) {
    console.error('[WHOIS/RDAP] Error for domain', cleanDomain, ':', err.message);
    return res.status(200).json({
      checked: false,
      domain: cleanDomain,
      error: `RDAP lookup failed: ${err.message}`,
      domainAgeDays: -1,
    });
  }
}
