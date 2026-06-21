/**
 * threat-intelligence.js
 * Threat intelligence integration for PhishGuard.
 *
 * Integrates with:
 * - Google Safe Browsing API v4 (Lookup API)
 * - PhishTank API
 * - WHOIS lookup (via backend proxy to avoid CORS)
 *
 * All external API calls are routed through the user's configurable backend
 * to protect API keys and avoid CORS issues.
 */

'use strict';

// ─── Safe Browsing Threat Types ───────────────────────────────────────────────
const SAFE_BROWSING_THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
];

const SAFE_BROWSING_PLATFORM_TYPES = ['ANY_PLATFORM'];
const SAFE_BROWSING_ENTRY_TYPES = ['URL'];

// ─── Request Timeout ─────────────────────────────────────────────────────────
const FETCH_TIMEOUT_MS = 8000;

/**
 * Fetch with a timeout, returning null on timeout or network error.
 * @param {string} url
 * @param {RequestInit} [options]
 * @returns {Promise<Response|null>}
 */
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch {
    clearTimeout(timeoutId);
    return null;
  }
}

// ─── Google Safe Browsing ─────────────────────────────────────────────────────

/**
 * Check a URL against Google Safe Browsing API v4.
 * Can be called directly with an API key or proxied through the backend.
 *
 * @param {string} urlToCheck - The URL to check
 * @param {object} config - { apiKey?: string, backendURL?: string }
 * @returns {Promise<{ checked: boolean, threat: boolean, threatType?: string, error?: string }>}
 */
export async function checkSafeBrowsing(urlToCheck, config = {}) {
  const { apiKey, backendURL } = config;

  if (!apiKey && !backendURL) {
    return { checked: false, threat: false, error: 'No API key or backend configured' };
  }

  try {
    let requestURL;
    let requestBody;

    if (backendURL) {
      // Use backend proxy to protect the API key
      requestURL = `${backendURL}/api/safebrowsing`;
      requestBody = JSON.stringify({ url: urlToCheck });
    } else {
      // Direct API call (API key exposed in extension — use backend instead)
      requestURL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
      requestBody = JSON.stringify({
        client: { clientId: 'phishguard-extension', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: SAFE_BROWSING_THREAT_TYPES,
          platformTypes: SAFE_BROWSING_PLATFORM_TYPES,
          threatEntryTypes: SAFE_BROWSING_ENTRY_TYPES,
          threatEntries: [{ url: urlToCheck }],
        },
      });
    }

    const response = await fetchWithTimeout(requestURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: requestBody,
    });

    if (!response) {
      return { checked: false, threat: false, error: 'Request timed out' };
    }

    if (!response.ok) {
      return { checked: false, threat: false, error: `HTTP ${response.status}` };
    }

    const data = await response.json();

    // Interpret response
    const hasMatches = data.matches && data.matches.length > 0;
    const threatType = hasMatches ? data.matches[0].threatType : null;

    return {
      checked: true,
      threat: hasMatches,
      threatType,
      rawResponse: hasMatches ? data.matches : null,
    };
  } catch (err) {
    return { checked: false, threat: false, error: err.message };
  }
}

// ─── PhishTank ────────────────────────────────────────────────────────────────

/**
 * Check a URL against PhishTank's database.
 * PhishTank provides a free API (with registration) for URL lookups.
 *
 * @param {string} urlToCheck
 * @param {object} config - { apiKey?: string, backendURL?: string }
 * @returns {Promise<{ checked: boolean, inDatabase: boolean, phish?: boolean, phishId?: string, error?: string }>}
 */
export async function checkPhishTank(urlToCheck, config = {}) {
  const { apiKey, backendURL } = config;

  if (!backendURL && !apiKey) {
    return { checked: false, inDatabase: false, error: 'No backend or API key configured' };
  }

  try {
    let requestURL;
    let requestBody;

    if (backendURL) {
      requestURL = `${backendURL}/api/phishtank`;
      requestBody = JSON.stringify({ url: urlToCheck });
    } else {
      // Direct PhishTank API call
      requestURL = 'https://checkurl.phishtank.com/checkurl/';
      const formData = new URLSearchParams();
      formData.append('url', encodeURIComponent(urlToCheck));
      formData.append('format', 'json');
      if (apiKey) formData.append('app_key', apiKey);
      requestBody = formData.toString();
    }

    const response = await fetchWithTimeout(requestURL, {
      method: 'POST',
      headers: backendURL
        ? { 'Content-Type': 'application/json' }
        : { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: requestBody,
    });

    if (!response) return { checked: false, inDatabase: false, error: 'Request timed out' };
    if (!response.ok) return { checked: false, inDatabase: false, error: `HTTP ${response.status}` };

    const data = await response.json();

    // PhishTank response shape: { results: { in_database, phish_detail_page, ... } }
    const results = data.results || data;
    return {
      checked: true,
      inDatabase: results.in_database === true,
      phish: results.valid === true || results.phish === true,
      phishId: results.phish_id,
      detailPage: results.phish_detail_page,
    };
  } catch (err) {
    return { checked: false, inDatabase: false, error: err.message };
  }
}

// ─── WHOIS Lookup ─────────────────────────────────────────────────────────────

/**
 * Look up WHOIS/domain registration data for a domain.
 * Requires the backend to proxy the WHOIS query (no CORS for WHOIS over HTTP).
 *
 * @param {string} domain
 * @param {object} config - { backendURL: string }
 * @returns {Promise<{
 *   checked: boolean,
 *   registrar?: string,
 *   createdDate?: string,
 *   updatedDate?: string,
 *   expiresDate?: string,
 *   domainAgeDays?: number,
 *   error?: string
 * }>}
 */
export async function lookupWHOIS(domain, config = {}) {
  const { backendURL } = config;

  if (!backendURL) {
    return { checked: false, error: 'Backend URL not configured for WHOIS lookups' };
  }

  try {
    const response = await fetchWithTimeout(
      `${backendURL}/api/whois?domain=${encodeURIComponent(domain)}`,
      { method: 'GET' }
    );

    if (!response) return { checked: false, error: 'Request timed out' };
    if (!response.ok) return { checked: false, error: `HTTP ${response.status}` };

    const data = await response.json();

    // Calculate domain age in days
    let domainAgeDays = -1;
    if (data.createdDate) {
      const created = new Date(data.createdDate);
      if (!isNaN(created.getTime())) {
        domainAgeDays = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
      }
    }

    return {
      checked: true,
      registrar: data.registrar,
      createdDate: data.createdDate,
      updatedDate: data.updatedDate,
      expiresDate: data.expiresDate,
      registrantCountry: data.registrantCountry,
      domainAgeDays,
      nameservers: data.nameservers,
    };
  } catch (err) {
    return { checked: false, error: err.message };
  }
}

// ─── Aggregated Threat Intelligence ──────────────────────────────────────────

/**
 * Run all configured threat intelligence checks for a URL in parallel.
 *
 * @param {string} url
 * @param {object} settings - User settings from storage-manager
 * @returns {Promise<object>} Aggregated threat intelligence results
 */
export async function runThreatIntelligence(url, settings = {}) {
  const config = {
    apiKey: settings.safeBrowsingAPIKey,
    phishTankKey: settings.phishTankAPIKey,
    backendURL: settings.backendURL,
  };

  let domain = '';
  try {
    domain = new URL(url).hostname;
  } catch { /* ignore */ }

  const promises = [];
  const checks = [];

  if (settings.useSafeBrowsing) {
    promises.push(checkSafeBrowsing(url, { apiKey: config.apiKey, backendURL: config.backendURL }));
    checks.push('safeBrowsing');
  }

  if (settings.usePhishTank) {
    promises.push(checkPhishTank(url, { apiKey: config.phishTankKey, backendURL: config.backendURL }));
    checks.push('phishTank');
  }

  if (settings.useWhois && domain && config.backendURL) {
    promises.push(lookupWHOIS(domain, { backendURL: config.backendURL }));
    checks.push('whois');
  }

  const results = await Promise.allSettled(promises);

  const intel = {};
  checks.forEach((checkName, i) => {
    const r = results[i];
    intel[checkName] = r.status === 'fulfilled'
      ? r.value
      : { checked: false, error: r.reason?.message || 'Unknown error' };
  });

  return intel;
}
