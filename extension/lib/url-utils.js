/**
 * url-utils.js
 * Core URL parsing and analysis utilities for PhishGuard.
 * Handles domain extraction, homoglyph detection, typosquatting,
 * URL shortener detection, and other structural URL checks.
 */

'use strict';

// ─── Known URL Shorteners ────────────────────────────────────────────────────
export const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
  'short.link', 'rb.gy', 'cutt.ly', 'shorturl.at', 'is.gd', 'v.gd',
  'clck.ru', 'snip.ly', 'bl.ink', 'rebrand.ly', 'tiny.cc', 'lnkd.in',
  'ift.tt', 'dlvr.it', 'soo.gd', 'po.st', 'x.co', 'zi.pe'
]);

// ─── Suspicious TLDs ─────────────────────────────────────────────────────────
export const SUSPICIOUS_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work',
  '.party', '.racing', '.download', '.loan', '.win', '.bid', '.stream',
  '.review', '.men', '.faith', '.date', '.accountant', '.cricket',
  '.science', '.trade', '.webcam', '.click', '.link', '.kim', '.country'
]);

// ─── High-Value Brand Keywords (for typosquatting detection) ─────────────────
export const BRAND_KEYWORDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'twitter',
  'instagram', 'netflix', 'linkedin', 'dropbox', 'github', 'gmail', 'yahoo',
  'outlook', 'office365', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
  'americanexpress', 'visa', 'mastercard', 'ebay', 'walmart', 'target',
  'coinbase', 'binance', 'blockchain', 'metamask', 'steam', 'adobe',
  'docusign', 'fedex', 'ups', 'usps', 'dhl', 'irs', 'ssa', 'medicare'
];

// ─── Homoglyph Map (Unicode lookalikes → ASCII) ───────────────────────────────
export const HOMOGLYPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
  'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g',
  'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm',
  'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ǫ': 'q', 'ʀ': 'r', 'ꜱ': 's',
  'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'b',
  '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i', '|': 'l'
};

// ─── Phishing Keywords ────────────────────────────────────────────────────────
export const PHISHING_KEYWORDS = [
  'login', 'signin', 'sign-in', 'account', 'verify', 'verification',
  'update', 'confirm', 'secure', 'security', 'banking', 'credential',
  'password', 'passwd', 'authenticate', 'auth', 'wallet', 'recover',
  'support', 'help', 'service', 'suspended', 'unusual', 'activity',
  'alert', 'warning', 'urgent', 'limited', 'expire', 'expiry',
  'validate', 'reactivate', 'unlock', 'restore', 'refund', 'claim'
];

/**
 * Safely parse a URL string, returning null on failure.
 * @param {string} urlString
 * @returns {URL|null}
 */
export function safeParseURL(urlString) {
  try {
    return new URL(urlString);
  } catch {
    return null;
  }
}

/**
 * Extract the registered domain (eTLD+1) from a hostname.
 * Uses a simple heuristic – for production, integrate a Public Suffix List.
 * @param {string} hostname
 * @returns {string}
 */
export function extractRegisteredDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.replace(/^www\./, '').split('.');
  if (parts.length <= 2) return hostname.replace(/^www\./, '');
  // Handle common two-part TLDs (co.uk, com.au, etc.)
  const twoPartTLDs = ['co.uk', 'co.nz', 'co.za', 'com.au', 'org.uk', 'net.au', 'gov.uk'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTLDs.includes(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Count the number of subdomains in a hostname.
 * @param {string} hostname
 * @returns {number}
 */
export function countSubdomains(hostname) {
  if (!hostname) return 0;
  const withoutWww = hostname.replace(/^www\./, '');
  const parts = withoutWww.split('.');
  return Math.max(0, parts.length - 2);
}

/**
 * Normalize a domain by replacing homoglyphs with ASCII equivalents.
 * @param {string} domain
 * @returns {string}
 */
export function normalizeHomoglyphs(domain) {
  let normalized = '';
  for (const char of domain.toLowerCase()) {
    normalized += HOMOGLYPH_MAP[char] ?? char;
  }
  return normalized;
}

/**
 * Check if a hostname is an IP address (IPv4 or IPv6).
 * @param {string} hostname
 * @returns {boolean}
 */
export function isIPAddress(hostname) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
  return ipv4Regex.test(hostname) || ipv6Regex.test(hostname);
}

/**
 * Compute Levenshtein edit distance between two strings.
 * Used for typosquatting detection.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function levenshteinDistance(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * Detect typosquatting by comparing domain against known brand keywords.
 * Returns an array of { brand, distance } matches where distance <= 2.
 * @param {string} domain
 * @returns {{ brand: string, distance: number }[]}
 */
export function detectTyposquatting(domain) {
  const normalizedDomain = normalizeHomoglyphs(domain.toLowerCase());
  const domainWithoutTLD = normalizedDomain.split('.').slice(0, -1).join('');
  const matches = [];

  for (const brand of BRAND_KEYWORDS) {
    // Exact brand name present but not AS the brand domain
    if (domainWithoutTLD.includes(brand) && !domainWithoutTLD.startsWith(brand)) {
      matches.push({ brand, distance: 0, type: 'brand-in-subdomain' });
      continue;
    }
    // Levenshtein distance check
    const dist = levenshteinDistance(domainWithoutTLD, brand);
    if (dist > 0 && dist <= 2 && domainWithoutTLD.length >= brand.length - 2) {
      matches.push({ brand, distance: dist, type: 'typosquatting' });
    }
  }
  return matches;
}

/**
 * Detect homoglyph attacks in a domain.
 * Returns true if the domain contains non-ASCII lookalike characters.
 * @param {string} domain
 * @returns {boolean}
 */
export function detectHomoglyphs(domain) {
  for (const char of domain) {
    if (HOMOGLYPH_MAP[char] !== undefined && !/[0-9]/.test(char)) {
      return true;
    }
  }
  // Check for Punycode (xn--) indicating IDN that may contain homoglyphs
  return domain.includes('xn--');
}

/**
 * Detect if a URL uses a known URL shortener service.
 * @param {string} hostname
 * @returns {boolean}
 */
export function isURLShortener(hostname) {
  const domain = hostname.replace(/^www\./, '').toLowerCase();
  return URL_SHORTENERS.has(domain);
}

/**
 * Check if a URL has a suspicious TLD.
 * @param {string} hostname
 * @returns {boolean}
 */
export function hasSuspiciousTLD(hostname) {
  const lower = hostname.toLowerCase();
  for (const tld of SUSPICIOUS_TLDS) {
    if (lower.endsWith(tld)) return true;
  }
  return false;
}

/**
 * Analyze URL path and query string for phishing keywords.
 * @param {string} urlString
 * @returns {{ found: string[], count: number }}
 */
export function findPhishingKeywords(urlString) {
  const lower = urlString.toLowerCase();
  const found = PHISHING_KEYWORDS.filter(kw => lower.includes(kw));
  return { found, count: found.length };
}

/**
 * Check if a URL has an unusually long length (common in phishing).
 * @param {string} urlString
 * @returns {boolean}
 */
export function hasLongURL(urlString) {
  return urlString.length > 150;
}

/**
 * Check for excessive special characters in a URL (obfuscation indicator).
 * @param {string} urlString
 * @returns {boolean}
 */
export function hasExcessiveSpecialChars(urlString) {
  const specialChars = (urlString.match(/[-_.~!*'();:@&=+$,/?%#[\]]/g) || []).length;
  return specialChars > 20;
}

/**
 * Check if a URL contains an encoded IP address (e.g., hex or octal encoded).
 * @param {string} urlString
 * @returns {boolean}
 */
export function hasEncodedIP(urlString) {
  // Match hex-encoded IPv4 (0x7f000001) or dotless decimal
  const hexIPRegex = /0x[0-9a-f]{8}/i;
  const octalIPRegex = /0\d{10,11}/;
  const dotlessDecimalRegex = /\/\/\d{7,12}(\/|$)/;
  return hexIPRegex.test(urlString) || octalIPRegex.test(urlString) || dotlessDecimalRegex.test(urlString);
}

/**
 * Check for @ symbol in URL (credential embedding trick, RFC 3986).
 * @param {string} urlString
 * @returns {boolean}
 */
export function hasAtSymbolInURL(urlString) {
  try {
    const url = new URL(urlString);
    return url.username.length > 0 || url.password.length > 0;
  } catch {
    return urlString.includes('@');
  }
}

/**
 * Check for double-slash redirect tricks (e.g., http://evil.com//google.com).
 * @param {string} urlString
 * @returns {boolean}
 */
export function hasRedirectTrick(urlString) {
  try {
    const url = new URL(urlString);
    // Check for redirect parameter containing another URL
    const redirectParams = ['url', 'redirect', 'next', 'return', 'goto', 'target', 'redir', 'to'];
    for (const param of redirectParams) {
      const val = url.searchParams.get(param);
      if (val && (val.startsWith('http') || val.startsWith('//'))) {
        return true;
      }
    }
  } catch { /* ignore */ }
  return false;
}

/**
 * Full structural URL analysis. Returns a detailed result object.
 * @param {string} urlString
 * @returns {object}
 */
export function analyzeURLStructure(urlString) {
  const url = safeParseURL(urlString);
  if (!url) {
    return { valid: false, error: 'Invalid URL' };
  }

  const hostname = url.hostname.toLowerCase();
  const registeredDomain = extractRegisteredDomain(hostname);
  const subdomainCount = countSubdomains(hostname);
  const typosquatMatches = detectTyposquatting(registeredDomain);
  const keywordAnalysis = findPhishingKeywords(urlString);

  return {
    valid: true,
    url: urlString,
    hostname,
    registeredDomain,
    protocol: url.protocol,
    path: url.pathname,
    query: url.search,
    // Security flags
    isHTTPS: url.protocol === 'https:',
    isIPBased: isIPAddress(hostname),
    isURLShortener: isURLShortener(hostname),
    hasSuspiciousTLD: hasSuspiciousTLD(hostname),
    hasHomoglyphs: detectHomoglyphs(hostname),
    hasLongURL: hasLongURL(urlString),
    hasExcessiveSpecialChars: hasExcessiveSpecialChars(urlString),
    hasEncodedIP: hasEncodedIP(urlString),
    hasAtSymbol: hasAtSymbolInURL(urlString),
    hasRedirectTrick: hasRedirectTrick(urlString),
    subdomainCount,
    excessiveSubdomains: subdomainCount > 3,
    typosquatMatches,
    phishingKeywords: keywordAnalysis,
    urlLength: urlString.length,
  };
}
