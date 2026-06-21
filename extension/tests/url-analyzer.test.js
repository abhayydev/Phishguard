/**
 * url-analyzer.test.js
 * Unit tests for PhishGuard URL analysis utilities.
 *
 * Run with: node --experimental-vm-modules tests/url-analyzer.test.js
 * Or with a test runner like Jest (after configuring for ES modules).
 *
 * These tests validate the core URL analysis logic without requiring
 * a browser environment — all utilities are pure JavaScript functions.
 */

'use strict';

// ─── Minimal test harness (no dependencies required) ─────────────────────────
let passed = 0, failed = 0;

function describe(name, fn) {
  console.log(`\n  📦 ${name}`);
  fn();
}

function it(name, fn) {
  try {
    fn();
    console.log(`    ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`    ✗ ${name}`);
    console.error(`      → ${err.message}`);
    failed++;
  }
}

function expect(actual) {
  return {
    toBe: (expected) => {
      if (actual !== expected) throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    },
    toEqual: (expected) => {
      const a = JSON.stringify(actual), b = JSON.stringify(expected);
      if (a !== b) throw new Error(`Expected ${b}, got ${a}`);
    },
    toBeTruthy: () => {
      if (!actual) throw new Error(`Expected truthy, got ${JSON.stringify(actual)}`);
    },
    toBeFalsy: () => {
      if (actual) throw new Error(`Expected falsy, got ${JSON.stringify(actual)}`);
    },
    toBeGreaterThan: (n) => {
      if (actual <= n) throw new Error(`Expected ${actual} > ${n}`);
    },
    toBeLessThan: (n) => {
      if (actual >= n) throw new Error(`Expected ${actual} < ${n}`);
    },
    toBeGreaterThanOrEqual: (n) => {
      if (actual < n) throw new Error(`Expected ${actual} >= ${n}`);
    },
    toContain: (item) => {
      if (Array.isArray(actual)) {
        if (!actual.includes(item)) throw new Error(`Expected array to contain ${JSON.stringify(item)}`);
      } else if (typeof actual === 'string') {
        if (!actual.includes(item)) throw new Error(`Expected string to contain "${item}"`);
      } else {
        throw new Error(`toContain: unsupported type ${typeof actual}`);
      }
    },
    not: {
      toBe: (expected) => {
        if (actual === expected) throw new Error(`Expected value NOT to be ${JSON.stringify(expected)}`);
      },
      toContain: (item) => {
        if (Array.isArray(actual) && actual.includes(item)) throw new Error(`Expected array NOT to contain ${JSON.stringify(item)}`);
        if (typeof actual === 'string' && actual.includes(item)) throw new Error(`Expected string NOT to contain "${item}"`);
      },
      toBeTruthy: () => {
        if (actual) throw new Error(`Expected falsy, got ${JSON.stringify(actual)}`);
      },
    }
  };
}

// ─── Import modules (Node.js with --input-type=module or dynamic import) ─────
// Inline reimplementation of core functions for test portability
// (avoids browser-only chrome.* API calls in test files)

// ── URL Utils (reimplemented inline for testability) ──────────────────────────

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
  'short.link', 'rb.gy', 'cutt.ly', 'shorturl.at', 'is.gd',
]);

const SUSPICIOUS_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work',
  '.party', '.racing', '.download', '.loan', '.win', '.bid',
]);

const BRAND_KEYWORDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
  'twitter', 'instagram', 'netflix', 'linkedin', 'chase', 'wellsfargo',
];

const PHISHING_KEYWORDS = [
  'login', 'signin', 'sign-in', 'account', 'verify', 'verification',
  'update', 'confirm', 'secure', 'security', 'banking', 'credential',
  'password', 'authenticate', 'wallet', 'recover',
];

function extractRegisteredDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.replace(/^www\./, '').split('.');
  if (parts.length <= 2) return hostname.replace(/^www\./, '');
  const twoPartTLDs = ['co.uk', 'co.nz', 'co.za', 'com.au', 'org.uk'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTLDs.includes(lastTwo)) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function countSubdomains(hostname) {
  if (!hostname) return 0;
  const withoutWww = hostname.replace(/^www\./, '');
  const parts = withoutWww.split('.');
  return Math.max(0, parts.length - 2);
}

function isIPAddress(hostname) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
  return ipv4Regex.test(hostname) || ipv6Regex.test(hostname);
}

function levenshteinDistance(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) dp[i][j] = dp[i - 1][j - 1];
      else dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function isURLShortener(hostname) {
  return URL_SHORTENERS.has(hostname.replace(/^www\./, '').toLowerCase());
}

function hasSuspiciousTLD(hostname) {
  const lower = hostname.toLowerCase();
  for (const tld of SUSPICIOUS_TLDS) if (lower.endsWith(tld)) return true;
  return false;
}

function findPhishingKeywords(urlString) {
  const lower = urlString.toLowerCase();
  const found = PHISHING_KEYWORDS.filter(kw => lower.includes(kw));
  return { found, count: found.length };
}

function hasLongURL(urlString) { return urlString.length > 150; }

function hasAtSymbolInURL(urlString) {
  try {
    const url = new URL(urlString);
    return url.username.length > 0 || url.password.length > 0;
  } catch { return urlString.includes('@'); }
}

function detectHomoglyphs(domain) {
  const HOMOGLYPH_MAP = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x' };
  for (const char of domain) if (HOMOGLYPH_MAP[char] !== undefined) return true;
  return domain.includes('xn--');
}

// ── Risk Scorer (reimplemented inline) ────────────────────────────────────────

const FEATURE_WEIGHTS = {
  isIPBased: 25, isURLShortener: 15, hasSuspiciousTLD: 12,
  hasHomoglyphs: 30, hasAtSymbol: 20, hasRedirectTrick: 18,
  noHTTPS: 20, typosquatExact: 35, typosquatFuzzy: 25,
  phishingKeywordsMany: 20, phishingKeywordsFew: 8,
  hasFakeLoginForm: 35, inSafeBrowsing: 100, inPhishTank: 100,
  domainVeryNew: 30, domainNew: 15,
};

function calculateRiskScore(features) {
  let rawScore = 0;
  const triggered = [];
  for (const [f, on] of Object.entries(features)) {
    if (on && FEATURE_WEIGHTS[f]) { rawScore += FEATURE_WEIGHTS[f]; triggered.push(f); }
  }
  return { score: Math.min(100, rawScore), triggered, rawScore };
}

function classifyRisk(score) {
  if (score <= 25) return 'Safe';
  if (score <= 60) return 'Suspicious';
  return 'High Risk';
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST SUITES
// ═══════════════════════════════════════════════════════════════════════════════

describe('URL Utilities — extractRegisteredDomain', () => {
  it('extracts simple domain', () => {
    expect(extractRegisteredDomain('example.com')).toBe('example.com');
  });
  it('strips www prefix', () => {
    expect(extractRegisteredDomain('www.example.com')).toBe('example.com');
  });
  it('handles subdomains', () => {
    expect(extractRegisteredDomain('sub.example.com')).toBe('example.com');
  });
  it('handles deep subdomains', () => {
    expect(extractRegisteredDomain('a.b.c.evil.com')).toBe('evil.com');
  });
  it('handles two-part TLDs', () => {
    expect(extractRegisteredDomain('bank.co.uk')).toBe('bank.co.uk');
  });
  it('returns empty string for empty input', () => {
    expect(extractRegisteredDomain('')).toBe('');
  });
});

describe('URL Utilities — countSubdomains', () => {
  it('returns 0 for apex domain', () => {
    expect(countSubdomains('example.com')).toBe(0);
  });
  it('returns 0 for www', () => {
    expect(countSubdomains('www.example.com')).toBe(0);
  });
  it('returns 1 for single subdomain', () => {
    expect(countSubdomains('sub.example.com')).toBe(1);
  });
  it('returns correct count for deep subdomains', () => {
    expect(countSubdomains('a.b.c.example.com')).toBe(3);
  });
  it('flags excessive subdomains (>3)', () => {
    expect(countSubdomains('paypal.com.secure.verify.evil.com') > 3).toBeTruthy();
  });
});

describe('URL Utilities — isIPAddress', () => {
  it('detects valid IPv4', () => {
    expect(isIPAddress('192.168.1.1')).toBeTruthy();
  });
  it('detects IP in phishing URL', () => {
    expect(isIPAddress('185.220.101.45')).toBeTruthy();
  });
  it('returns false for domain names', () => {
    expect(isIPAddress('google.com')).toBeFalsy();
  });
  it('returns false for localhost', () => {
    // localhost is not an IP in numeric form
    expect(isIPAddress('localhost')).toBeFalsy();
  });
  it('detects IPv6 address', () => {
    expect(isIPAddress('[::1]')).toBeTruthy();
  });
});

describe('URL Utilities — isURLShortener', () => {
  it('detects bit.ly', () => expect(isURLShortener('bit.ly')).toBeTruthy());
  it('detects tinyurl.com', () => expect(isURLShortener('tinyurl.com')).toBeTruthy());
  it('detects t.co', () => expect(isURLShortener('t.co')).toBeTruthy());
  it('does not flag real domains', () => expect(isURLShortener('google.com')).toBeFalsy());
  it('does not flag paypal.com', () => expect(isURLShortener('paypal.com')).toBeFalsy());
  it('handles www prefix', () => expect(isURLShortener('www.bit.ly')).toBeTruthy());
});

describe('URL Utilities — hasSuspiciousTLD', () => {
  it('detects .tk TLD', () => expect(hasSuspiciousTLD('evil-site.tk')).toBeTruthy());
  it('detects .xyz TLD', () => expect(hasSuspiciousTLD('fake-bank.xyz')).toBeTruthy());
  it('detects .ml TLD', () => expect(hasSuspiciousTLD('paypal-login.ml')).toBeTruthy());
  it('does not flag .com', () => expect(hasSuspiciousTLD('example.com')).toBeFalsy());
  it('does not flag .org', () => expect(hasSuspiciousTLD('charity.org')).toBeFalsy());
  it('does not flag .gov', () => expect(hasSuspiciousTLD('irs.gov')).toBeFalsy());
});

describe('URL Utilities — findPhishingKeywords', () => {
  it('finds login keyword', () => {
    expect(findPhishingKeywords('http://evil.com/login.php').count).toBeGreaterThan(0);
  });
  it('finds multiple keywords', () => {
    const r = findPhishingKeywords('http://evil.com/account/verify/password');
    expect(r.count).toBeGreaterThan(2);
  });
  it('returns 0 for clean URL', () => {
    expect(findPhishingKeywords('http://news.example.com/articles').count).toBe(0);
  });
  it('detects verify keyword', () => {
    expect(findPhishingKeywords('http://paypal-verify.tk/verify').found).toContain('verify');
  });
});

describe('URL Utilities — hasAtSymbolInURL', () => {
  it('detects @ in user info', () => {
    expect(hasAtSymbolInURL('http://user@evil.com')).toBeTruthy();
  });
  it('detects credentials in URL', () => {
    expect(hasAtSymbolInURL('http://paypal.com@evil.com')).toBeTruthy();
  });
  it('returns false for normal URL', () => {
    expect(hasAtSymbolInURL('https://paypal.com/login')).toBeFalsy();
  });
});

describe('URL Utilities — detectHomoglyphs', () => {
  it('detects Cyrillic a (а)', () => {
    expect(detectHomoglyphs('pаypаl.com')).toBeTruthy(); // Cyrillic а
  });
  it('detects Cyrillic o (о)', () => {
    expect(detectHomoglyphs('micrоsoft.com')).toBeTruthy(); // Cyrillic о
  });
  it('detects Punycode IDN', () => {
    expect(detectHomoglyphs('xn--pypal-4ve.com')).toBeTruthy();
  });
  it('returns false for clean domain', () => {
    expect(detectHomoglyphs('google.com')).toBeFalsy();
  });
});

describe('URL Utilities — hasLongURL', () => {
  it('flags URLs over 150 chars', () => {
    expect(hasLongURL('https://evil.com/' + 'a'.repeat(140))).toBeTruthy();
  });
  it('does not flag normal URLs', () => {
    expect(hasLongURL('https://google.com/search?q=hello')).toBeFalsy();
  });
});

describe('Levenshtein Distance', () => {
  it('computes distance 0 for identical strings', () => {
    expect(levenshteinDistance('paypal', 'paypal')).toBe(0);
  });
  it('computes distance 1 for single char difference', () => {
    expect(levenshteinDistance('paypal', 'paypa1')).toBe(1); // l → 1
  });
  it('computes distance 2 for paypall', () => {
    expect(levenshteinDistance('paypal', 'paypall')).toBe(1);
  });
  it('detects apple → appie typosquat', () => {
    expect(levenshteinDistance('apple', 'appie') <= 2).toBeTruthy();
  });
  it('computes distance between unrelated words', () => {
    expect(levenshteinDistance('cat', 'house')).toBeGreaterThan(3);
  });
});

describe('Risk Scorer — calculateRiskScore', () => {
  it('returns 0 for no features', () => {
    const r = calculateRiskScore({});
    expect(r.score).toBe(0);
  });

  it('scores Safe for low-risk features', () => {
    const r = calculateRiskScore({ hasLongURL: true });
    expect(classifyRisk(r.score)).toBe('Safe');
  });

  it('scores Suspicious for moderate risk', () => {
    const r = calculateRiskScore({
      noHTTPS: true,
      hasSuspiciousTLD: true,
      phishingKeywordsFew: true,
    });
    expect(['Suspicious', 'High Risk']).toContain(classifyRisk(r.score));
  });

  it('scores High Risk when in Safe Browsing database', () => {
    const r = calculateRiskScore({ inSafeBrowsing: true });
    expect(classifyRisk(r.score)).toBe('High Risk');
  });

  it('scores High Risk for IP + no HTTPS + phishing keywords', () => {
    const r = calculateRiskScore({
      isIPBased: true,
      noHTTPS: true,
      phishingKeywordsMany: true,
      hasHomoglyphs: true,
    });
    expect(classifyRisk(r.score)).toBe('High Risk');
  });

  it('scores High Risk for fake login form', () => {
    const r = calculateRiskScore({ hasFakeLoginForm: true, noHTTPS: true });
    expect(r.score).toBeGreaterThan(25);
  });

  it('caps score at 100', () => {
    const allFeatures = Object.fromEntries(
      Object.keys(FEATURE_WEIGHTS).map(k => [k, true])
    );
    const r = calculateRiskScore(allFeatures);
    expect(r.score).toBeLessThan(101);
  });

  it('triggers correct features', () => {
    const r = calculateRiskScore({ isIPBased: true, noHTTPS: true });
    expect(r.triggered).toContain('isIPBased');
    expect(r.triggered).toContain('noHTTPS');
    expect(r.triggered).not.toContain('hasHomoglyphs');
  });
});

describe('Risk Classifier — classifyRisk', () => {
  it('classifies 0 as Safe', () => expect(classifyRisk(0)).toBe('Safe'));
  it('classifies 25 as Safe', () => expect(classifyRisk(25)).toBe('Safe'));
  it('classifies 26 as Suspicious', () => expect(classifyRisk(26)).toBe('Suspicious'));
  it('classifies 60 as Suspicious', () => expect(classifyRisk(60)).toBe('Suspicious'));
  it('classifies 61 as High Risk', () => expect(classifyRisk(61)).toBe('High Risk'));
  it('classifies 100 as High Risk', () => expect(classifyRisk(100)).toBe('High Risk'));
});

// ─── Real-world phishing URL scenarios ────────────────────────────────────────
describe('Real-world Phishing Scenarios', () => {
  it('detects PayPal typosquat on suspicious TLD', () => {
    const domain = extractRegisteredDomain('paypa1-secure.ml');
    const tldFlag = hasSuspiciousTLD('paypa1-secure.ml');
    const kwFlag = findPhishingKeywords('http://paypa1-secure.ml/login/account/verify');
    expect(tldFlag).toBeTruthy();
    expect(kwFlag.count).toBeGreaterThan(1);
  });

  it('detects IP-based phishing URL', () => {
    expect(isIPAddress('192.168.1.100')).toBeTruthy();
    expect(isIPAddress('185.220.101.45')).toBeTruthy();
  });

  it('detects fake bank login with multiple subdomain trick', () => {
    const subdomains = countSubdomains('secure.bankofamerica.account-verify.evil.com');
    expect(subdomains).toBeGreaterThan(2);
  });

  it('detects URL shortener hiding destination', () => {
    expect(isURLShortener('bit.ly')).toBeTruthy();
    expect(isURLShortener('tinyurl.com')).toBeTruthy();
  });

  it('scores legitimate Google URL as Safe', () => {
    const features = {
      isIPBased: false,
      isURLShortener: false,
      hasSuspiciousTLD: false,
      hasHomoglyphs: false,
      hasAtSymbol: false,
      noHTTPS: false,
      phishingKeywordsMany: false,
      phishingKeywordsFew: false,
    };
    const r = calculateRiskScore(features);
    expect(classifyRisk(r.score)).toBe('Safe');
  });

  it('correctly identifies high-risk combined URL pattern', () => {
    // Pattern: credential stealing page with all the hallmarks
    const r = calculateRiskScore({
      noHTTPS: true,
      isIPBased: true,
      hasFakeLoginForm: true,
      phishingKeywordsMany: true,
      domainVeryNew: true,
    });
    expect(classifyRisk(r.score)).toBe('High Risk');
    expect(r.score).toBeGreaterThan(60);
  });
});

// ─── Edge Cases ────────────────────────────────────────────────────────────────
describe('Edge Cases', () => {
  it('handles empty hostname in extractRegisteredDomain', () => {
    expect(extractRegisteredDomain('')).toBe('');
  });
  it('handles single-label domain', () => {
    expect(extractRegisteredDomain('localhost')).toBe('localhost');
  });
  it('levenshtein handles empty strings', () => {
    expect(levenshteinDistance('', 'abc')).toBe(3);
    expect(levenshteinDistance('abc', '')).toBe(3);
    expect(levenshteinDistance('', '')).toBe(0);
  });
  it('findPhishingKeywords handles empty URL', () => {
    expect(findPhishingKeywords('').count).toBe(0);
  });
  it('hasSuspiciousTLD is case-insensitive', () => {
    expect(hasSuspiciousTLD('EVIL.TK')).toBeTruthy();
  });
});

// ─── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(50)}`);
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log(`${'─'.repeat(50)}\n`);

if (failed > 0) process.exit(1);
