/**
 * ml-classifier.test.js
 * Unit tests for the ML-inspired phishing risk classifier.
 *
 * Run with: node tests/ml-classifier.test.js
 */

'use strict';

let passed = 0, failed = 0;

function describe(name, fn) { console.log(`\n  📦 ${name}`); fn(); }

function it(name, fn) {
  try { fn(); console.log(`    ✓ ${name}`); passed++; }
  catch (err) { console.error(`    ✗ ${name}\n      → ${err.message}`); failed++; }
}

function expect(actual) {
  return {
    toBe: (e) => { if (actual !== e) throw new Error(`Expected ${JSON.stringify(e)}, got ${JSON.stringify(actual)}`); },
    toBeTruthy: () => { if (!actual) throw new Error(`Expected truthy, got ${JSON.stringify(actual)}`); },
    toBeFalsy: () => { if (actual) throw new Error(`Expected falsy, got ${JSON.stringify(actual)}`); },
    toBeGreaterThan: (n) => { if (actual <= n) throw new Error(`Expected ${actual} > ${n}`); },
    toBeLessThanOrEqual: (n) => { if (actual > n) throw new Error(`Expected ${actual} <= ${n}`); },
    toEqual: (e) => { if (JSON.stringify(actual) !== JSON.stringify(e)) throw new Error(`Expected ${JSON.stringify(e)}, got ${JSON.stringify(actual)}`); },
    toContain: (item) => {
      if (Array.isArray(actual) && !actual.includes(item)) throw new Error(`Expected array to contain ${JSON.stringify(item)}`);
      if (typeof actual === 'string' && !actual.includes(item)) throw new Error(`Expected string to contain "${item}"`);
    },
  };
}

// ── Inline classifier (mirrors ml-classifier.js) ──────────────────────────────

const RISK_THRESHOLDS = { SAFE: 25, SUSPICIOUS: 60, HIGH_RISK: 100 };

const FEATURE_WEIGHTS = {
  isIPBased: 25, isURLShortener: 15, hasSuspiciousTLD: 12,
  hasHomoglyphs: 30, hasAtSymbol: 20, hasRedirectTrick: 18,
  hasEncodedIP: 25, hasLongURL: 5, hasExcessiveSpecialChars: 8,
  excessiveSubdomains: 15, noHTTPS: 20,
  typosquatExact: 35, typosquatFuzzy: 25,
  phishingKeywordsMany: 20, phishingKeywordsFew: 8,
  hasFakeLoginForm: 35, hasPasswordField: 5, hasHiddenIframes: 15,
  hasObfuscatedJS: 20, hasCredentialHarvesting: 40,
  titleMismatch: 15, noFavicon: 5,
  inSafeBrowsing: 100, inPhishTank: 100,
  domainVeryNew: 30, domainNew: 15, manyRedirects: 10,
  mixedContent: 10, invalidSSL: 25, selfSignedSSL: 15,
};

function calculateRiskScore(features) {
  let rawScore = 0;
  const triggeredFeatures = [];
  for (const [feature, isTriggered] of Object.entries(features)) {
    if (isTriggered && FEATURE_WEIGHTS[feature] !== undefined) {
      rawScore += FEATURE_WEIGHTS[feature];
      triggeredFeatures.push(feature);
    }
  }
  const score = Math.min(100, rawScore);
  return { score, triggeredFeatures, rawScore };
}

function classifyRisk(score) {
  if (score <= RISK_THRESHOLDS.SAFE) return 'Safe';
  if (score <= RISK_THRESHOLDS.SUSPICIOUS) return 'Suspicious';
  return 'High Risk';
}

const FINDING_MESSAGES = {
  isIPBased: 'URL uses a raw IP address instead of a domain name',
  noHTTPS: 'Connection is not encrypted (HTTP instead of HTTPS)',
  hasFakeLoginForm: 'Page contains a login form on an untrusted domain',
  inSafeBrowsing: '⚠️ URL is flagged by Google Safe Browsing',
  inPhishTank: '⚠️ URL is listed in the PhishTank phishing database',
  domainVeryNew: 'Domain was registered very recently (less than 7 days ago)',
};

function generateFindings(triggeredFeatures) {
  return triggeredFeatures
    .filter(f => FINDING_MESSAGES[f])
    .map(f => FINDING_MESSAGES[f]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('calculateRiskScore — basic scoring', () => {
  it('returns score 0 with no features', () => {
    expect(calculateRiskScore({}).score).toBe(0);
  });

  it('returns positive score for triggered features', () => {
    const r = calculateRiskScore({ isIPBased: true });
    expect(r.score).toBeGreaterThan(0);
  });

  it('includes triggered feature in list', () => {
    const r = calculateRiskScore({ isIPBased: true, noHTTPS: true });
    expect(r.triggeredFeatures).toContain('isIPBased');
    expect(r.triggeredFeatures).toContain('noHTTPS');
  });

  it('ignores false features', () => {
    const r = calculateRiskScore({ isIPBased: false, noHTTPS: false });
    expect(r.score).toBe(0);
    expect(r.triggeredFeatures.length).toBe(0);
  });

  it('caps score at 100', () => {
    const allOn = Object.fromEntries(Object.keys(FEATURE_WEIGHTS).map(k => [k, true]));
    expect(calculateRiskScore(allOn).score).toBeLessThanOrEqual(100);
  });

  it('ignores unknown feature keys', () => {
    const r = calculateRiskScore({ unknownFeature: true, anotherFake: true });
    expect(r.score).toBe(0);
  });
});

describe('calculateRiskScore — threat intelligence signals (hardcoded 100)', () => {
  it('Safe Browsing hit scores very high', () => {
    expect(calculateRiskScore({ inSafeBrowsing: true }).score).toBeGreaterThan(60);
  });

  it('PhishTank hit scores very high', () => {
    expect(calculateRiskScore({ inPhishTank: true }).score).toBeGreaterThan(60);
  });

  it('Safe Browsing + PhishTank = Max Risk', () => {
    const r = calculateRiskScore({ inSafeBrowsing: true, inPhishTank: true });
    expect(r.score).toBeLessThanOrEqual(100);
    expect(classifyRisk(r.score)).toBe('High Risk');
  });
});

describe('calculateRiskScore — content signal weights', () => {
  it('credential harvesting carries highest content weight', () => {
    const r1 = calculateRiskScore({ hasCredentialHarvesting: true });
    const r2 = calculateRiskScore({ hasFakeLoginForm: true });
    expect(r1.rawScore).toBeGreaterThan(r2.rawScore);
  });

  it('fake login form is significant', () => {
    const r = calculateRiskScore({ hasFakeLoginForm: true });
    expect(r.score).toBeGreaterThan(0);
  });

  it('hidden iframes contribute to score', () => {
    const withIframes = calculateRiskScore({ hasHiddenIframes: true });
    const without = calculateRiskScore({});
    expect(withIframes.score).toBeGreaterThan(without.score);
  });
});

describe('classifyRisk — boundary values', () => {
  it('score 0 → Safe', () => expect(classifyRisk(0)).toBe('Safe'));
  it('score 25 → Safe', () => expect(classifyRisk(25)).toBe('Safe'));
  it('score 26 → Suspicious', () => expect(classifyRisk(26)).toBe('Suspicious'));
  it('score 60 → Suspicious', () => expect(classifyRisk(60)).toBe('Suspicious'));
  it('score 61 → High Risk', () => expect(classifyRisk(61)).toBe('High Risk'));
  it('score 100 → High Risk', () => expect(classifyRisk(100)).toBe('High Risk'));
});

describe('generateFindings — human-readable output', () => {
  it('generates finding for IP-based URL', () => {
    const findings = generateFindings(['isIPBased']);
    expect(findings).toContain('URL uses a raw IP address instead of a domain name');
  });

  it('generates finding for no HTTPS', () => {
    const findings = generateFindings(['noHTTPS']);
    expect(findings).toContain('Connection is not encrypted (HTTP instead of HTTPS)');
  });

  it('generates finding for Safe Browsing hit', () => {
    const findings = generateFindings(['inSafeBrowsing']);
    expect(findings).toContain('⚠️ URL is flagged by Google Safe Browsing');
  });

  it('returns empty array for no triggered features', () => {
    expect(generateFindings([]).length).toBe(0);
  });

  it('ignores features without messages', () => {
    const findings = generateFindings(['unknownFeature', 'isIPBased']);
    expect(findings.length).toBe(1);
  });
});

describe('Feature weight ordering — sanity checks', () => {
  it('threat intel > URL structure signals', () => {
    expect(FEATURE_WEIGHTS.inSafeBrowsing).toBeGreaterThan(FEATURE_WEIGHTS.isIPBased);
  });
  it('homoglyph > suspicious TLD', () => {
    expect(FEATURE_WEIGHTS.hasHomoglyphs).toBeGreaterThan(FEATURE_WEIGHTS.hasSuspiciousTLD);
  });
  it('credential harvesting > fake login form', () => {
    expect(FEATURE_WEIGHTS.hasCredentialHarvesting).toBeGreaterThan(FEATURE_WEIGHTS.hasFakeLoginForm);
  });
  it('very new domain > recently new domain', () => {
    expect(FEATURE_WEIGHTS.domainVeryNew).toBeGreaterThan(FEATURE_WEIGHTS.domainNew);
  });
});

describe('Realistic phishing pattern tests', () => {
  it('Pattern: bank phishing page (all hallmarks)', () => {
    const r = calculateRiskScore({
      noHTTPS: true,
      hasFakeLoginForm: true,
      hasCredentialHarvesting: true,
      typosquatFuzzy: true,
      domainNew: true,
    });
    expect(classifyRisk(r.score)).toBe('High Risk');
  });

  it('Pattern: mild suspicious page (1-2 flags)', () => {
    const r = calculateRiskScore({
      noHTTPS: true,
      phishingKeywordsFew: true,
    });
    const cls = classifyRisk(r.score);
    expect(['Suspicious', 'High Risk']).toContain(cls);
  });

  it('Pattern: legitimate HTTPS page, no flags', () => {
    const r = calculateRiskScore({
      isIPBased: false, noHTTPS: false, hasHomoglyphs: false,
      hasSuspiciousTLD: false, inSafeBrowsing: false,
    });
    expect(classifyRisk(r.score)).toBe('Safe');
  });

  it('Pattern: newly registered domain with login form', () => {
    const r = calculateRiskScore({ domainVeryNew: true, hasFakeLoginForm: true });
    expect(r.score).toBeGreaterThan(RISK_THRESHOLDS.SAFE);
  });
});

// ─── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(50)}`);
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log(`${'─'.repeat(50)}\n`);
if (failed > 0) process.exit(1);
