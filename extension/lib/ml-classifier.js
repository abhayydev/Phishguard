/**
 * ml-classifier.js
 * Machine-learning inspired phishing risk scoring engine for PhishGuard.
 *
 * Uses a weighted feature extraction approach that mimics ML classification
 * without requiring a runtime model. Features are extracted from URL structure,
 * content signals, and threat intelligence results, then combined into a
 * calibrated risk score (0–100) with a classification label.
 */

'use strict';

import { analyzeURLStructure } from './url-utils.js';

// ─── Risk Score Thresholds ───────────────────────────────────────────────────
export const RISK_THRESHOLDS = {
  SAFE: 25,        // 0–25: Safe
  SUSPICIOUS: 60,  // 26–60: Suspicious
  HIGH_RISK: 100   // 61–100: High Risk
};

// ─── Feature Weights (calibrated for low false-positive rate) ─────────────────
const FEATURE_WEIGHTS = {
  // URL structure signals
  isIPBased: 25,
  isURLShortener: 15,
  hasSuspiciousTLD: 12,
  hasHomoglyphs: 30,
  hasAtSymbol: 20,
  hasRedirectTrick: 18,
  hasEncodedIP: 25,
  hasLongURL: 5,
  hasExcessiveSpecialChars: 8,
  excessiveSubdomains: 15,
  noHTTPS: 20,
  typosquatExact: 35,       // Brand in subdomain
  typosquatFuzzy: 25,       // Levenshtein 1–2
  phishingKeywordsMany: 20, // 3+ keywords
  phishingKeywordsFew: 8,   // 1–2 keywords

  // Content analysis signals (from content script)
  hasFakeLoginForm: 35,
  hasPasswordField: 5,
  hasHiddenIframes: 15,
  hasObfuscatedJS: 20,
  hasCredentialHarvesting: 40,
  titleMismatch: 15,
  noFavicon: 5,

  // Threat intelligence signals
  inSafeBrowsing: 100,
  inPhishTank: 100,
  domainVeryNew: 30,        // < 7 days old
  domainNew: 15,            // < 30 days old
  manyRedirects: 10,
  mixedContent: 10,
  invalidSSL: 25,
  selfSignedSSL: 15,
};

/**
 * Extract numeric features from various analysis inputs.
 * Returns a map of feature names to boolean/numeric values.
 *
 * @param {object} params
 * @param {string} params.url - The URL being analyzed
 * @param {object} [params.urlAnalysis] - Pre-computed URL analysis
 * @param {object} [params.contentSignals] - Signals from content script
 * @param {object} [params.threatIntel] - Results from threat intelligence APIs
 * @param {object} [params.sslInfo] - SSL certificate information
 * @param {number} [params.domainAgeDays] - Domain age in days (-1 if unknown)
 * @param {number} [params.redirectCount] - Number of redirects observed
 * @returns {object} Feature map
 */
export function extractFeatures({
  url,
  urlAnalysis,
  contentSignals = {},
  threatIntel = {},
  sslInfo = {},
  domainAgeDays = -1,
  redirectCount = 0,
}) {
  // Use provided URL analysis or compute fresh
  const ua = urlAnalysis || analyzeURLStructure(url);

  const features = {};

  // ── URL Structure Features ──────────────────────────────────────────────
  features.isIPBased = ua.isIPBased === true;
  features.isURLShortener = ua.isURLShortener === true;
  features.hasSuspiciousTLD = ua.hasSuspiciousTLD === true;
  features.hasHomoglyphs = ua.hasHomoglyphs === true;
  features.hasAtSymbol = ua.hasAtSymbol === true;
  features.hasRedirectTrick = ua.hasRedirectTrick === true;
  features.hasEncodedIP = ua.hasEncodedIP === true;
  features.hasLongURL = ua.hasLongURL === true;
  features.hasExcessiveSpecialChars = ua.hasExcessiveSpecialChars === true;
  features.excessiveSubdomains = ua.excessiveSubdomains === true;
  features.noHTTPS = ua.isHTTPS === false;

  // Typosquatting features
  const typosquats = ua.typosquatMatches || [];
  features.typosquatExact = typosquats.some(m => m.type === 'brand-in-subdomain');
  features.typosquatFuzzy = typosquats.some(m => m.type === 'typosquatting');

  // Phishing keyword features
  const kwCount = (ua.phishingKeywords || {}).count || 0;
  features.phishingKeywordsMany = kwCount >= 3;
  features.phishingKeywordsFew = kwCount >= 1 && kwCount < 3;

  // ── Content Analysis Features ───────────────────────────────────────────
  features.hasFakeLoginForm = contentSignals.hasFakeLoginForm === true;
  features.hasPasswordField = contentSignals.hasPasswordField === true;
  features.hasHiddenIframes = contentSignals.hasHiddenIframes === true;
  features.hasObfuscatedJS = contentSignals.hasObfuscatedJS === true;
  features.hasCredentialHarvesting = contentSignals.hasCredentialHarvesting === true;
  features.titleMismatch = contentSignals.titleMismatch === true;
  features.noFavicon = contentSignals.noFavicon === true;

  // ── Threat Intelligence Features ────────────────────────────────────────
  features.inSafeBrowsing = threatIntel.safeBrowsing?.threat === true;
  features.inPhishTank = threatIntel.phishTank?.inDatabase === true;
  features.mixedContent = contentSignals.hasMixedContent === true;

  // ── SSL Features ─────────────────────────────────────────────────────────
  features.invalidSSL = sslInfo.valid === false && ua.isHTTPS;
  features.selfSignedSSL = sslInfo.selfSigned === true;

  // ── Domain Age Features ──────────────────────────────────────────────────
  if (domainAgeDays >= 0) {
    features.domainVeryNew = domainAgeDays < 7;
    features.domainNew = domainAgeDays >= 7 && domainAgeDays < 30;
  } else {
    features.domainVeryNew = false;
    features.domainNew = false;
  }

  // ── Redirect Features ────────────────────────────────────────────────────
  features.manyRedirects = redirectCount >= 3;

  return features;
}

/**
 * Calculate a risk score (0–100) from extracted features.
 * @param {object} features - Output of extractFeatures()
 * @returns {{ score: number, triggeredFeatures: string[] }}
 */
export function calculateRiskScore(features) {
  let rawScore = 0;
  const triggeredFeatures = [];

  for (const [feature, isTriggered] of Object.entries(features)) {
    if (isTriggered && FEATURE_WEIGHTS[feature] !== undefined) {
      rawScore += FEATURE_WEIGHTS[feature];
      triggeredFeatures.push(feature);
    }
  }

  // Weights are calibrated so common phishing patterns sum to 60–100 directly.
  // Cap at 100 — each weight represents its direct contribution to the score.
  const normalizedScore = Math.min(100, rawScore);

  return { score: normalizedScore, triggeredFeatures, rawScore };
}

/**
 * Classify a risk score into a human-readable label.
 * @param {number} score
 * @returns {'Safe'|'Suspicious'|'High Risk'}
 */
export function classifyRisk(score) {
  if (score <= RISK_THRESHOLDS.SAFE) return 'Safe';
  if (score <= RISK_THRESHOLDS.SUSPICIOUS) return 'Suspicious';
  return 'High Risk';
}

/**
 * Generate human-readable security findings from triggered features.
 * @param {string[]} triggeredFeatures
 * @param {object} urlAnalysis
 * @returns {string[]}
 */
export function generateFindings(triggeredFeatures, urlAnalysis = {}) {
  const findings = [];

  const FINDING_MESSAGES = {
    isIPBased: 'URL uses a raw IP address instead of a domain name',
    isURLShortener: 'URL uses a shortener service, hiding the real destination',
    hasSuspiciousTLD: `Domain uses a suspicious top-level domain (.tk, .ml, .xyz, etc.)`,
    hasHomoglyphs: 'Domain contains lookalike characters (homoglyph attack)',
    hasAtSymbol: 'URL contains "@" symbol, which may redirect to a different host',
    hasRedirectTrick: 'URL contains a redirect parameter pointing to another site',
    hasEncodedIP: 'URL contains an encoded IP address (obfuscation technique)',
    hasLongURL: 'URL is unusually long — a common obfuscation technique',
    hasExcessiveSpecialChars: 'URL contains excessive special characters',
    excessiveSubdomains: 'Domain has an unusual number of subdomains',
    noHTTPS: 'Connection is not encrypted (HTTP instead of HTTPS)',
    typosquatExact: `Domain impersonates a known brand in its subdomain`,
    typosquatFuzzy: `Domain name closely resembles a known brand (typosquatting)`,
    phishingKeywordsMany: 'URL contains multiple phishing-related keywords',
    phishingKeywordsFew: 'URL contains phishing-related keywords',
    hasFakeLoginForm: 'Page contains a login form on an untrusted domain',
    hasPasswordField: 'Page requests password/credential input',
    hasHiddenIframes: 'Page contains hidden iframes (content injection risk)',
    hasObfuscatedJS: 'Page contains obfuscated JavaScript (potential malware)',
    hasCredentialHarvesting: 'Page shows signs of credential harvesting behavior',
    titleMismatch: 'Page title does not match the domain (brand impersonation)',
    noFavicon: 'Page has no favicon (common with hastily-built phishing pages)',
    inSafeBrowsing: '⚠️ URL is flagged by Google Safe Browsing',
    inPhishTank: '⚠️ URL is listed in the PhishTank phishing database',
    mixedContent: 'Page loads insecure resources over HTTP on an HTTPS page',
    invalidSSL: 'SSL/TLS certificate is invalid or expired',
    selfSignedSSL: 'SSL certificate is self-signed (not from a trusted authority)',
    domainVeryNew: 'Domain was registered very recently (less than 7 days ago)',
    domainNew: 'Domain was registered recently (less than 30 days ago)',
    manyRedirects: 'URL involves multiple redirects before reaching the final page',
  };

  for (const feature of triggeredFeatures) {
    if (FINDING_MESSAGES[feature]) {
      findings.push(FINDING_MESSAGES[feature]);
    }
  }

  // Add specific typosquat detail
  if (triggeredFeatures.includes('typosquatFuzzy') && urlAnalysis.typosquatMatches?.length) {
    const brands = urlAnalysis.typosquatMatches
      .filter(m => m.type === 'typosquatting')
      .map(m => m.brand)
      .join(', ');
    if (brands) {
      findings.push(`Domain closely resembles: ${brands}`);
    }
  }

  return findings;
}

/**
 * Full ML-inspired phishing analysis pipeline.
 * Orchestrates feature extraction, scoring, and classification.
 *
 * @param {object} params - Same as extractFeatures params
 * @returns {{
 *   score: number,
 *   classification: 'Safe'|'Suspicious'|'High Risk',
 *   findings: string[],
 *   features: object,
 *   triggeredFeatures: string[],
 *   urlAnalysis: object,
 * }}
 */
export function analyzePhishingRisk(params) {
  const urlAnalysis = params.urlAnalysis || analyzeURLStructure(params.url);
  const features = extractFeatures({ ...params, urlAnalysis });
  const { score, triggeredFeatures, rawScore } = calculateRiskScore(features);
  const classification = classifyRisk(score);
  const findings = generateFindings(triggeredFeatures, urlAnalysis);

  return {
    score,
    rawScore,
    classification,
    findings,
    features,
    triggeredFeatures,
    urlAnalysis,
    timestamp: Date.now(),
  };
}
