/**
 * storage-manager.js
 * Abstraction layer over chrome.storage for PhishGuard.
 *
 * Manages:
 * - Per-URL analysis result caching (with TTL)
 * - Browsing security history
 * - User settings/preferences
 * - Phishing report submissions
 * - Extension statistics
 */

'use strict';

// ─── Storage Keys ────────────────────────────────────────────────────────────
const KEYS = {
  SETTINGS: 'phishguard_settings',
  HISTORY: 'phishguard_history',
  CACHE: 'phishguard_cache',
  REPORTS: 'phishguard_reports',
  STATS: 'phishguard_stats',
  ALLOWLIST: 'phishguard_allowlist',
};

// ─── Cache TTL (milliseconds) ─────────────────────────────────────────────────
const CACHE_TTL = {
  SAFE: 24 * 60 * 60 * 1000,        // 24 hours for safe sites
  SUSPICIOUS: 6 * 60 * 60 * 1000,   // 6 hours for suspicious
  HIGH_RISK: 1 * 60 * 60 * 1000,    // 1 hour for high-risk (re-check frequently)
  DEFAULT: 12 * 60 * 60 * 1000,     // 12 hours default
};

// ─── Default Settings ─────────────────────────────────────────────────────────
export const DEFAULT_SETTINGS = {
  protectionEnabled: true,
  showWarningPage: true,
  blockHighRisk: true,
  blockSuspicious: false,
  useSafeBrowsing: true,
  usePhishTank: true,
  useWhois: true,
  showNotifications: true,
  darkMode: true,
  historyRetentionDays: 30,
  maxHistoryItems: 1000,
  backendURL: '', // User configures their own Vercel backend URL
  safeBrowsingAPIKey: '',
  phishTankAPIKey: '',
  aiExplanationsEnabled: false,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Wrap chrome.storage.local.get in a Promise.
 * @param {string|string[]} keys
 * @returns {Promise<object>}
 */
function storageGet(keys) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(keys, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(result);
      }
    });
  });
}

/**
 * Wrap chrome.storage.local.set in a Promise.
 * @param {object} items
 * @returns {Promise<void>}
 */
function storageSet(items) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(items, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}

// ─── Settings ─────────────────────────────────────────────────────────────────

/**
 * Get current user settings, merged with defaults.
 * @returns {Promise<object>}
 */
export async function getSettings() {
  const result = await storageGet(KEYS.SETTINGS);
  return { ...DEFAULT_SETTINGS, ...(result[KEYS.SETTINGS] || {}) };
}

/**
 * Save (partial) settings update.
 * @param {object} updates
 * @returns {Promise<void>}
 */
export async function saveSettings(updates) {
  const current = await getSettings();
  const merged = { ...current, ...updates };
  await storageSet({ [KEYS.SETTINGS]: merged });
}

// ─── Analysis Cache ───────────────────────────────────────────────────────────

/**
 * Build a cache key from a URL (uses registered domain + path prefix).
 * @param {string} url
 * @returns {string}
 */
function buildCacheKey(url) {
  try {
    const u = new URL(url);
    // Cache at domain level for efficiency; strip query/fragment
    return `${u.protocol}//${u.hostname}${u.pathname.substring(0, 50)}`;
  } catch {
    return url.substring(0, 100);
  }
}

/**
 * Get a cached analysis result, returning null if expired or not found.
 * @param {string} url
 * @returns {Promise<object|null>}
 */
export async function getCachedAnalysis(url) {
  const cacheKey = buildCacheKey(url);
  const result = await storageGet(KEYS.CACHE);
  const cache = result[KEYS.CACHE] || {};
  const entry = cache[cacheKey];

  if (!entry) return null;

  const ttl = CACHE_TTL[entry.classification?.toUpperCase().replace(' ', '_')] || CACHE_TTL.DEFAULT;
  if (Date.now() - entry.cachedAt > ttl) {
    // Expired — delete it
    delete cache[cacheKey];
    await storageSet({ [KEYS.CACHE]: cache });
    return null;
  }

  return entry;
}

/**
 * Cache an analysis result.
 * @param {string} url
 * @param {object} analysis
 * @returns {Promise<void>}
 */
export async function cacheAnalysis(url, analysis) {
  const cacheKey = buildCacheKey(url);
  const result = await storageGet(KEYS.CACHE);
  const cache = result[KEYS.CACHE] || {};

  // Evict oldest entries if cache exceeds 500 entries
  const entries = Object.entries(cache);
  if (entries.length >= 500) {
    entries.sort((a, b) => a[1].cachedAt - b[1].cachedAt);
    const toDelete = entries.slice(0, 50).map(([k]) => k);
    toDelete.forEach(k => delete cache[k]);
  }

  cache[cacheKey] = { ...analysis, cachedAt: Date.now() };
  await storageSet({ [KEYS.CACHE]: cache });
}

/**
 * Clear the entire analysis cache.
 * @returns {Promise<void>}
 */
export async function clearCache() {
  await storageSet({ [KEYS.CACHE]: {} });
}

// ─── Browsing History ─────────────────────────────────────────────────────────

/**
 * Add a URL analysis result to the security history.
 * @param {string} url
 * @param {object} analysis
 * @param {string} pageTitle
 * @returns {Promise<void>}
 */
export async function addToHistory(url, analysis, pageTitle = '') {
  const settings = await getSettings();
  const result = await storageGet(KEYS.HISTORY);
  let history = result[KEYS.HISTORY] || [];

  // Prepend new entry
  history.unshift({
    url,
    pageTitle: pageTitle.substring(0, 100),
    score: analysis.score,
    classification: analysis.classification,
    timestamp: Date.now(),
    findings: (analysis.findings || []).slice(0, 5), // Store top 5 findings
  });

  // Enforce retention
  const cutoff = Date.now() - settings.historyRetentionDays * 24 * 60 * 60 * 1000;
  history = history
    .filter(h => h.timestamp > cutoff)
    .slice(0, settings.maxHistoryItems);

  await storageSet({ [KEYS.HISTORY]: history });
}

/**
 * Get browsing security history.
 * @param {{ limit?: number, classification?: string }} options
 * @returns {Promise<object[]>}
 */
export async function getHistory(options = {}) {
  const result = await storageGet(KEYS.HISTORY);
  let history = result[KEYS.HISTORY] || [];

  if (options.classification) {
    history = history.filter(h => h.classification === options.classification);
  }
  if (options.limit) {
    history = history.slice(0, options.limit);
  }

  return history;
}

/**
 * Clear all browsing history.
 * @returns {Promise<void>}
 */
export async function clearHistory() {
  await storageSet({ [KEYS.HISTORY]: [] });
}

// ─── Allowlist ────────────────────────────────────────────────────────────────

/**
 * Get the user's allowlisted domains.
 * @returns {Promise<Set<string>>}
 */
export async function getAllowlist() {
  const result = await storageGet(KEYS.ALLOWLIST);
  return new Set(result[KEYS.ALLOWLIST] || []);
}

/**
 * Add a domain to the allowlist (user chose to proceed).
 * @param {string} domain
 * @returns {Promise<void>}
 */
export async function addToAllowlist(domain) {
  const allowlist = await getAllowlist();
  allowlist.add(domain.toLowerCase());
  await storageSet({ [KEYS.ALLOWLIST]: [...allowlist] });
}

/**
 * Remove a domain from the allowlist.
 * @param {string} domain
 * @returns {Promise<void>}
 */
export async function removeFromAllowlist(domain) {
  const allowlist = await getAllowlist();
  allowlist.delete(domain.toLowerCase());
  await storageSet({ [KEYS.ALLOWLIST]: [...allowlist] });
}

// ─── Reports ──────────────────────────────────────────────────────────────────

/**
 * Save a user-submitted phishing report.
 * @param {object} report
 * @returns {Promise<void>}
 */
export async function saveReport(report) {
  const result = await storageGet(KEYS.REPORTS);
  const reports = result[KEYS.REPORTS] || [];
  reports.unshift({
    ...report,
    id: `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    submittedAt: Date.now(),
    status: 'pending',
  });
  // Keep at most 200 reports
  await storageSet({ [KEYS.REPORTS]: reports.slice(0, 200) });
}

/**
 * Get all saved reports.
 * @returns {Promise<object[]>}
 */
export async function getReports() {
  const result = await storageGet(KEYS.REPORTS);
  return result[KEYS.REPORTS] || [];
}

// ─── Statistics ───────────────────────────────────────────────────────────────

/**
 * Increment a named statistic counter.
 * @param {string} statName
 * @param {number} [delta=1]
 * @returns {Promise<void>}
 */
export async function incrementStat(statName, delta = 1) {
  const result = await storageGet(KEYS.STATS);
  const stats = result[KEYS.STATS] || {};
  stats[statName] = (stats[statName] || 0) + delta;
  await storageSet({ [KEYS.STATS]: stats });
}

/**
 * Get all statistics.
 * @returns {Promise<object>}
 */
export async function getStats() {
  const result = await storageGet(KEYS.STATS);
  const stats = result[KEYS.STATS] || {};
  return {
    sitesScanned: stats.sitesScanned || 0,
    threatsBlocked: stats.threatsBlocked || 0,
    suspiciousDetected: stats.suspiciousDetected || 0,
    reportsSubmitted: stats.reportsSubmitted || 0,
    cacheHits: stats.cacheHits || 0,
    ...stats,
  };
}

/**
 * Export history and reports as JSON string.
 * @returns {Promise<string>}
 */
export async function exportDataAsJSON() {
  const [history, reports, stats] = await Promise.all([
    getHistory(),
    getReports(),
    getStats(),
  ]);
  return JSON.stringify({
    exportedAt: new Date().toISOString(),
    stats,
    history,
    reports,
  }, null, 2);
}

/**
 * Export history as a CSV string.
 * @returns {Promise<string>}
 */
export async function exportHistoryAsCSV() {
  const history = await getHistory();
  const headers = ['Timestamp', 'URL', 'Page Title', 'Risk Score', 'Classification', 'Top Finding'];
  const rows = history.map(h => [
    new Date(h.timestamp).toISOString(),
    `"${h.url.replace(/"/g, '""')}"`,
    `"${(h.pageTitle || '').replace(/"/g, '""')}"`,
    h.score,
    h.classification,
    `"${(h.findings?.[0] || '').replace(/"/g, '""')}"`,
  ]);
  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}
