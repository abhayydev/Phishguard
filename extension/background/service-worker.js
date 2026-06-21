/**
 * service-worker.js
 * PhishGuard background service worker (Manifest V3).
 *
 * Responsibilities:
 * - Intercept navigation events and run phishing analysis
 * - Coordinate between URL analyzer, threat intelligence, and content scripts
 * - Redirect to warning page for dangerous URLs
 * - Manage analysis cache and badge updates
 * - Handle messages from popup and content scripts
 */

'use strict';

import { analyzeURLStructure } from '../lib/url-utils.js';
import { analyzePhishingRisk } from '../lib/ml-classifier.js';
import { runThreatIntelligence } from '../lib/threat-intelligence.js';
import {
  getSettings,
  getCachedAnalysis,
  cacheAnalysis,
  addToHistory,
  getAllowlist,
  addToAllowlist,
  incrementStat,
  getStats,
  getHistory,
  getReports,
  saveReport,
  exportDataAsJSON,
  exportHistoryAsCSV,
} from '../lib/storage-manager.js';

// ─── Badge Colors ─────────────────────────────────────────────────────────────
const BADGE_COLORS = {
  Safe: '#22c55e',
  Suspicious: '#f59e0b',
  'High Risk': '#ef4444',
  Unknown: '#6b7280',
  Disabled: '#374151',
};

const BADGE_TEXT = {
  Safe: '✓',
  Suspicious: '!',
  'High Risk': '✕',
  Unknown: '?',
  Disabled: 'OFF',
};

// ─── Internal State ───────────────────────────────────────────────────────────
// Map<tabId, analysisResult> — in-memory tab state
const tabAnalysisMap = new Map();

// Set of tabIds currently being analyzed (prevent double-analysis)
const analyzingTabs = new Set();

// ─── Initialization ───────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  console.log('[PhishGuard] Extension installed/updated. Reason:', reason);

  if (reason === 'install') {
    // Set default settings
    const { DEFAULT_SETTINGS } = await import('../lib/storage-manager.js');
    await chrome.storage.local.set({ phishguard_settings: DEFAULT_SETTINGS });

    // Show welcome notification
    chrome.notifications.create('welcome', {
      type: 'basic',
      iconUrl: '../assets/icons/icon48.png',
      title: 'PhishGuard Activated',
      message: 'Real-time phishing protection is now active. Click the extension icon for security details.',
    });
  }

  // Set up periodic cache cleanup alarm
  chrome.alarms.create('cache-cleanup', { periodInMinutes: 60 });
  chrome.alarms.create('stats-reset-check', { periodInMinutes: 1440 }); // Daily
});

// ─── Alarm Handlers ───────────────────────────────────────────────────────────
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'cache-cleanup') {
    // Trigger cache cleanup by calling getCached with expired TTL logic
    console.log('[PhishGuard] Running scheduled cache cleanup');
  }
});

// ─── Navigation Analysis ──────────────────────────────────────────────────────

/**
 * Main entry point: analyze a navigation and update tab state.
 * @param {number} tabId
 * @param {string} url
 * @param {string} [pageTitle]
 */
async function analyzeNavigation(tabId, url, pageTitle = '') {
  // Skip chrome://, about:, data:, extension pages
  if (!url || !url.startsWith('http')) return;

  // Skip our own warning page
  if (url.includes('warning/warning.html')) return;

  // Prevent duplicate concurrent analysis for same tab
  if (analyzingTabs.has(tabId)) return;
  analyzingTabs.add(tabId);

  try {
    const settings = await getSettings();

    // If protection is disabled, just clear badge
    if (!settings.protectionEnabled) {
      updateBadge(tabId, 'Disabled');
      return;
    }

    // Check allowlist
    const allowlist = await getAllowlist();
    let domain = '';
    try { domain = new URL(url).hostname; } catch { /* ignore */ }

    if (allowlist.has(domain.toLowerCase())) {
      const allowedResult = {
        classification: 'Safe',
        score: 0,
        findings: ['Domain is on your allowlist'],
        allowlisted: true,
      };
      tabAnalysisMap.set(tabId, allowedResult);
      updateBadge(tabId, 'Safe');
      return;
    }

    // Check cache first
    const cached = await getCachedAnalysis(url);
    if (cached) {
      tabAnalysisMap.set(tabId, cached);
      updateBadge(tabId, cached.classification);
      await incrementStat('cacheHits');
      // Still check if we should warn
      await handleRiskResult(tabId, url, cached, settings);
      return;
    }

    // Set badge to "analyzing" state
    updateBadgePending(tabId);

    // ── Phase 1: URL Structure Analysis (fast, synchronous) ──────────────────
    const urlAnalysis = analyzeURLStructure(url);
    const quickResult = analyzePhishingRisk({ url, urlAnalysis });

    // If clearly high-risk from URL alone, warn immediately
    if (quickResult.score >= 70 && settings.showWarningPage) {
      tabAnalysisMap.set(tabId, { ...quickResult, complete: false });
      updateBadge(tabId, quickResult.classification);
      await handleRiskResult(tabId, url, quickResult, settings);
    }

    // ── Phase 2: Threat Intelligence (async) ────────────────────────────────
    const threatIntel = await runThreatIntelligence(url, settings);
    const domainAgeDays = threatIntel.whois?.domainAgeDays ?? -1;

    // ── Phase 3: Full ML Analysis ────────────────────────────────────────────
    const fullResult = analyzePhishingRisk({
      url,
      urlAnalysis,
      threatIntel,
      domainAgeDays,
    });

    // Attach threat intel data for display
    fullResult.threatIntel = threatIntel;
    fullResult.whois = threatIntel.whois;
    fullResult.complete = true;

    // Update tab state
    tabAnalysisMap.set(tabId, fullResult);
    updateBadge(tabId, fullResult.classification);

    // Cache the result
    await cacheAnalysis(url, fullResult);

    // Record in history
    await addToHistory(url, fullResult, pageTitle);

    // Increment stats
    await incrementStat('sitesScanned');
    if (fullResult.classification === 'High Risk') {
      await incrementStat('threatsBlocked');
    } else if (fullResult.classification === 'Suspicious') {
      await incrementStat('suspiciousDetected');
    }

    // Final risk check
    await handleRiskResult(tabId, url, fullResult, settings);

    // Notify popup/content script if they're listening
    safeMessageTab(tabId, {
      type: 'ANALYSIS_COMPLETE',
      analysis: fullResult,
    });

  } catch (err) {
    console.error('[PhishGuard] Analysis error:', err);
    const errorResult = {
      classification: 'Unknown',
      score: 0,
      findings: ['Analysis failed: ' + err.message],
      complete: true,
    };
    tabAnalysisMap.set(tabId, errorResult);
    updateBadge(tabId, 'Unknown');
  } finally {
    analyzingTabs.delete(tabId);
  }
}

/**
 * Handle risk result — show warning page if appropriate.
 * @param {number} tabId
 * @param {string} url
 * @param {object} result
 * @param {object} settings
 */
async function handleRiskResult(tabId, url, result, settings) {
  if (!settings.showWarningPage) return;

  const shouldWarn =
    (result.classification === 'High Risk' && settings.blockHighRisk) ||
    (result.classification === 'Suspicious' && settings.blockSuspicious);

  if (shouldWarn) {
    const warningURL = chrome.runtime.getURL('warning/warning.html') +
      `?url=${encodeURIComponent(url)}&score=${result.score}&classification=${encodeURIComponent(result.classification)}`;

    try {
      await chrome.tabs.update(tabId, { url: warningURL });
    } catch { /* Tab may have been closed */ }
  }
}

// ─── Badge Management ─────────────────────────────────────────────────────────

function updateBadge(tabId, classification) {
  const color = BADGE_COLORS[classification] || BADGE_COLORS.Unknown;
  const text = BADGE_TEXT[classification] || '?';

  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text });
}

function updateBadgePending(tabId) {
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#6366f1' });
  chrome.action.setBadgeText({ tabId, text: '...' });
}

/**
 * Safely send a message to a tab's content script.
 */
function safeMessageTab(tabId, message) {
  chrome.tabs.sendMessage(tabId, message).catch(() => {
    // Content script may not be ready — ignore
  });
}

// ─── Navigation Event Listeners ───────────────────────────────────────────────

// Primary trigger: when a navigation completes
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame

  // Get page title
  let pageTitle = '';
  try {
    const tab = await chrome.tabs.get(details.tabId);
    pageTitle = tab.title || '';
  } catch { /* ignore */ }

  await analyzeNavigation(details.tabId, details.url, pageTitle);
}, { url: [{ schemes: ['http', 'https'] }] });

// Also trigger on history state changes (SPAs)
chrome.webNavigation.onHistoryStateUpdated.addListener(async (details) => {
  if (details.frameId !== 0) return;
  await analyzeNavigation(details.tabId, details.url);
}, { url: [{ schemes: ['http', 'https'] }] });

// Clear state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabAnalysisMap.delete(tabId);
  analyzingTabs.delete(tabId);
});

// Clear state when tab navigates away
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    updateBadgePending(tabId);
  }
});

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch(err => sendResponse({ error: err.message }));
  return true; // Keep message channel open for async
});

async function handleMessage(message, sender) {
  const { type, payload } = message;

  switch (type) {
    // ── Popup requests current tab analysis ─────────────────────────────────
    case 'GET_TAB_ANALYSIS': {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tabId = tabs[0]?.id;
      if (!tabId) return { error: 'No active tab' };

      const analysis = tabAnalysisMap.get(tabId);
      if (analysis) {
        return { analysis, tabId };
      }
      // Not analyzed yet — trigger analysis
      const tab = tabs[0];
      analyzeNavigation(tabId, tab.url, tab.title).catch(console.error);
      return { analysis: null, pending: true };
    }

    // ── Content script sends content analysis signals ────────────────────────
    case 'CONTENT_SIGNALS': {
      const tabId = sender.tab?.id;
      if (!tabId) return { ok: false };

      const existing = tabAnalysisMap.get(tabId);
      if (existing && !existing.allowlisted) {
        // Re-run risk analysis with content signals
        const settings = await getSettings();
        const refreshed = analyzePhishingRisk({
          url: sender.tab.url,
          contentSignals: payload,
          threatIntel: existing.threatIntel,
          domainAgeDays: existing.whois?.domainAgeDays ?? -1,
        });
        refreshed.threatIntel = existing.threatIntel;
        refreshed.whois = existing.whois;
        refreshed.contentSignals = payload;
        refreshed.complete = true;

        tabAnalysisMap.set(tabId, refreshed);
        updateBadge(tabId, refreshed.classification);
        await cacheAnalysis(sender.tab.url, refreshed);

        // Warn if content signals escalated risk
        await handleRiskResult(tabId, sender.tab.url, refreshed, settings);
      }
      return { ok: true };
    }

    // ── User chooses to proceed past warning page ────────────────────────────
    case 'PROCEED_ANYWAY': {
      const { url } = payload;
      let domain = '';
      try { domain = new URL(url).hostname; } catch { /* ignore */ }
      await addToAllowlist(domain);
      return { ok: true };
    }

    // ── Get statistics ───────────────────────────────────────────────────────
    case 'GET_STATS': {
      const stats = await getStats();
      return { stats };
    }

    // ── Get history ──────────────────────────────────────────────────────────
    case 'GET_HISTORY': {
      const history = await getHistory(payload || {});
      return { history };
    }

    // ── Get reports ──────────────────────────────────────────────────────────
    case 'GET_REPORTS': {
      const reports = await getReports();
      return { reports };
    }

    // ── Submit phishing report ───────────────────────────────────────────────
    case 'SUBMIT_REPORT': {
      await saveReport(payload);
      await incrementStat('reportsSubmitted');
      return { ok: true };
    }

    // ── Export data ──────────────────────────────────────────────────────────
    case 'EXPORT_JSON': {
      const json = await exportDataAsJSON();
      return { data: json };
    }

    case 'EXPORT_CSV': {
      const csv = await exportHistoryAsCSV();
      return { data: csv };
    }

    // ── Re-analyze current tab ───────────────────────────────────────────────
    case 'REANALYZE': {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (tab) {
        tabAnalysisMap.delete(tab.id);
        analyzingTabs.delete(tab.id);
        analyzeNavigation(tab.id, tab.url, tab.title).catch(console.error);
      }
      return { ok: true };
    }

    default:
      return { error: `Unknown message type: ${type}` };
  }
}

// ─── Command Shortcuts ────────────────────────────────────────────────────────
chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'toggle-protection') {
    const settings = await getSettings();
    const { saveSettings } = await import('../lib/storage-manager.js');
    await saveSettings({ protectionEnabled: !settings.protectionEnabled });

    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tabId = tabs[0]?.id;
    if (tabId) updateBadge(tabId, settings.protectionEnabled ? 'Disabled' : 'Unknown');

    chrome.notifications.create({
      type: 'basic',
      iconUrl: '../assets/icons/icon48.png',
      title: 'PhishGuard',
      message: settings.protectionEnabled
        ? 'Protection disabled. You are now unprotected.'
        : 'Protection re-enabled. Staying safe!',
    });
  }

  if (command === 'open-dashboard') {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
  }
});
