/**
 * warning.js
 * PhishGuard warning page controller.
 * Parses URL parameters and loads full analysis from storage,
 * then renders the warning details and handles user actions.
 */

'use strict';

// ─── Parse URL Parameters ─────────────────────────────────────────────────────
const params = new URLSearchParams(window.location.search);
const targetURL = decodeURIComponent(params.get('url') || '');
const riskScore = parseInt(params.get('score') || '0', 10);
const classification = decodeURIComponent(params.get('classification') || 'High Risk');

// ─── Populate Static Fields ───────────────────────────────────────────────────
document.getElementById('riskScore').textContent = riskScore;
document.getElementById('riskClassification').textContent = classification;
document.getElementById('targetURL').textContent = targetURL || 'Unknown URL';

// Style risk badge based on classification
const riskBadge = document.getElementById('riskBadge');
if (classification === 'Suspicious') riskBadge.classList.add('suspicious');

// Update page title
document.title = `⚠️ ${classification} — PhishGuard`;

// ─── Load Full Analysis for Findings ─────────────────────────────────────────
async function loadFindings() {
  const findingsList = document.getElementById('findingsList');

  try {
    // Try to get cached analysis from storage
    const cacheKey = buildCacheKey(targetURL);
    const result = await new Promise((resolve) => {
      chrome.storage.local.get('phishguard_cache', (data) => {
        const cache = data.phishguard_cache || {};
        resolve(cache[cacheKey]);
      });
    });

    if (result?.findings?.length > 0) {
      findingsList.innerHTML = result.findings
        .map(f => `<li>${escapeHTML(f)}</li>`)
        .join('');
    } else {
      // Show generic findings based on classification
      findingsList.innerHTML = getGenericFindings(classification)
        .map(f => `<li>${escapeHTML(f)}</li>`)
        .join('');
    }
  } catch {
    findingsList.innerHTML = getGenericFindings(classification)
      .map(f => `<li>${escapeHTML(f)}</li>`)
      .join('');
  }
}

function buildCacheKey(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.hostname}${u.pathname.substring(0, 50)}`;
  } catch {
    return url.substring(0, 100);
  }
}

function getGenericFindings(classification) {
  if (classification === 'High Risk') {
    return [
      'URL matches patterns commonly used in phishing attacks',
      'Domain or URL structure raises multiple security concerns',
      'This site may attempt to steal your credentials or personal data',
      'Threat intelligence systems have flagged this URL as dangerous',
    ];
  }
  return [
    'URL contains suspicious patterns that may indicate phishing',
    'Some elements of this site resemble known phishing techniques',
    'Exercise caution — do not enter personal information on this site',
  ];
}

// ─── Action Handlers ──────────────────────────────────────────────────────────
document.getElementById('goBackBtn').addEventListener('click', () => {
  // Navigate back to the previous safe page
  if (history.length > 1) {
    history.go(-2); // -2 to skip the warning page itself
  } else {
    window.location.href = 'chrome://newtab/';
  }
});

document.getElementById('proceedBtn').addEventListener('click', async () => {
  // Add domain to allowlist via background
  if (targetURL) {
    await chrome.runtime.sendMessage({
      type: 'PROCEED_ANYWAY',
      payload: { url: targetURL },
    });
  }

  // Navigate to the original URL
  window.location.href = targetURL;
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
loadFindings();
