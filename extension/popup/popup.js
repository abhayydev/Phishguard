/**
 * popup.js
 * PhishGuard popup controller.
 * Fetches the current tab's analysis from the background service worker
 * and renders the security dashboard in the popup.
 */

'use strict';

// ─── DOM Elements ─────────────────────────────────────────────────────────────
const loadingState = document.getElementById('loadingState');
const resultState = document.getElementById('resultState');
const errorState = document.getElementById('errorState');
const disabledState = document.getElementById('disabledState');

const gaugeArc = document.getElementById('gaugeArc');
const scoreText = document.getElementById('scoreText');
const classificationBadge = document.getElementById('classificationBadge');

const httpsIcon = document.getElementById('httpsIcon');
const domainText = document.getElementById('domainText');
const sslInfo = document.getElementById('sslInfo');

const sbStatus = document.getElementById('sbStatus');
const ptStatus = document.getElementById('ptStatus');
const whoisStatus = document.getElementById('whoisStatus');

const findingsContainer = document.getElementById('findingsContainer');
const findingsList = document.getElementById('findingsList');

const reportBtn = document.getElementById('reportBtn');
const reanalyzeBtn = document.getElementById('reanalyzeBtn');
const retryBtn = document.getElementById('retryBtn');
const enableBtn = document.getElementById('enableBtn');
const toggleBtn = document.getElementById('toggleProtection');
const dashboardBtn = document.getElementById('openDashboard');

const reportModal = document.getElementById('reportModal');
const reportURL = document.getElementById('reportURL');
const reportNotes = document.getElementById('reportNotes');
const cancelReport = document.getElementById('cancelReport');
const submitReport = document.getElementById('submitReport');
const errorText = document.getElementById('errorText');

const statScanned = document.getElementById('statScanned');
const statBlocked = document.getElementById('statBlocked');
const statSuspicious = document.getElementById('statSuspicious');

// Gauge arc circumference = 2π * 80 * (180/360) = ~251.2
const GAUGE_CIRCUMFERENCE = 251.2;

let currentURL = '';
let currentAnalysis = null;

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
  showState('loading');

  // Load footer stats
  loadStats();

  // Get current tab info
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    currentURL = tab.url || '';
  }

  // Check protection toggle state
  const settings = await getSettings();
  if (!settings.protectionEnabled) {
    showState('disabled');
    toggleBtn.classList.remove('active');
    return;
  }
  toggleBtn.classList.add('active');

  // Request analysis from background
  const response = await sendMessage({ type: 'GET_TAB_ANALYSIS' });

  if (response?.error) {
    showError(response.error);
    return;
  }

  if (response?.analysis) {
    currentAnalysis = response.analysis;
    renderAnalysis(response.analysis);
  } else if (response?.pending) {
    // Poll for result
    pollForResult(tab?.id);
  } else {
    showState('loading');
    pollForResult(tab?.id);
  }
}

// ─── Poll for background analysis result ─────────────────────────────────────
function pollForResult(tabId) {
  let attempts = 0;
  const interval = setInterval(async () => {
    attempts++;
    const response = await sendMessage({ type: 'GET_TAB_ANALYSIS' });

    if (response?.analysis) {
      clearInterval(interval);
      currentAnalysis = response.analysis;
      renderAnalysis(response.analysis);
    } else if (attempts >= 10) {
      clearInterval(interval);
      showError('Analysis timed out. The page may not be accessible.');
    }
  }, 800);
}

// ─── Render Analysis ──────────────────────────────────────────────────────────
function renderAnalysis(analysis) {
  if (!analysis) { showError('No analysis data received.'); return; }

  const score = analysis.score || 0;
  const classification = analysis.classification || 'Unknown';

  // Update gauge
  const offset = GAUGE_CIRCUMFERENCE - (score / 100) * GAUGE_CIRCUMFERENCE;
  gaugeArc.style.strokeDashoffset = offset;
  gaugeArc.style.stroke = getScoreColor(score);
  scoreText.textContent = score;

  // Update classification badge
  classificationBadge.textContent = classification;
  classificationBadge.className = 'classification-badge ' + classificationToClass(classification);

  // Update domain info
  const urlAnalysis = analysis.urlAnalysis || {};
  const domain = urlAnalysis.hostname || getDomain(currentURL);
  domainText.textContent = domain;
  httpsIcon.textContent = urlAnalysis.isHTTPS !== false ? '🔒' : '⚠️';

  // SSL info
  const ssl = analysis.sslInfo;
  if (ssl) {
    sslInfo.textContent = ssl.valid === false
      ? '⚠️ SSL certificate invalid'
      : `SSL valid until ${ssl.expiry || 'unknown'}`;
  }

  // Threat intel chips
  renderThreatIntel(analysis.threatIntel || {});

  // Findings
  const findings = analysis.findings || [];
  if (findings.length > 0) {
    findingsList.innerHTML = findings.map(f => `<li>${escapeHTML(f)}</li>`).join('');
    findingsContainer.classList.remove('hidden');
  } else {
    findingsContainer.classList.add('hidden');
  }

  showState('result');
}

function renderThreatIntel(intel) {
  // Safe Browsing
  if (intel.safeBrowsing?.checked) {
    sbStatus.textContent = intel.safeBrowsing.threat ? '⚠ Threat' : '✓ Clean';
    sbStatus.className = 'chip-status ' + (intel.safeBrowsing.threat ? 'danger' : 'ok');
  } else {
    sbStatus.textContent = intel.safeBrowsing?.error ? 'N/A' : '—';
    sbStatus.className = 'chip-status unknown';
  }

  // PhishTank
  if (intel.phishTank?.checked) {
    const flagged = intel.phishTank.inDatabase;
    ptStatus.textContent = flagged ? '⚠ Listed' : '✓ Clear';
    ptStatus.className = 'chip-status ' + (flagged ? 'danger' : 'ok');
  } else {
    ptStatus.textContent = '—';
    ptStatus.className = 'chip-status unknown';
  }

  // WHOIS / Domain Age
  if (intel.whois?.checked) {
    const age = intel.whois.domainAgeDays;
    if (age === 0 || age > 0) {
      if (age < 7) {
        whoisStatus.textContent = `${age}d ⚠`;
        whoisStatus.className = 'chip-status danger';
      } else if (age < 30) {
        whoisStatus.textContent = `${age}d !`;
        whoisStatus.className = 'chip-status warn';
      } else {
        whoisStatus.textContent = age > 365 ? `${Math.floor(age / 365)}y` : `${age}d`;
        whoisStatus.className = 'chip-status ok';
      }
    } else {
      whoisStatus.textContent = 'N/A';
      whoisStatus.className = 'chip-status unknown';
    }
  } else {
    whoisStatus.textContent = '—';
    whoisStatus.className = 'chip-status unknown';
  }
}

// ─── State Management ─────────────────────────────────────────────────────────
function showState(state) {
  loadingState.classList.add('hidden');
  resultState.classList.add('hidden');
  errorState.classList.add('hidden');
  disabledState.classList.add('hidden');

  if (state === 'loading') loadingState.classList.remove('hidden');
  else if (state === 'result') resultState.classList.remove('hidden');
  else if (state === 'error') errorState.classList.remove('hidden');
  else if (state === 'disabled') disabledState.classList.remove('hidden');
}

function showError(msg) {
  errorText.textContent = msg || 'An error occurred.';
  showState('error');
}

// ─── Stats ─────────────────────────────────────────────────────────────────────
async function loadStats() {
  const response = await sendMessage({ type: 'GET_STATS' });
  if (response?.stats) {
    statScanned.textContent = formatNumber(response.stats.sitesScanned);
    statBlocked.textContent = formatNumber(response.stats.threatsBlocked);
    statSuspicious.textContent = formatNumber(response.stats.suspiciousDetected);
  }
}

// ─── Event Handlers ───────────────────────────────────────────────────────────

reanalyzeBtn?.addEventListener('click', async () => {
  showState('loading');
  await sendMessage({ type: 'REANALYZE' });
  setTimeout(async () => {
    const response = await sendMessage({ type: 'GET_TAB_ANALYSIS' });
    if (response?.analysis) {
      currentAnalysis = response.analysis;
      renderAnalysis(response.analysis);
    } else {
      pollForResult();
    }
  }, 500);
});

retryBtn?.addEventListener('click', () => init());
enableBtn?.addEventListener('click', async () => {
  await saveSettings({ protectionEnabled: true });
  init();
});

toggleBtn?.addEventListener('click', async () => {
  const settings = await getSettings();
  await saveSettings({ protectionEnabled: !settings.protectionEnabled });
  init();
});

dashboardBtn?.addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
});

reportBtn?.addEventListener('click', () => {
  reportURL.textContent = currentURL.substring(0, 80) + (currentURL.length > 80 ? '...' : '');
  reportModal.classList.remove('hidden');
});

cancelReport?.addEventListener('click', () => {
  reportModal.classList.add('hidden');
  reportNotes.value = '';
});

document.querySelector('.modal-backdrop')?.addEventListener('click', () => {
  reportModal.classList.add('hidden');
  reportNotes.value = '';
});

submitReport?.addEventListener('click', async () => {
  await sendMessage({
    type: 'SUBMIT_REPORT',
    payload: {
      url: currentURL,
      notes: reportNotes.value.trim(),
      score: currentAnalysis?.score,
      classification: currentAnalysis?.classification,
    },
  });
  reportModal.classList.add('hidden');
  reportNotes.value = '';

  // Show brief confirmation
  reportBtn.textContent = '✓ Reported';
  reportBtn.disabled = true;
  setTimeout(() => {
    reportBtn.textContent = '🚨 Report Site';
    reportBtn.disabled = false;
  }, 2000);
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sendMessage(msg) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (response) => {
        if (chrome.runtime.lastError) resolve(null);
        else resolve(response);
      });
    } catch {
      resolve(null);
    }
  });
}

async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get('phishguard_settings', (result) => {
      resolve(result.phishguard_settings || {});
    });
  });
}

function saveSettings(updates) {
  return new Promise((resolve) => {
    chrome.storage.local.get('phishguard_settings', (result) => {
      const merged = { ...(result.phishguard_settings || {}), ...updates };
      chrome.storage.local.set({ phishguard_settings: merged }, resolve);
    });
  });
}

function getDomain(url) {
  try { return new URL(url).hostname; } catch { return url.substring(0, 40); }
}

function getScoreColor(score) {
  if (score <= 25) return '#22c55e';
  if (score <= 60) return '#f59e0b';
  return '#ef4444';
}

function classificationToClass(c) {
  if (c === 'Safe') return 'safe';
  if (c === 'Suspicious') return 'suspicious';
  if (c === 'High Risk') return 'high-risk';
  return 'unknown';
}

function formatNumber(n) {
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
  return String(n);
}

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Start ────────────────────────────────────────────────────────────────────
init();
