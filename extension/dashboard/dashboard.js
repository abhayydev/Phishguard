/**
 * dashboard.js
 * PhishGuard full security dashboard controller.
 * Handles overview stats, history table, reports, and settings management.
 */

'use strict';

// ─── Tab Navigation ───────────────────────────────────────────────────────────
const navItems = document.querySelectorAll('.nav-item');
const tabSections = document.querySelectorAll('.tab-section');

navItems.forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const tab = item.dataset.tab;
    activateTab(tab);
  });
});

function activateTab(tabName) {
  navItems.forEach(n => n.classList.toggle('active', n.dataset.tab === tabName));
  tabSections.forEach(s => s.classList.toggle('hidden', s.id !== `tab-${tabName}`));
  if (tabName === 'overview') loadOverview();
  if (tabName === 'history') loadHistory();
  if (tabName === 'reports') loadReports();
  if (tabName === 'settings') loadSettings();
}

// ─── Messaging Helper ─────────────────────────────────────────────────────────
function sendMessage(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (response) => {
      if (chrome.runtime.lastError) resolve(null);
      else resolve(response);
    });
  });
}

// ─── OVERVIEW ─────────────────────────────────────────────────────────────────
async function loadOverview() {
  const [statsResp, historyResp] = await Promise.all([
    sendMessage({ type: 'GET_STATS' }),
    sendMessage({ type: 'GET_HISTORY', payload: { limit: 100 } }),
  ]);

  const stats = statsResp?.stats || {};
  document.getElementById('totalScanned').textContent = formatNumber(stats.sitesScanned);
  document.getElementById('totalBlocked').textContent = formatNumber(stats.threatsBlocked);
  document.getElementById('totalSuspicious').textContent = formatNumber(stats.suspiciousDetected);
  document.getElementById('totalReports').textContent = formatNumber(stats.reportsSubmitted);

  const history = historyResp?.history || [];
  renderDonutChart(history);
  renderActivityChart(history);
  renderHighRiskTable(history.filter(h => h.classification === 'High Risk').slice(0, 10));
}

function renderDonutChart(history) {
  const counts = { safe: 0, suspicious: 0, danger: 0 };
  history.forEach(h => {
    if (h.classification === 'Safe') counts.safe++;
    else if (h.classification === 'Suspicious') counts.suspicious++;
    else if (h.classification === 'High Risk') counts.danger++;
  });

  const total = counts.safe + counts.suspicious + counts.danger;
  document.getElementById('donutTotal').textContent = total;
  document.getElementById('legendSafe').textContent = counts.safe;
  document.getElementById('legendSuspicious').textContent = counts.suspicious;
  document.getElementById('legendDanger').textContent = counts.danger;

  const circumference = 301.6; // 2 * π * 48
  if (total === 0) return;

  const safeArc = (counts.safe / total) * circumference;
  const suspArc = (counts.suspicious / total) * circumference;
  const dangerArc = (counts.danger / total) * circumference;

  let offset = 0;
  setDonutSegment('donutSafe', safeArc, circumference, offset);
  offset += safeArc;
  setDonutSegment('donutSuspicious', suspArc, circumference, offset);
  offset += suspArc;
  setDonutSegment('donutDanger', dangerArc, circumference, offset);
}

function setDonutSegment(id, arcLen, circumference, startOffset) {
  const el = document.getElementById(id);
  if (!el) return;
  el.setAttribute('stroke-dasharray', `${arcLen} ${circumference - arcLen}`);
  el.setAttribute('stroke-dashoffset', -startOffset);
}

function renderActivityChart(history) {
  const canvas = document.getElementById('activityChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Build day buckets for last 7 days
  const days = [];
  const now = Date.now();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now - i * 86400000);
    days.push({
      label: d.toLocaleDateString('en-US', { weekday: 'short' }),
      safe: 0, suspicious: 0, danger: 0,
    });
  }

  history.forEach(h => {
    const age = Math.floor((now - h.timestamp) / 86400000);
    if (age <= 6) {
      const idx = 6 - age;
      if (h.classification === 'Safe') days[idx].safe++;
      else if (h.classification === 'Suspicious') days[idx].suspicious++;
      else if (h.classification === 'High Risk') days[idx].danger++;
    }
  });

  const W = canvas.width, H = canvas.height;
  const padL = 30, padB = 24, padT = 10, padR = 10;
  const chartW = W - padL - padR, chartH = H - padB - padT;

  ctx.clearRect(0, 0, W, H);

  const maxVal = Math.max(1, ...days.map(d => d.safe + d.suspicious + d.danger));
  const barW = (chartW / days.length) * 0.6;
  const barGap = chartW / days.length;

  days.forEach((day, i) => {
    const x = padL + i * barGap + (barGap - barW) / 2;
    const total = day.safe + day.suspicious + day.danger;

    // Stacked bar
    let yOffset = padT + chartH;
    const segments = [
      { val: day.safe, color: '#22c55e' },
      { val: day.suspicious, color: '#f59e0b' },
      { val: day.danger, color: '#ef4444' },
    ];

    for (const seg of segments) {
      if (seg.val === 0) continue;
      const h = (seg.val / maxVal) * chartH;
      yOffset -= h;
      ctx.fillStyle = seg.color;
      ctx.fillRect(x, yOffset, barW, h);
    }

    // Day label
    ctx.fillStyle = '#64748b';
    ctx.font = '10px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText(day.label, x + barW / 2, H - 6);
  });

  // Y-axis lines
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 1;
  for (let v = 0; v <= maxVal; v += Math.max(1, Math.floor(maxVal / 4))) {
    const y = padT + chartH - (v / maxVal) * chartH;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillStyle = '#64748b'; ctx.font = '9px system-ui'; ctx.textAlign = 'right';
    ctx.fillText(v, padL - 4, y + 3);
  }
}

function renderHighRiskTable(items) {
  const body = document.getElementById('highRiskBody');
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty-cell">No high-risk sites detected yet.</td></tr>';
    return;
  }
  body.innerHTML = items.map(h => `
    <tr>
      <td title="${escapeHTML(h.url)}">${escapeHTML(truncate(h.url, 55))}</td>
      <td><span class="score-pill" style="background:${scoreColor(h.score, 0.15)};color:${scoreColor(h.score)}">${h.score}</span></td>
      <td><span class="badge badge-high">High Risk</span></td>
      <td>${timeAgo(h.timestamp)}</td>
    </tr>
  `).join('');
}

// ─── HISTORY ──────────────────────────────────────────────────────────────────
let historyData = [];
let historyPage = 0;
const PAGE_SIZE = 20;

async function loadHistory() {
  const resp = await sendMessage({ type: 'GET_HISTORY' });
  historyData = resp?.history || [];
  historyPage = 0;
  renderHistoryTable();
}

function renderHistoryTable() {
  const search = document.getElementById('historySearch')?.value.toLowerCase() || '';
  const filter = document.getElementById('historyFilter')?.value || '';

  let filtered = historyData;
  if (search) filtered = filtered.filter(h => h.url.toLowerCase().includes(search));
  if (filter) filtered = filtered.filter(h => h.classification === filter);

  const total = filtered.length;
  const start = historyPage * PAGE_SIZE;
  const page = filtered.slice(start, start + PAGE_SIZE);

  const body = document.getElementById('historyTableBody');
  if (!page.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-cell">No entries match your filter.</td></tr>';
  } else {
    body.innerHTML = page.map(h => `
      <tr>
        <td title="${escapeHTML(h.url)}">${escapeHTML(truncate(h.url, 45))}</td>
        <td>${escapeHTML(truncate(h.pageTitle || '—', 30))}</td>
        <td><span class="score-pill" style="background:${scoreColor(h.score, 0.15)};color:${scoreColor(h.score)}">${h.score}</span></td>
        <td>${classificationBadge(h.classification)}</td>
        <td title="${escapeHTML((h.findings || []).join(', '))}">${escapeHTML(truncate((h.findings || [])[0] || '—', 35))}</td>
        <td>${timeAgo(h.timestamp)}</td>
      </tr>
    `).join('');
  }

  const totalPages = Math.ceil(total / PAGE_SIZE) || 1;
  document.getElementById('historyPageInfo').textContent = `Page ${historyPage + 1} of ${totalPages} (${total} entries)`;
  document.getElementById('historyPrevBtn').disabled = historyPage === 0;
  document.getElementById('historyNextBtn').disabled = start + PAGE_SIZE >= total;
}

document.getElementById('historySearch')?.addEventListener('input', () => { historyPage = 0; renderHistoryTable(); });
document.getElementById('historyFilter')?.addEventListener('change', () => { historyPage = 0; renderHistoryTable(); });
document.getElementById('historyPrevBtn')?.addEventListener('click', () => { historyPage--; renderHistoryTable(); });
document.getElementById('historyNextBtn')?.addEventListener('click', () => { historyPage++; renderHistoryTable(); });

document.getElementById('clearHistoryBtn')?.addEventListener('click', async () => {
  if (!confirm('Clear all browsing history? This cannot be undone.')) return;
  await chrome.storage.local.set({ phishguard_history: [] });
  historyData = [];
  renderHistoryTable();
});

// ─── REPORTS ──────────────────────────────────────────────────────────────────
async function loadReports() {
  const resp = await sendMessage({ type: 'GET_REPORTS' });
  const reports = resp?.reports || [];
  const body = document.getElementById('reportsTableBody');

  if (!reports.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty-cell">No reports submitted yet.</td></tr>';
    return;
  }
  body.innerHTML = reports.map(r => `
    <tr>
      <td title="${escapeHTML(r.url)}">${escapeHTML(truncate(r.url, 50))}</td>
      <td>${r.score ?? '—'}</td>
      <td>${escapeHTML(truncate(r.notes || '—', 40))}</td>
      <td><span class="badge badge-unknown">${escapeHTML(r.status || 'pending')}</span></td>
      <td>${timeAgo(r.submittedAt)}</td>
    </tr>
  `).join('');
}

document.getElementById('newReportBtn')?.addEventListener('click', () => {
  document.getElementById('newReportForm').style.display = 'block';
});
document.getElementById('cancelNewReport')?.addEventListener('click', () => {
  document.getElementById('newReportForm').style.display = 'none';
});
document.getElementById('submitNewReport')?.addEventListener('click', async () => {
  const url = document.getElementById('reportURLInput').value.trim();
  const notes = document.getElementById('reportNotesInput').value.trim();
  if (!url) return;
  await sendMessage({ type: 'SUBMIT_REPORT', payload: { url, notes } });
  document.getElementById('newReportForm').style.display = 'none';
  document.getElementById('reportURLInput').value = '';
  document.getElementById('reportNotesInput').value = '';
  loadReports();
});

// ─── SETTINGS ─────────────────────────────────────────────────────────────────
async function loadSettings() {
  const settings = await getSettings();

  document.getElementById('setProtection').checked = settings.protectionEnabled;
  document.getElementById('setWarningPage').checked = settings.showWarningPage;
  document.getElementById('setBlockHighRisk').checked = settings.blockHighRisk;
  document.getElementById('setBlockSuspicious').checked = settings.blockSuspicious;
  document.getElementById('setNotifications').checked = settings.showNotifications;
  document.getElementById('setSafeBrowsing').checked = settings.useSafeBrowsing;
  document.getElementById('setPhishTank').checked = settings.usePhishTank;
  document.getElementById('setWhois').checked = settings.useWhois;
  document.getElementById('setBackendURL').value = settings.backendURL || '';
  document.getElementById('setRetention').value = settings.historyRetentionDays || 30;
  document.getElementById('globalProtectionToggle').checked = settings.protectionEnabled;
}

document.getElementById('saveSettingsBtn')?.addEventListener('click', async () => {
  const updates = {
    protectionEnabled: document.getElementById('setProtection').checked,
    showWarningPage: document.getElementById('setWarningPage').checked,
    blockHighRisk: document.getElementById('setBlockHighRisk').checked,
    blockSuspicious: document.getElementById('setBlockSuspicious').checked,
    showNotifications: document.getElementById('setNotifications').checked,
    useSafeBrowsing: document.getElementById('setSafeBrowsing').checked,
    usePhishTank: document.getElementById('setPhishTank').checked,
    useWhois: document.getElementById('setWhois').checked,
    backendURL: document.getElementById('setBackendURL').value.trim(),
    historyRetentionDays: parseInt(document.getElementById('setRetention').value) || 30,
  };
  await saveSettings(updates);
  document.getElementById('globalProtectionToggle').checked = updates.protectionEnabled;
  showSaveStatus('✓ Settings saved');
});

document.getElementById('saveAPIKeys')?.addEventListener('click', async () => {
  const updates = {
    backendURL: document.getElementById('setBackendURL').value.trim(),
    safeBrowsingAPIKey: document.getElementById('setSBKey').value.trim(),
    phishTankAPIKey: document.getElementById('setPTKey').value.trim(),
  };
  await saveSettings(updates);
  showSaveStatus('✓ API keys saved');
});

document.getElementById('clearCacheBtn')?.addEventListener('click', async () => {
  await chrome.storage.local.set({ phishguard_cache: {} });
  showSaveStatus('✓ Cache cleared');
});

document.getElementById('clearAllDataBtn')?.addEventListener('click', async () => {
  if (!confirm('Delete ALL PhishGuard data including history, reports, and cache? This cannot be undone.')) return;
  await chrome.storage.local.clear();
  showSaveStatus('✓ All data cleared');
});

document.getElementById('globalProtectionToggle')?.addEventListener('change', async (e) => {
  await saveSettings({ protectionEnabled: e.target.checked });
});

function showSaveStatus(msg) {
  const el = document.getElementById('saveStatus');
  if (el) { el.textContent = msg; setTimeout(() => { el.textContent = ''; }, 2000); }
}

// ─── Export Buttons ───────────────────────────────────────────────────────────
document.getElementById('exportJSONBtn')?.addEventListener('click', async () => {
  const resp = await sendMessage({ type: 'EXPORT_JSON' });
  if (resp?.data) downloadFile('phishguard-export.json', resp.data, 'application/json');
});

document.getElementById('exportCSVBtn')?.addEventListener('click', async () => {
  const resp = await sendMessage({ type: 'EXPORT_CSV' });
  if (resp?.data) downloadFile('phishguard-history.csv', resp.data, 'text/csv');
});

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function getSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get('phishguard_settings', r => resolve(r.phishguard_settings || {}));
  });
}

function saveSettings(updates) {
  return new Promise(resolve => {
    chrome.storage.local.get('phishguard_settings', r => {
      const merged = { ...(r.phishguard_settings || {}), ...updates };
      chrome.storage.local.set({ phishguard_settings: merged }, resolve);
    });
  });
}

function classificationBadge(c) {
  const map = { Safe: 'badge-safe', Suspicious: 'badge-suspicious', 'High Risk': 'badge-high' };
  return `<span class="badge ${map[c] || 'badge-unknown'}">${escapeHTML(c)}</span>`;
}

function scoreColor(score, alpha) {
  const base = score <= 25 ? '34,197,94' : score <= 60 ? '245,158,11' : '239,68,68';
  return alpha ? `rgba(${base},${alpha})` : `rgb(${base})`;
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return new Date(ts).toLocaleDateString();
}

function truncate(str, len) {
  if (!str) return '';
  return str.length > len ? str.substring(0, len) + '…' : str;
}

function formatNumber(n) {
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
  return String(n || 0);
}

function escapeHTML(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
loadOverview();
