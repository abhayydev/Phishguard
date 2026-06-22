
# ⚡ PhishGuard — Phishing Prevention Browser Extension


![Status](https://img.shields.io/badge/status-production--ready-22c55e)
![Manifest](https://img.shields.io/badge/manifest-v3-6366f1)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## 📋 Table of Contents

1. [Features](#-features)
2. [Architecture](#-architecture)
3. [Installation Guide](#-installation-guide)
4. [Backend Deployment](#-backend-deployment-vercel)
5. [API Key Setup](#-api-key-setup)
6. [File Structure](#-file-structure)
7. [How It Works](#-how-it-works)
8. [Running Tests](#-running-tests)
9. [Docker Deployment](#-docker-deployment)
10. [Privacy & Security](#-privacy--security)
11. [Extending the Extension](#-extending-the-extension)
    

---

## ✨ Features

### Real-Time URL Analysis
- **Domain inspection** — extracts registered domain, counts subdomains
- **Typosquatting detection** — Levenshtein distance comparison against 40+ known brands
- **Homoglyph attacks** — detects Cyrillic/Unicode lookalikes (e.g. `pаypal.com`)
- **URL shortener detection** — flags 24+ known shortener services
- **IP-based URLs** — detects IPv4, IPv6, hex-encoded IPs
- **Suspicious TLDs** — flags `.tk`, `.ml`, `.xyz`, `.top`, and 20+ others
- **Excessive subdomains** — `paypal.secure.login.evil.com`
- **Phishing keywords** — 30+ keywords in URL path/query

### ML-Inspired Risk Scoring
- **Weighted feature extraction** across 30+ signals
- **Risk score 0–100** with calibrated weights
- **Three classifications** — Safe / Suspicious / High Risk
- **Human-readable findings** for each triggered signal
- **Threshold-based alerts** configurable by user

### Content Inspection (Content Script)
- **Fake login form detection** — brand in title vs. untrusted domain
- **Credential harvesting** — forms submitting to external domains
- **Hidden iframes** — 1×1 pixel or display:none iframes
- **Obfuscated JavaScript** — eval, unescape, String.fromCharCode patterns
- **Mixed content detection** — HTTP resources on HTTPS pages
- **Title/domain mismatch** — "PayPal Login" hosted on `evil.tk`
- **Missing favicon** — common in hastily-built phishing pages

### Website Security Checks
- HTTPS verification
- SSL certificate status display
- Mixed content detection
- Domain age via RDAP/WHOIS

### Threat Intelligence Integration
| Service | Type | Requires |
|---|---|---|
| Google Safe Browsing v4 | URL blacklist | API key + backend |
| PhishTank | Phishing database | Optional API key |
| RDAP/WHOIS | Domain age | Backend |

All intelligence checks run in **parallel** for performance and results are **cached** per-URL.

### User Protection
- **Warning page** with animated UI before entering dangerous sites
- **Risk score display** with gauge and classification badge
- **Detailed findings** — exactly why the site was flagged
- **Safe exit** (go back) or **allowlist proceed**
- **Domain allowlist** — remember user choices

### Dashboard
- **Overview stats** — sites scanned, threats blocked, suspicious count
- **Interactive donut chart** — risk distribution
- **7-day activity bar chart** (canvas-drawn, no external libraries)
- **Browsing history table** — searchable, filterable, paginated
- **Reports management** — submit and track phishing reports
- **Settings panel** — all toggles and API configuration
- **Export** — JSON or CSV with one click
- **Dark mode** by default (cybersecurity theme)

### Reporting System
- Submit suspected phishing sites with notes
- Optional server-side forwarding to PhishTank
- Export all reports as JSON or CSV

### Privacy
- All URL analysis runs **locally** in the extension — no data sent to servers
- Threat intelligence API calls only made when explicitly enabled
- **No credential collection** — no content from password fields is ever read
- API keys stored in extension's local storage (never transmitted to third parties)
- Backend proxy keeps your API keys off the client

---
<img width="353" height="565" alt="Screenshot 2026-06-21 125137" src="https://github.com/user-attachments/assets/f212238f-7c07-4b01-8b4c-f31efc7a23e6" />
<img width="1336" height="679" alt="Screenshot 2026-06-21 125714" src="https://github.com/user-attachments/assets/9c536d45-a612-4355-99e6-1decb3fcd0dc" />
<img width="1347" height="674" alt="Screenshot 2026-06-21 125941" src="https://github.com/user-attachments/assets/cee8f716-a98a-46b3-83ce-c9409e2445b7" />
<img width="1158" height="552" alt="Screenshot 2026-06-21 130051" src="https://github.com/user-attachments/assets/66aa8d4f-13bb-4138-8002-b4f9eb6954d0" />
<img width="1182" height="581" alt="Screenshot 2026-06-21 130116" src="https://github.com/user-attachments/assets/f956f758-7633-4c2b-ace2-0dd690e0dd35" />
<img width="1182" height="597" alt="Screenshot 2026-06-21 140656" src="https://github.com/user-attachments/assets/a2f79ee7-9ba9-4f7c-8f25-4261b76920ca" />


## 🏗 Architecture

```
phishing-extension/
├── extension/                  # Chrome/Edge extension (Manifest V3)
│   ├── manifest.json           # Extension manifest
│   ├── background/
│   │   └── service-worker.js   # Main coordinator — navigation analysis, cache, messages
│   ├── content/
│   │   └── content-script.js   # DOM analysis — forms, iframes, JS obfuscation
│   ├── popup/
│   │   ├── popup.html/css/js   # Extension popup — risk gauge, findings
│   ├── dashboard/
│   │   ├── dashboard.html/css/js  # Full dashboard — stats, history, settings
│   ├── warning/
│   │   ├── warning.html/css/js  # Warning interstitial page
│   ├── lib/
│   │   ├── url-utils.js        # URL parsing, typosquatting, homoglyphs
│   │   ├── ml-classifier.js    # Feature extraction + risk scoring
│   │   ├── storage-manager.js  # chrome.storage abstraction
│   │   └── threat-intelligence.js  # Safe Browsing, PhishTank, WHOIS
│   ├── assets/icons/           # Extension icons (16/32/48/128px)
│   └── tests/                  # Unit tests (no browser required)
│
└── backend/                    # Vercel serverless backend
    ├── api/
    │   ├── safebrowsing.js     # Google Safe Browsing proxy
    │   ├── phishtank.js        # PhishTank proxy
    │   ├── whois.js            # RDAP/WHOIS domain lookup
    │   └── report.js           # Report submission endpoint
    ├── vercel.json             # Vercel deployment config
    ├── docker-server.js        # Express adapter for Docker
    └── Dockerfile              # Docker deployment
```

### Analysis Pipeline

```
Navigation → service-worker.js
               │
               ├─ 1. Check allowlist (instant)
               ├─ 2. Check analysis cache (instant)
               ├─ 3. URL structure analysis via url-utils.js (sync, ~1ms)
               │      ↓
               │   Quick risk score via ml-classifier.js
               │   → If score ≥ 70: show warning page immediately
               │
               ├─ 4. Threat intelligence (async, parallel)
               │      ├─ checkSafeBrowsing()
               │      ├─ checkPhishTank()
               │      └─ lookupWHOIS()
               │
               ├─ 5. Full ML risk score (all signals combined)
               │
               ├─ 6. Content script signals (DOM analysis)
               │      └─ Re-score if content signals escalate risk
               │
               └─ 7. Update badge, cache result, record history
```

---

## 🚀 Installation Guide

### Prerequisites
- Google Chrome 88+ or Microsoft Edge 88+
- (Optional) Node.js 18+ for backend deployment and running tests

### Step 1: Download the Extension

```bash
git clone https://github.com/abhayydev/phishguard.git
cd phishguard
```

Or download and extract the ZIP from GitHub Releases.

### Step 2: Generate Icons

The extension needs PNG icons in `extension/assets/icons/`. You can:

**Option A: Use the generator script (requires `canvas` npm package)**
```bash
cd extension/assets/icons
npm install canvas
node generate-icons.js
```

**Option B: Create icons manually**
Create four PNG files with a lightning bolt (⚡) on an indigo (#6366f1) background:
- `icon16.png` — 16×16px
- `icon32.png` — 32×32px
- `icon48.png` — 48×48px
- `icon128.png` — 128×128px

**Option C: Use placeholder icons for development**
```bash
# On Linux/macOS with ImageMagick:
cd extension/assets/icons
for size in 16 32 48 128; do
  convert -size ${size}x${size} xc:#6366f1 icon${size}.png 2>/dev/null || \
  python3 -c "
import struct, zlib, base64
# Create minimal 1x1 PNG
sig = b'\x89PNG\r\n\x1a\n'
ihdr = struct.pack('>IIBBBBB', $size, $size, 8, 2, 0, 0, 0)
open('icon${size}.png', 'wb').write(sig)
print('Created placeholder icon${size}.png')
"
done
```

### Step 3: Load in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `phishing-extension/extension/` folder
5. PhishGuard appears in your extensions list ✓

### Step 4: Load in Edge

1. Navigate to `edge://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `phishing-extension/extension/`

### Step 5: Pin the Extension

- Click the puzzle piece (🧩) icon in Chrome/Edge toolbar
- Find PhishGuard and click the pin icon
- The PhishGuard badge now appears in your toolbar

### Step 6: Configure (Optional)

Click the extension icon → gear (⚙) → Opens dashboard → **Settings** tab

---

## ☁️ Backend Deployment (Vercel)

The backend is **optional** but required for Google Safe Browsing, PhishTank, and WHOIS checks. It keeps your API keys secure.

### Deploy to Vercel

```bash
cd phishing-extension/backend

# Install Vercel CLI
npm install -g vercel

# Login to Vercel
vercel login

# Deploy
vercel --prod
```

### Set Environment Variables

In the Vercel dashboard (or via CLI):

```bash
vercel env add SAFE_BROWSING_API_KEY
# Paste your Google API key when prompted

vercel env add PHISHTANK_API_KEY
# Paste your PhishTank key (or leave empty)
```

### Configure Extension

After deployment:
1. Open PhishGuard dashboard → Settings
2. Paste your Vercel deployment URL (e.g. `https://phishguard-backend.vercel.app`)
3. Click **Save API Configuration**

---

## 🔑 API Key Setup

### Google Safe Browsing API

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project (or use existing)
3. Enable the **Safe Browsing API**: APIs & Services → Library → search "Safe Browsing"
4. Create credentials: APIs & Services → Credentials → Create API Key
5. Restrict the key to "Safe Browsing API" only
6. **Free tier**: 10,000 queries/day

### PhishTank API (Optional)

1. Register at [phishtank.com](https://www.phishtank.com/register.php)
2. Go to [API registration](https://www.phishtank.com/api_register.php)
3. Create an app key
4. **Free tier**: 100 req/hr without key, 1,000 req/hr with key

---

## 📁 File Structure

```
extension/
├── manifest.json                # MV3 manifest — permissions, service worker, content scripts
│
├── background/
│   └── service-worker.js        # Navigation interception, analysis coordination,
│                                #   badge management, message router
│
├── content/
│   └── content-script.js        # Injected into every page at document_start
│                                #   Analyzes DOM: forms, iframes, JS, mixed content
│
├── popup/
│   ├── popup.html               # 360px popup UI
│   ├── popup.css                # Dark cybersecurity theme
│   └── popup.js                 # Gauge animation, chip updates, report modal
│
├── dashboard/
│   ├── dashboard.html           # Full-page dashboard (opens as extension option)
│   ├── dashboard.css            # Sidebar layout, data tables, chart styles
│   └── dashboard.js             # Stats, history pagination, settings, canvas charts
│
├── warning/
│   ├── warning.html             # Full-page warning interstitial
│   ├── warning.css              # Animated shield, grid background, pulse effects
│   └── warning.js               # URL param parsing, findings loading, proceed/back
│
├── lib/
│   ├── url-utils.js             # analyzeURLStructure() — 15+ URL signal checks
│   ├── ml-classifier.js         # analyzePhishingRisk() — 30+ feature scoring
│   ├── storage-manager.js       # Cache, history, settings, reports via chrome.storage
│   └── threat-intelligence.js   # Safe Browsing, PhishTank, WHOIS API clients
│
├── assets/
│   └── icons/
│       ├── icon16.png            # Required: 16×16 extension icon
│       ├── icon32.png            # Required: 32×32
│       ├── icon48.png            # Required: 48×48
│       ├── icon128.png           # Required: 128×128 (store listing)
│       └── generate-icons.js     # Script to generate icons programmatically
│
└── tests/
    ├── url-analyzer.test.js      # 60+ tests for url-utils.js
    └── ml-classifier.test.js     # 40+ tests for ml-classifier.js
```

---

## ⚙️ How It Works

### Phase 1: URL Analysis (Synchronous, <1ms)

When you navigate to a new page, the background service worker immediately:

1. **Parses the URL** — extracts hostname, registered domain, protocol, path
2. **Checks 15+ structural signals**:
   - Is it an IP address? (`185.220.101.45/login`)
   - Is it a URL shortener? (`bit.ly/fake-bank`)
   - Does it have a suspicious TLD? (`paypal-login.tk`)
   - Does it contain homoglyphs? (`pаypal.com` with Cyrillic а)
   - Does it have 4+ subdomains? (`secure.paypal.com.verify.evil.ml`)
   - Is there an `@` symbol? (`https://paypal.com@evil.com`)
   - Are there phishing keywords? (`/account/verify/login.php`)
3. **Runs initial ML scoring** — if score ≥ 70, immediately redirects to warning page

### Phase 2: Threat Intelligence (Async, ~1–3 seconds)

In parallel, the service worker contacts the configured backend for:
- **Google Safe Browsing** — checks against Google's continuously-updated threat database
- **PhishTank** — checks against crowdsourced phishing URL database
- **RDAP/WHOIS** — determines domain registration age (< 7 days = very suspicious)

### Phase 3: Content Analysis (After DOM Ready)

The injected content script runs DOM analysis:
- Scans all `<form>` elements for login fields submitting to external domains
- Checks iframes for hidden/1×1 pixel elements
- Scans inline `<script>` tags for obfuscation patterns
- Compares page title against domain name

### Phase 4: Consolidated Score

All three phases combine into a final weighted risk score. The badge and popup update with the final result.

### Caching Strategy

| Classification | Cache Duration |
|---|---|
| Safe | 24 hours |
| Suspicious | 6 hours |
| High Risk | 1 hour (re-check frequently) |

Maximum 500 cached entries — LRU eviction when full.

---

## 🧪 Running Tests

Tests use a self-contained test harness (no npm install required):

```bash
# Navigate to the extension directory
cd phishing-extension/extension

# Run URL analysis tests (60+ test cases)
node tests/url-analyzer.test.js

# Run ML classifier tests (40+ test cases)
node tests/ml-classifier.test.js
```

Expected output:
```
  📦 URL Utilities — extractRegisteredDomain
    ✓ extracts simple domain
    ✓ strips www prefix
    ...

  ────────────────────────────────────────────────
  Results: 67 passed, 0 failed
  ────────────────────────────────────────────────
```

### Test Coverage

| Module | Tests | What's Covered |
|---|---|---|
| `url-utils.js` | 67 | Domain extraction, IP detection, TLD check, typosquatting, homoglyphs, keywords, edge cases |
| `ml-classifier.js` | 42 | Feature extraction, score calculation, risk classification, real-world scenarios |

---

## 🐳 Docker Deployment

For self-hosted backend (non-Vercel):

```bash
cd phishing-extension/backend

# Build image
docker build -t phishguard-backend .

# Run with environment variables
docker run -d \
  -p 3001:3001 \
  -e SAFE_BROWSING_API_KEY=your_key_here \
  -e PHISHTANK_API_KEY=your_key_here \
  --name phishguard \
  phishguard-backend

# Verify
curl http://localhost:3001/health
# → {"status":"ok","service":"phishguard-backend"}
```

### Docker Compose (with HTTPS via nginx)

```yaml
# docker-compose.yml
version: '3.8'
services:
  phishguard-backend:
    build: ./backend
    environment:
      - SAFE_BROWSING_API_KEY=${SAFE_BROWSING_API_KEY}
      - PHISHTANK_API_KEY=${PHISHTANK_API_KEY}
    ports:
      - "3001:3001"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3001/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

---

## 🔒 Privacy & Security

### What PhishGuard Does NOT Collect

- ❌ URL contents or browsing history are never sent to any server unless threat intelligence is enabled
- ❌ No password field values are ever read by the content script
- ❌ No personal information is collected
- ❌ No analytics or telemetry

### What Gets Sent to Servers (When Enabled)

| Data | Sent To | When |
|---|---|---|
| Full URL | Your Vercel backend → Google/PhishTank | Per navigation (cached 1–24h) |
| Domain name | Your Vercel backend → RDAP | Per new domain |
| Phishing report URL | Your Vercel backend | When you click "Report" |

All API calls go through **your own backend**, not to a PhishGuard server. You control the data.

### Security Best Practices Followed

- Manifest V3 (restrictive permission model)
- Content Security Policy on extension pages (`script-src 'self'`)
- All external API calls proxied through user-controlled backend
- API keys stored in `chrome.storage.local` (sandboxed per extension)
- No `eval()` or dynamic code execution
- CORS restricted to extension origins on backend

---

## 🔧 Extending the Extension

### Adding a New URL Signal

In `lib/url-utils.js`, add your check function:
```js
export function detectNewSignal(urlString) {
  // Your logic
  return true; // or false
}
```

In `lib/ml-classifier.js`:
1. Add to `FEATURE_WEIGHTS`: `newSignal: 20`
2. Extract in `extractFeatures()`: `features.newSignal = detectNewSignal(url)`
3. Add to `FINDING_MESSAGES` in `generateFindings()`

### Adding a New Threat Intelligence Source

In `lib/threat-intelligence.js`:
1. Export a new async function `checkNewSource(url, config)`
2. Add to `runThreatIntelligence()` in the parallel promise array
3. Add the result key to the feature extraction in `ml-classifier.js`

### Adding a New Dashboard Tab

1. Add nav item in `dashboard/dashboard.html`
2. Add `<section id="tab-newname">` content
3. Add case to `activateTab()` in `dashboard/dashboard.js`

--

This project demonstrates:

| Skill | Where |
|---|---|
| **Browser Extension Development** | Manifest V3, service workers, content scripts, message passing |
| **JavaScript ES Modules** | All files use `import`/`export`, no bundler required |
| **Security Engineering** | Typosquatting detection, homoglyph attacks, credential harvesting detection |
| **Algorithm Design** | Levenshtein distance, weighted scoring, logistic normalization |
| **API Integration** | Google Safe Browsing v4, PhishTank, RDAP/WHOIS |
| **Serverless Architecture** | Vercel functions with CORS, rate limiting, API key proxying |
| **Docker** | Multi-stage builds, health checks, docker-compose |
| **Testing** | Self-contained test harness, 100+ test cases, real-world scenarios |
| **UI/UX Design** | Dark mode, animated gauge, canvas charts, responsive layout |
| **Privacy Engineering** | Local-first analysis, no credential collection, minimal data exposure |


> "Built a production-ready anti-phishing browser extension for Chrome/Edge (Manifest V3) with real-time URL analysis using Levenshtein-based typosquatting detection, homoglyph attack identification, and a weighted ML-inspired scoring engine across 30+ security signals. Integrated Google Safe Browsing and PhishTank APIs through a Vercel serverless backend with CORS and API key proxying. Content scripts perform live DOM analysis for credential harvesting detection and fake login form identification. Includes a full cybersecurity dashboard with browsing history, export capabilities, and an animated warning page. Backed by 100+ unit tests with no external test framework dependency."

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-signal`
3. Run tests: `node tests/url-analyzer.test.js && node tests/ml-classifier.test.js`
4. Submit a pull request

---

*Built by Abhay ⚡ PhishGuard — Keeping users safe, one URL at a time.*
