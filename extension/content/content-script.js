/**
 * content-script.js
 * PhishGuard content script — injected into every page at document_start.
 *
 * Responsibilities:
 * - Detect fake login forms and credential harvesting
 * - Identify hidden iframes and suspicious DOM patterns
 * - Detect obfuscated JavaScript
 * - Check for title/domain mismatches
 * - Detect mixed content
 * - Send content signals to background service worker
 */

'use strict';

(function () {
  // Prevent double-injection
  if (window.__phishguard_injected) return;
  window.__phishguard_injected = true;

  const PAGE_URL = window.location.href;
  const PAGE_HOSTNAME = window.location.hostname.toLowerCase();

  // ─── Brand Keywords for Title Mismatch Detection ───────────────────────────
  const BRAND_NAMES = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
    'twitter', 'instagram', 'netflix', 'linkedin', 'dropbox', 'github',
    'gmail', 'yahoo', 'outlook', 'chase', 'wellsfargo', 'bankofamerica',
    'coinbase', 'binance', 'steam', 'adobe', 'docusign', 'fedex', 'irs'
  ];

  // ─── Obfuscation Indicators ────────────────────────────────────────────────
  const OBFUSCATION_PATTERNS = [
    /eval\s*\(/,
    /unescape\s*\(/,
    /String\.fromCharCode\s*\(/,
    /atob\s*\(/,
    /\\x[0-9a-f]{2}/i,
    /\\u[0-9a-f]{4}/i,
    /document\.write\s*\(/,
    /\[\s*'[a-z]+'\s*\]\s*\(\s*\[/,  // Array obfuscation
    /(\w{1,3}\[(['"`])\w+\2\]){3,}/,  // Heavy bracket notation
  ];

  // ─── Suspicious Form Action Patterns ──────────────────────────────────────
  const SUSPICIOUS_FORM_PATTERNS = [
    /login|signin|sign-in|auth|account|verify|credential/i,
    /passwd|password|pwd/i,
    /\.php$/i,  // Many phishing pages use raw PHP
  ];

  /**
   * Analyze all forms on the page for phishing indicators.
   * @returns {{ hasFakeLoginForm: boolean, hasPasswordField: boolean, hasCredentialHarvesting: boolean, details: string[] }}
   */
  function analyzeForms() {
    const forms = document.querySelectorAll('form');
    let hasPasswordField = false;
    let hasFakeLoginForm = false;
    let hasCredentialHarvesting = false;
    const details = [];

    for (const form of forms) {
      const hasPassword = form.querySelector('input[type="password"]') !== null;
      const hasUsername = form.querySelector(
        'input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[id*="user"], input[id*="email"]'
      ) !== null;

      if (hasPassword) hasPasswordField = true;

      // A login form = has both password and username fields
      if (hasPassword && hasUsername) {
        // Check if form submits to a different domain (credential harvesting)
        const action = form.getAttribute('action') || '';
        if (action) {
          try {
            const actionURL = new URL(action, PAGE_URL);
            if (actionURL.hostname && actionURL.hostname !== PAGE_HOSTNAME) {
              hasCredentialHarvesting = true;
              details.push(`Form submits credentials to external domain: ${actionURL.hostname}`);
            }
          } catch { /* relative URLs are fine */ }
        }

        // Check if we're on an untrusted domain with a login form for a brand
        for (const brand of BRAND_NAMES) {
          const pageTitle = document.title.toLowerCase();
          if (
            (pageTitle.includes(brand) || PAGE_URL.toLowerCase().includes(brand)) &&
            !PAGE_HOSTNAME.includes(brand)
          ) {
            hasFakeLoginForm = true;
            details.push(`Login form impersonates ${brand} on untrusted domain`);
            break;
          }
        }

        // Mark as fake if HTTPS is missing and it has credentials
        if (!PAGE_URL.startsWith('https://')) {
          hasFakeLoginForm = true;
          details.push('Login form on non-HTTPS page — credentials sent in plaintext');
        }
      }

      // Check for hidden forms (method="post" with display:none)
      if (form.style.display === 'none' || form.style.visibility === 'hidden') {
        hasCredentialHarvesting = true;
        details.push('Hidden form detected — possible credential harvesting');
      }
    }

    return { hasFakeLoginForm, hasPasswordField, hasCredentialHarvesting, details };
  }

  /**
   * Scan for hidden iframes (potential clickjacking or content injection).
   * @returns {{ hasHiddenIframes: boolean, count: number }}
   */
  function analyzeIframes() {
    const iframes = document.querySelectorAll('iframe');
    let hiddenCount = 0;

    for (const iframe of iframes) {
      const style = window.getComputedStyle(iframe);
      const width = parseInt(style.width) || iframe.offsetWidth;
      const height = parseInt(style.height) || iframe.offsetHeight;

      // 1×1 pixel, hidden, or zero-dimension iframes
      if (
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        (width <= 1 && height <= 1) ||
        style.opacity === '0'
      ) {
        hiddenCount++;
      }
    }

    return { hasHiddenIframes: hiddenCount > 0, count: hiddenCount };
  }

  /**
   * Detect obfuscated JavaScript in inline scripts.
   * @returns {{ hasObfuscatedJS: boolean, count: number }}
   */
  function detectObfuscatedJS() {
    const scripts = document.querySelectorAll('script:not([src])');
    let count = 0;

    for (const script of scripts) {
      const content = script.textContent || '';
      const matched = OBFUSCATION_PATTERNS.filter(p => p.test(content));
      if (matched.length >= 2) {
        count++; // Multiple indicators = more suspicious
      }
    }

    return { hasObfuscatedJS: count > 0, count };
  }

  /**
   * Check for page title mismatch with domain (brand impersonation).
   * @returns {boolean}
   */
  function detectTitleMismatch() {
    const title = document.title.toLowerCase();
    for (const brand of BRAND_NAMES) {
      if (title.includes(brand) && !PAGE_HOSTNAME.includes(brand)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if the page has no favicon (common with quick phishing setups).
   * @returns {boolean}
   */
  function detectNoFavicon() {
    const links = document.querySelectorAll('link[rel*="icon"]');
    return links.length === 0;
  }

  /**
   * Check for mixed content (HTTP resources on HTTPS page).
   * @returns {boolean}
   */
  function detectMixedContent() {
    if (!PAGE_URL.startsWith('https://')) return false;
    const elements = document.querySelectorAll('script[src], link[href], img[src], iframe[src]');
    for (const el of elements) {
      const src = el.getAttribute('src') || el.getAttribute('href') || '';
      if (src.startsWith('http://')) return true;
    }
    return false;
  }

  /**
   * Run all content analysis checks and send signals to service worker.
   */
  function runAnalysis() {
    const formAnalysis = analyzeForms();
    const iframeAnalysis = analyzeIframes();
    const obfuscationAnalysis = detectObfuscatedJS();

    const signals = {
      hasFakeLoginForm: formAnalysis.hasFakeLoginForm,
      hasPasswordField: formAnalysis.hasPasswordField,
      hasCredentialHarvesting: formAnalysis.hasCredentialHarvesting,
      hasHiddenIframes: iframeAnalysis.hasHiddenIframes,
      hasObfuscatedJS: obfuscationAnalysis.hasObfuscatedJS,
      titleMismatch: detectTitleMismatch(),
      noFavicon: detectNoFavicon(),
      hasMixedContent: detectMixedContent(),
      formDetails: formAnalysis.details,
      pageTitle: document.title,
    };

    // Send to background service worker
    chrome.runtime.sendMessage({
      type: 'CONTENT_SIGNALS',
      payload: signals,
    }).catch(() => {
      // Extension context may be invalidated — fail silently
    });
  }

  // ─── DOM Ready Handler ───────────────────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runAnalysis);
  } else {
    // DOM already ready (content script injected late)
    runAnalysis();
  }

  // Re-run on dynamic DOM changes (for SPAs) with debounce
  let domChangeTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(domChangeTimer);
    domChangeTimer = setTimeout(runAnalysis, 1500);
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });

  // ─── Listen for background requests ─────────────────────────────────────
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'GET_PAGE_INFO') {
      return Promise.resolve({
        title: document.title,
        url: PAGE_URL,
        metaDescription: document.querySelector('meta[name="description"]')?.content || '',
      });
    }
  });

})();
