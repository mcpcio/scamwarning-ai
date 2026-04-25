const API_BASE = 'https://api.scamwarning.ai';
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const CLEAN_THRESHOLD = 0; // total_signal_score below this = skip API
const CACHE_CLEANUP_ALARM = 'scamwarning-cache-cleanup';

// --- Install & Setup ---

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    const installId = crypto.randomUUID();
    await chrome.storage.local.set({
      installId: installId,
      settings: {
        alwaysOn: false,
        showBadge: true,
        showOnSafe: true
      },
      whitelist: [],
      assessmentCache: {}
    });
  }
  chrome.alarms.create(CACHE_CLEANUP_ALARM, { periodInMinutes: 30 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === CACHE_CLEANUP_ALARM) {
    await cleanExpiredCache();
  }
});

// --- Message Handlers ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PAGE_SIGNALS') {
    handlePageSignals(message.signals, sender.tab).then(result => {
      sendResponse(result || {});
    }).catch(() => sendResponse({}));
    return true;
  }

  if (message.type === 'PAGE_CONTENT') {
    handlePageContent(message.requestId, message.content).catch(() => {});
    return false;
  }

  if (message.type === 'GET_ASSESSMENT') {
    getAssessmentForTab(message.tabId).then(result => {
      sendResponse(result);
    }).catch(() => sendResponse(null));
    return true;
  }

  if (message.type === 'SUBMIT_CORRECTION') {
    submitCorrection(message.data).then(result => {
      sendResponse(result);
    }).catch(() => sendResponse({ success: false }));
    return true;
  }

  if (message.type === 'REQUEST_SCAN') {
    handleManualScan(sender.tab || message.tab).catch(() => {});
    return false;
  }
});

// --- Core Assessment Logic ---

async function handlePageSignals(signals, tab) {
  if (!tab || !tab.id) return {};

  const domain = signals.domain;
  if (!domain) return {};

  const { whitelist = [] } = await chrome.storage.local.get('whitelist');
  if (whitelist.includes(domain)) {
    await setIconState(tab.id, 'safe', { risk_level: 'safe', summary: 'Whitelisted domain' });
    return {};
  }

  const cached = await getCachedAssessment(domain);
  if (cached) {
    await setIconState(tab.id, cached.risk_level, cached);
    return {};
  }

  if (signals.total_signal_score <= CLEAN_THRESHOLD) {
    const cleanResult = {
      risk_score: 0,
      risk_level: 'safe',
      flags: [],
      summary: 'No suspicious patterns detected.',
      source: 'local',
      cached: false
    };
    await cacheAssessment(domain, cleanResult);
    await setIconState(tab.id, 'safe', cleanResult);
    return {};
  }

  const { settings = {} } = await chrome.storage.local.get('settings');
  const hasAlwaysOn = await checkAlwaysOnPermission();

  if (!settings.alwaysOn && !hasAlwaysOn) {
    await setIconState(tab.id, 'moderate', {
      risk_level: 'moderate',
      summary: 'Suspicious patterns detected. Click to scan.',
      flags: buildLocalFlags(signals),
      source: 'local_pending',
      signals: signals
    });
    return {};
  }

  return await performApiAssessment(signals, tab.id);
}

async function handleManualScan(tab) {
  if (!tab || !tab.id) return;

  const tabAssessment = await getAssessmentForTab(tab.id);

  if (tabAssessment && tabAssessment.signals) {
    await performApiAssessment(tabAssessment.signals, tab.id);
  } else {
    await setIconState(tab.id, 'default', {
      risk_level: 'unknown',
      summary: 'Unable to scan this page. Try refreshing.'
    });
  }
}

async function performApiAssessment(signals, tabId) {
  await setIconState(tabId, 'loading');

  try {
    const { installId } = await chrome.storage.local.get('installId');
    const hmac = await generateHmac(signals.domain + signals.content_hash);

    const response = await fetch(`${API_BASE}/assess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        install_id: installId,
        domain: signals.domain,
        page_title: signals.page_title,
        meta_description: signals.meta_description,
        content_hash: signals.content_hash,
        signals: {
          is_https: signals.is_https,
          form_count: signals.form_count,
          password_field_count: signals.password_field_count,
          external_link_count: signals.external_link_count,
          urgency_count: signals.urgency_count || 0,
          phishing_count: signals.phishing_count || 0,
          financial_fraud_count: signals.financial_fraud_count || 0,
          tech_support_count: signals.tech_support_count || 0,
          too_good_count: signals.too_good_count || 0,
          data_harvest_count: signals.data_harvest_count || 0,
          misleading_ads_count: signals.misleading_ads_count || 0,
          suspicious_commerce_count: signals.suspicious_commerce_count || 0,
          total_signal_score: signals.total_signal_score
        },
        hmac: hmac
      })
    });

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    const result = await response.json();

    if (result.needs_content) {
      return { needsContent: true, requestId: result.request_id };
    }

    await cacheAssessment(signals.domain, result);
    await setIconState(tabId, result.risk_level, result);
    return {};

  } catch (err) {
    const fallback = buildLocalOnlyAssessment(signals);
    await setIconState(tabId, fallback.risk_level, fallback);
    return {};
  }
}

async function handlePageContent(requestId, content) {
  try {
    const { installId } = await chrome.storage.local.get('installId');
    const hmac = await generateHmac(content.domain + requestId);

    const response = await fetch(`${API_BASE}/assess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        install_id: installId,
        request_id: requestId,
        domain: content.domain,
        body_text: content.body_text,
        hmac: hmac
      })
    });

    if (!response.ok) return;

    const result = await response.json();
    await cacheAssessment(content.domain, result);

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      const tabDomain = new URL(tab.url).hostname;
      if (tabDomain === content.domain) {
        await setIconState(tab.id, result.risk_level, result);
      }
    }
  } catch {}
}

// --- Correction ---

async function submitCorrection(data) {
  try {
    const { installId } = await chrome.storage.local.get('installId');
    const hmac = await generateHmac(data.domain + data.corrected_level);

    const response = await fetch(`${API_BASE}/correct`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        install_id: installId,
        domain: data.domain,
        original_score: data.original_score,
        corrected_level: data.corrected_level,
        note: (data.note || '').substring(0, 500),
        hmac: hmac
      })
    });

    if (response.ok) {
      await removeCachedAssessment(data.domain);
      return { success: true };
    }
    return { success: false };
  } catch {
    return { success: false };
  }
}

// --- Icon State ---

const ICON_PATHS = {
  default: {
    16: 'assets/icons/icon-default-16.png',
    32: 'assets/icons/icon-default-32.png',
    48: 'assets/icons/icon-default-48.png',
    128: 'assets/icons/icon-default-128.png'
  },
  safe: {
    16: 'assets/icons/icon-safe-16.png',
    32: 'assets/icons/icon-safe-32.png',
    48: 'assets/icons/icon-safe-48.png',
    128: 'assets/icons/icon-safe-128.png'
  },
  moderate: {
    16: 'assets/icons/icon-moderate-16.png',
    32: 'assets/icons/icon-moderate-32.png',
    48: 'assets/icons/icon-moderate-48.png',
    128: 'assets/icons/icon-moderate-128.png'
  },
  threat: {
    16: 'assets/icons/icon-threat-16.png',
    32: 'assets/icons/icon-threat-32.png',
    48: 'assets/icons/icon-threat-48.png',
    128: 'assets/icons/icon-threat-128.png'
  }
};

const BADGE_CONFIG = {
  safe: { text: '', color: '#22c55e' },
  moderate: { text: '!', color: '#f59e0b' },
  threat: { text: '!!', color: '#ef4444' },
  default: { text: '', color: '#6b7280' },
  loading: { text: '...', color: '#6b7280' }
};

async function setIconState(tabId, state, assessment) {
  const iconState = state === 'loading' ? 'default' : (ICON_PATHS[state] ? state : 'default');
  const badge = BADGE_CONFIG[state] || BADGE_CONFIG.default;

  try {
    await chrome.action.setIcon({ tabId, path: ICON_PATHS[iconState] });
    await chrome.action.setBadgeText({ tabId, text: badge.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });

    if (assessment) {
      const title = assessment.risk_level === 'safe'
        ? 'ScamWarning — Safe'
        : assessment.risk_level === 'threat'
          ? 'ScamWarning — Threat Detected!'
          : 'ScamWarning — Review Recommended';
      await chrome.action.setTitle({ tabId, title });

      await chrome.storage.local.set({
        [`tab_${tabId}`]: assessment
      });
    }
  } catch {}
}

// --- Cache ---

async function getCachedAssessment(domain) {
  const { assessmentCache = {} } = await chrome.storage.local.get('assessmentCache');
  const entry = assessmentCache[domain];
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) return null;
  return entry.data;
}

async function cacheAssessment(domain, data) {
  const { assessmentCache = {} } = await chrome.storage.local.get('assessmentCache');
  assessmentCache[domain] = { data, timestamp: Date.now() };
  await chrome.storage.local.set({ assessmentCache });
}

async function removeCachedAssessment(domain) {
  const { assessmentCache = {} } = await chrome.storage.local.get('assessmentCache');
  delete assessmentCache[domain];
  await chrome.storage.local.set({ assessmentCache });
}

async function cleanExpiredCache() {
  const { assessmentCache = {} } = await chrome.storage.local.get('assessmentCache');
  const now = Date.now();
  let cleaned = 0;
  for (const [domain, entry] of Object.entries(assessmentCache)) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      delete assessmentCache[domain];
      cleaned++;
    }
  }
  if (cleaned > 0) {
    await chrome.storage.local.set({ assessmentCache });
  }
}

async function getAssessmentForTab(tabId) {
  const result = await chrome.storage.local.get(`tab_${tabId}`);
  return result[`tab_${tabId}`] || null;
}

// --- Helpers ---

function buildLocalFlags(signals) {
  const flags = [];
  if (signals.phishing_count > 0) flags.push('Potential phishing language detected');
  if (signals.financial_fraud_count > 0) flags.push('Financial fraud indicators found');
  if (signals.tech_support_count > 0) flags.push('Tech support scam patterns detected');
  if (signals.urgency_count > 0) flags.push('Urgency manipulation tactics present');
  if (signals.too_good_count > 0) flags.push('Too-good-to-be-true claims found');
  if (signals.data_harvest_count > 0) flags.push('Excessive personal data requests');
  if (signals.misleading_ads_count > 0) flags.push('Misleading advertising patterns');
  if (!signals.is_https) flags.push('No HTTPS encryption');
  if (signals.password_field_count > 0 && !signals.is_https) flags.push('Password field on insecure page');
  return flags.slice(0, 5);
}

function buildLocalOnlyAssessment(signals) {
  const flags = buildLocalFlags(signals);
  const score = Math.min(100, Math.round(signals.total_signal_score * 3));
  let level = 'safe';
  if (score > 50) level = 'threat';
  else if (score > 20) level = 'moderate';

  return {
    risk_score: score,
    risk_level: level,
    flags: flags,
    summary: level === 'safe'
      ? 'No significant threats detected.'
      : level === 'threat'
        ? 'Multiple scam indicators detected. Exercise caution.'
        : 'Some suspicious patterns found. Review before proceeding.',
    source: 'local_only',
    cached: false
  };
}

async function checkAlwaysOnPermission() {
  return new Promise((resolve) => {
    chrome.permissions.contains({ origins: ['<all_urls>'] }, resolve);
  });
}

async function generateHmac(data) {
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBytes);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Clean up tab assessment data when tabs close
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await chrome.storage.local.remove(`tab_${tabId}`);
});
