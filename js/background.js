if (typeof KeyFinderUtils === "undefined" && typeof importScripts === "function") {
  importScripts("/js/utils.js");
  importScripts("/js/providers.js");
}

const KEYWORDS_KEY = "kf_keywords";
const FINDINGS_KEY = "kf_findings";
const SETTINGS_KEY = "kf_settings";
const RECON_KEY = "kf_recon";
const MAX_FINDINGS = 5000;
const MAX_RECON_DOMAINS = 200;
const MAX_KEYWORDS = 50;
const MAX_KEYWORD_LENGTH = 50;
const VALID_STATUSES = new Set(["open", "acknowledged", "false_positive", "resolved"]);
const DEFAULT_SETTINGS = {
  paused: false,
  excludedDomains: [],
  external: {
    enabled: false,
    autoCheck: false,
    providers: {
      virusTotal: { enabled: false, apiKey: "" },
      safeBrowsing: { enabled: false, apiKey: "" },
      anyRun: { enabled: false, apiKey: "" },
      urlscan: { enabled: false, apiKey: "" },
      phishTank: { enabled: false, apiKey: "" },
      otx: { enabled: false, apiKey: "" },
      securityTrails: { enabled: false, apiKey: "" },
      shodan: { enabled: false, apiKey: "" },
      censys: { enabled: false, apiKey: "" },
      openPhish: { enabled: false }
    }
  }
};

const DEFAULT_KEYWORDS = [
  "key", "api_key", "apikey", "api-key", "secret", "token",
  "access_token", "auth", "credential", "password",
  "client_id", "client_secret"
];

// Serialize all storage writes to prevent race conditions
let storageQueue = Promise.resolve();
function enqueue(fn) {
  storageQueue = storageQueue.then(fn, fn);
  return storageQueue;
}

// --- Per-tab alert icon ---
const alertTabs = new Set();
let alertIconCache = null;

async function buildAlertIcons() {
  if (alertIconCache) return alertIconCache;
  const sizes = [16, 48];
  const imageData = {};
  for (const size of sizes) {
    const resp = await fetch(chrome.runtime.getURL(`icons/icon${size}.png`));
    const blob = await resp.blob();
    const bitmap = await createImageBitmap(blob);
    const canvas = new OffscreenCanvas(size, size);
    const ctx = canvas.getContext("2d");
    ctx.drawImage(bitmap, 0, 0, size, size);
    // Red alert dot in top-right
    const r = Math.max(3, Math.round(size * 0.22));
    const cx = size - r - 1;
    const cy = r + 1;
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.fillStyle = "#ff4444";
    ctx.fill();
    ctx.lineWidth = size >= 48 ? 2 : 1;
    ctx.strokeStyle = "#0f0f0f";
    ctx.stroke();
    imageData[size] = ctx.getImageData(0, 0, size, size);
  }
  alertIconCache = imageData;
  return imageData;
}

async function setAlertIcon(tabId) {
  if (alertTabs.has(tabId)) return;
  alertTabs.add(tabId);
  try {
    const imageData = await buildAlertIcons();
    await chrome.action.setIcon({ tabId, imageData });
  } catch {}
}

function resetTabIcon(tabId) {
  if (!alertTabs.delete(tabId)) return;
  try {
    chrome.action.setIcon({
      tabId,
      path: { "16": "icons/icon16.png", "48": "icons/icon48.png", "128": "icons/icon128.png" }
    });
  } catch {}
}

// Reset icon when a tab navigates to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    resetTabIcon(tabId);
  }
});

async function migrateFindings() {
  const findings = await getFindings();
  const normalized = findings.map((f) => KeyFinderUtils.normalizeFinding(f));
  await chrome.storage.local.set({ [FINDINGS_KEY]: normalized });
}

chrome.runtime.onStartup.addListener(() => {
  migrateFindings();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  alertTabs.delete(tabId);
});

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    await chrome.storage.local.set({
      [KEYWORDS_KEY]: DEFAULT_KEYWORDS,
      [FINDINGS_KEY]: [],
      [SETTINGS_KEY]: DEFAULT_SETTINGS,
    });
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "finding") {
    if (sender.tab?.id) setAlertIcon(sender.tab.id);
    enqueue(() => saveFinding(request.data)).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "getKeywords") {
    getKeywords().then((keywords) => sendResponse({ keywords }));
    return true;
  }
  if (request.type === "getFindings") {
    getFindings().then((findings) => sendResponse({ findings }));
    return true;
  }
  if (request.type === "addKeyword") {
    enqueue(() => addKeyword(request.keyword)).then((result) => sendResponse(result));
    return true;
  }
  if (request.type === "removeKeyword") {
    enqueue(() => removeKeyword(request.keyword)).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "removeFinding") {
    enqueue(() => removeFinding(request.findingId)).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "clearFindings") {
    enqueue(() => clearFindings()).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "exportFindings") {
    getFindings().then((findings) => sendResponse({ findings }));
    return true;
  }
  if (request.type === "getSettings") {
    getSettings().then((settings) => sendResponse({ settings }));
    return true;
  }
  if (request.type === "updateSettings") {
    enqueue(() => updateSettings(request.patch || {})).then((settings) => sendResponse({ ok: true, settings }));
    return true;
  }
  if (request.type === "updateFindingStatus") {
    enqueue(() => updateFindingStatus(request.findingId, request.status)).then((result) => sendResponse(result));
    return true;
  }
  if (request.type === "recon") {
    enqueue(() => saveRecon(request.data)).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "getRecon") {
    getRecon().then((recon) => sendResponse({ recon }));
    return true;
  }
  if (request.type === "clearRecon") {
    enqueue(() => clearRecon()).then(() => sendResponse({ ok: true }));
    return true;
  }
});

async function getKeywords() {
  const result = await chrome.storage.local.get(KEYWORDS_KEY);
  return result[KEYWORDS_KEY] || DEFAULT_KEYWORDS;
}

async function addKeyword(keyword) {
  const keywords = await getKeywords();
  const normalized = keyword.trim().toLowerCase();
  if (!normalized) return { ok: false, error: "Keyword cannot be empty." };
  if (normalized.length > MAX_KEYWORD_LENGTH) return { ok: false, error: `Keyword must be ${MAX_KEYWORD_LENGTH} characters or fewer.` };
  if (keywords.length >= MAX_KEYWORDS) return { ok: false, error: `Maximum of ${MAX_KEYWORDS} keywords allowed.` };
  if (keywords.includes(normalized)) return { ok: false, error: "Keyword already exists." };
  keywords.push(normalized);
  await chrome.storage.local.set({ [KEYWORDS_KEY]: keywords });
  return { ok: true };
}

async function removeKeyword(keyword) {
  const keywords = await getKeywords();
  await chrome.storage.local.set({ [KEYWORDS_KEY]: keywords.filter((k) => k !== keyword) });
}

async function getFindings() {
  const result = await chrome.storage.local.get(FINDINGS_KEY);
  return result[FINDINGS_KEY] || [];
}

async function saveFinding(finding) {
  // Normalize and store the finding (deduplication handled below)
  const findings = await getFindings();
  const normalized = KeyFinderUtils.normalizeFinding(finding);
  const dedupeKey = KeyFinderUtils.getFindingDedupeKey(normalized);
  const existingIdx = findings.findIndex(
    (f) => KeyFinderUtils.getFindingDedupeKey(KeyFinderUtils.normalizeFinding(f)) === dedupeKey
  );
  if (existingIdx !== -1) {
    const existing = KeyFinderUtils.normalizeFinding(findings[existingIdx]);
    existing.occurrenceCount = (existing.occurrenceCount || 1) + 1;
    existing.lastSeen = normalized.timestamp;
    // Update the stored entry
    findings[existingIdx] = existing;
  } else {
    findings.push(normalized);
  }
  await chrome.storage.local.set({ [FINDINGS_KEY]: findings });

  // *** External reputation check ***
  // If the finding is critical and high‑confidence, and auto‑check is on,
  // trigger external providers for the associated URL/domain/IP.
  try {
    const settings = (await chrome.storage.local.get(SETTINGS_KEY))[SETTINGS_KEY] || {};
    const ext = settings.external || {};
    if (ext.enabled && ext.autoCheck && normalized.riskLevel === 'critical' && normalized.confidence === 'high') {
      // Determine indicator type
      let indicator = normalized.url || normalized.domain || '';
      let type = 'url';
      if (indicator.startsWith('http')) {
        type = 'url';
      } else if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(indicator)) {
        type = 'ip';
      } else {
        type = 'domain';
      }
      // Dynamically import manager (works in service worker)
      importScripts('/js/providerManager.js');
      const results = await runExternalChecks(indicator, type);
      // Attach results to the finding (reconResults array)
      normalized.reconResults = results;
      // Persist updated finding
      await chrome.storage.local.set({ [FINDINGS_KEY]: findings });
    }
  } catch (e) {
    console.error('External recon error:', e);
  }

  return { ok: true };
}

  const findings = await getFindings();
  const normalized = KeyFinderUtils.normalizeFinding(finding);
  const dedupeKey = KeyFinderUtils.getFindingDedupeKey(normalized);

  const existingIdx = findings.findIndex(
    (f) => KeyFinderUtils.getFindingDedupeKey(KeyFinderUtils.normalizeFinding(f)) === dedupeKey
  );
  if (existingIdx !== -1) {
    const existing = KeyFinderUtils.normalizeFinding(findings[existingIdx]);
    existing.occurrenceCount = (existing.occurrenceCount || 1) + 1;
    existing.lastSeen = normalized.timestamp;
    findings[existingIdx] = existing;
    await chrome.storage.local.set({ [FINDINGS_KEY]: findings });
    return;
  }

  normalized.id = crypto.randomUUID();
  findings.push(normalized);

  // Evict oldest findings when cap is exceeded
  if (findings.length > MAX_FINDINGS) {
    findings.splice(0, findings.length - MAX_FINDINGS);
  }

  await chrome.storage.local.set({ [FINDINGS_KEY]: findings });

  const badgeCount = findings.length;
  chrome.action.setBadgeText({ text: badgeCount > 0 ? String(badgeCount) : "" });
  chrome.action.setBadgeBackgroundColor({ color: "#e74c3c" });
}

async function removeFinding(findingId) {
  const findings = await getFindings();
  const updated = findings.filter((f) => f.id !== findingId);
  await chrome.storage.local.set({ [FINDINGS_KEY]: updated });
  chrome.action.setBadgeText({ text: updated.length > 0 ? String(updated.length) : "" });
}

async function clearFindings() {
  await chrome.storage.local.set({ [FINDINGS_KEY]: [] });
  chrome.action.setBadgeText({ text: "" });
  for (const tabId of [...alertTabs]) {
    resetTabIcon(tabId);
  }
}

async function getSettings() {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const raw = result[SETTINGS_KEY] || {};
  return {
    paused: Boolean(raw.paused),
    excludedDomains: Array.isArray(raw.excludedDomains) ? raw.excludedDomains : [],
  };
}

async function updateSettings(patch) {
  const current = await getSettings();
  const next = {
    paused: typeof patch.paused === "boolean" ? patch.paused : current.paused,
    excludedDomains: Array.isArray(patch.excludedDomains)
      ? [...new Set(patch.excludedDomains.map((d) => String(d).trim().toLowerCase()).filter(Boolean))]
      : current.excludedDomains,
  };
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

async function updateFindingStatus(findingId, status) {
  if (!VALID_STATUSES.has(status)) {
    return { ok: false, error: "Invalid status." };
  }
  const findings = await getFindings();
  const idx = findings.findIndex((f) => f.id === findingId);
  if (idx === -1) return { ok: false, error: "Finding not found." };
  findings[idx] = { ...findings[idx], status };
  await chrome.storage.local.set({ [FINDINGS_KEY]: findings });
  return { ok: true };
}

async function getRecon() {
  const result = await chrome.storage.local.get(RECON_KEY);
  return result[RECON_KEY] || {};
}

async function saveRecon(payload) {
  if (!payload || !payload.domain) return;
  const recon = await getRecon();
  const domain = String(payload.domain).toLowerCase();
  const existing = recon[domain] || {
    domain,
    thirdPartyScripts: [],
    sourceMaps: [],
    endpoints: [],
    lastSeen: 0,
  };

  const mergeBy = (arr, items, keyFn, cap) => {
    const map = new Map(arr.map((x) => [keyFn(x), x]));
    for (const item of items || []) {
      map.set(keyFn(item), item);
      if (map.size >= cap) break;
    }
    return [...map.values()].slice(0, cap);
  };

  existing.thirdPartyScripts = mergeBy(existing.thirdPartyScripts, payload.thirdPartyScripts, (x) => x.origin, 50);
  existing.sourceMaps = mergeBy(existing.sourceMaps, payload.sourceMaps, (x) => x.mapUrl, 30);
  existing.endpoints = mergeBy(existing.endpoints, payload.endpoints, (x) => x, 80);
  existing.lastSeen = payload.timestamp || Date.now();
  recon[domain] = existing;

  const domains = Object.keys(recon);
  if (domains.length > MAX_RECON_DOMAINS) {
    domains.sort((a, b) => (recon[a].lastSeen || 0) - (recon[b].lastSeen || 0));
    for (const old of domains.slice(0, domains.length - MAX_RECON_DOMAINS)) {
      delete recon[old];
    }
  }

  await chrome.storage.local.set({ [RECON_KEY]: recon });
}

async function clearRecon() {
  await chrome.storage.local.set({ [RECON_KEY]: {} });
}
