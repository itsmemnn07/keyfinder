document.addEventListener("DOMContentLoaded", init);

const REDUCE_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

let lastKeywords = 0;
let lastFindings = 0;
let termBooted = false;
let currentSettings = { paused: false, excludedDomains: [] };
let activeDomain = "";

async function init() {
  const versionLabel = document.getElementById("versionLabel");
  if (versionLabel) versionLabel.textContent = "v" + chrome.runtime.getManifest().version;
  await loadActiveDomain();
  await renderSettings();
  await renderKeywords();
  await renderStats();
  updateTermLine(true);
  termBooted = true;
  document.getElementById("keywordForm").addEventListener("submit", handleAddKeyword);
  document.getElementById("pauseBtn").addEventListener("click", handleTogglePause);
  document.getElementById("excludeSiteBtn").addEventListener("click", handleToggleExcludeSite);
}

/* eased count-up for stat numerals */
function setNumber(el, target) {
  if (!el) return;
  const from = parseInt(el.textContent, 10);
  const start = Number.isFinite(from) ? from : 0;
  if (REDUCE_MOTION || start === target) {
    el.textContent = target;
    return;
  }
  const duration = 380;
  const t0 = performance.now();
  (function tick(t) {
    const p = Math.min(1, (t - t0) / duration);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(start + (target - start) * eased);
    if (p < 1) requestAnimationFrame(tick);
  })(t0);
}

/* terminal status line — types once per popup open, instant after */
function updateTermLine(typed) {
  const el = document.getElementById("termText");
  if (!el) return;
  const text = `kf> scan armed :: ${lastKeywords} keywords :: ${lastFindings} findings`;
  if (!typed || REDUCE_MOTION) {
    el.textContent = text;
    return;
  }
  let i = 0;
  (function type() {
    el.textContent = text.slice(0, ++i);
    if (i < text.length) setTimeout(type, 14);
  })();
}

async function renderKeywords() {
  const response = await chrome.runtime.sendMessage({ type: "getKeywords" });
  const keywords = response.keywords || [];
  const list = document.getElementById("keywordList");
  list.innerHTML = "";

  lastKeywords = keywords.length;
  setNumber(document.getElementById("keywordCount"), keywords.length);
  if (termBooted) updateTermLine(false);

  if (keywords.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.textContent = "no keywords configured";
    list.appendChild(empty);
    return;
  }

  for (const kw of keywords) {
    const li = document.createElement("li");
    li.className = "keyword-item";

    const label = document.createElement("span");
    label.className = "keyword-label";
    label.textContent = kw;

    const removeBtn = document.createElement("button");
    removeBtn.className = "keyword-remove";
    removeBtn.textContent = "×";
    removeBtn.title = `Remove "${kw}"`;
    removeBtn.addEventListener("click", () => handleRemoveKeyword(kw));

    li.appendChild(label);
    li.appendChild(removeBtn);
    list.appendChild(li);
  }
}

async function renderStats() {
  const response = await chrome.runtime.sendMessage({ type: "getFindings" });
  const findings = response.findings || [];
  lastFindings = findings.length;
  setNumber(document.getElementById("findingCount"), findings.length);
  if (termBooted) updateTermLine(false);
}

async function handleAddKeyword(e) {
  e.preventDefault();
  const input = document.getElementById("keywordInput");
  const errorMsg = document.getElementById("errorMsg");
  const keyword = input.value.trim();

  errorMsg.hidden = true;

  if (!keyword) {
    showError("Keyword cannot be empty.");
    return;
  }

  const result = await chrome.runtime.sendMessage({ type: "addKeyword", keyword });

  if (!result.ok) {
    showError(result.error);
    return;
  }

  input.value = "";
  input.focus();
  await renderKeywords();
}

async function handleRemoveKeyword(keyword) {
  await chrome.runtime.sendMessage({ type: "removeKeyword", keyword });
  await renderKeywords();
}

async function loadActiveDomain() {
  try {
    if (!chrome.tabs || !chrome.tabs.query) return;
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tabs && tabs[0] && tabs[0].url;
    if (url && url.startsWith("http")) {
      activeDomain = new URL(url).hostname.toLowerCase();
    }
  } catch {}
}

async function renderSettings() {
  const resp = await chrome.runtime.sendMessage({ type: "getSettings" });
  currentSettings = (resp && resp.settings) || { paused: false, excludedDomains: [] };

  const badge = document.getElementById("liveBadge");
  const badgeText = document.getElementById("liveBadgeText");
  const pauseBtn = document.getElementById("pauseBtn");
  const excludeBtn = document.getElementById("excludeSiteBtn");

  if (badgeText) badgeText.textContent = currentSettings.paused ? "PAUSED" : "ARMED";
  if (badge) badge.classList.toggle("paused", currentSettings.paused);
  if (pauseBtn) pauseBtn.textContent = currentSettings.paused ? "Resume Scan" : "Pause Scan";

  if (excludeBtn) {
    if (!activeDomain) {
      excludeBtn.disabled = true;
      excludeBtn.textContent = "Exclude Site";
    } else {
      excludeBtn.disabled = false;
      const excluded = currentSettings.excludedDomains.includes(activeDomain);
      excludeBtn.textContent = excluded ? `Include ${activeDomain}` : `Exclude ${activeDomain}`;
    }
  }

  const list = document.getElementById("excludedList");
  if (list) {
    list.innerHTML = "";
    for (const domain of currentSettings.excludedDomains) {
      const li = document.createElement("li");
      li.className = "excluded-chip";
      const span = document.createElement("span");
      span.textContent = domain;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = "×";
      btn.title = `Remove ${domain} from exclusions`;
      btn.addEventListener("click", async () => {
        const next = currentSettings.excludedDomains.filter((d) => d !== domain);
        await chrome.runtime.sendMessage({ type: "updateSettings", patch: { excludedDomains: next } });
        await renderSettings();
      });
      li.appendChild(span);
      li.appendChild(btn);
      list.appendChild(li);
    }
  }
}

async function handleTogglePause() {
  await chrome.runtime.sendMessage({
    type: "updateSettings",
    patch: { paused: !currentSettings.paused },
  });
  await renderSettings();
}

async function handleToggleExcludeSite() {
  if (!activeDomain) return;
  const exists = currentSettings.excludedDomains.includes(activeDomain);
  const next = exists
    ? currentSettings.excludedDomains.filter((d) => d !== activeDomain)
    : [...currentSettings.excludedDomains, activeDomain];
  await chrome.runtime.sendMessage({ type: "updateSettings", patch: { excludedDomains: next } });
  await renderSettings();
}

function showError(msg) {
  const errorMsg = document.getElementById("errorMsg");
  errorMsg.textContent = msg;
  errorMsg.hidden = false;
  setTimeout(() => { errorMsg.hidden = true; }, 3000);
}
