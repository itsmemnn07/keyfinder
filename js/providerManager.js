// Provider manager – orchestrates external reputation checks
// It reads the `external` settings, selects enabled providers, filters
// indicators by provider capability, deduplicates requests, and caches
// results for a bounded TTL (default 1 hour). This is a lightweight stub
// sufficient for the current task; real rate‑limit handling will be added later.

importScripts('/js/providers.js'); // ensure registry is loaded

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const cache = new Map(); // key -> { result, expires }

function isUrl(str) {
  try { new URL(str); return true; } catch { return false; }
}
function isIp(str) {
  // simple IPv4/IPv6 detection
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(str) || /^[0-9a-fA-F:]+$/.test(str);
}

export async function runExternalChecks(indicator, type) {
  // `type` can be "url", "domain", "ip" – callers decide based on indicator
  // Retrieve settings from storage
  const { ["kf_settings"]: settings = {} } = await chrome.storage.local.get('kf_settings');
  const ext = settings.external || {};
  if (!ext.enabled) return [];

  const enabledProviders = Object.entries(ext.providers || {})
    .filter(([, cfg]) => cfg.enabled)
    .map(([name]) => getProvider(name))
    .filter(Boolean);

  const results = [];
  for (const provider of enabledProviders) {
    if (!provider.canHandle(indicator, type)) continue;
    const cacheKey = `${provider.name}|${indicator}`;
    const now = Date.now();
    const cached = cache.get(cacheKey);
    if (cached && cached.expires > now) {
      results.push({ provider: provider.name, ...cached.result });
      continue;
    }
    try {
      const apiKey = (ext.providers[provider.name] || {}).apiKey || '';
      const resp = await provider.request(indicator, apiKey);
      cache.set(cacheKey, { result: resp, expires: now + CACHE_TTL_MS });
      results.push({ provider: provider.name, ...resp });
    } catch (e) {
      results.push({ provider: provider.name, status: 'error', verdict: 'error', error: e.message });
    }
  }
  return results;
}

// Helper to expose registry (optional for debugging)
export const __registry = getAllProviders();
