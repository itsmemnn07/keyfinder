// Provider framework for external reputation/enrichment
// Each provider must export an object with the following shape:
// {
//   name: string,               // identifier used in settings
//   canHandle: (indicator, type) => boolean,
//   request: async (indicator, apiKey) => Promise<{ status, verdict, reportUrl?, details? }>
// }
//
// The module maintains a registry of providers. Plugins can register themselves
// by calling `registerProvider(provider)`.

const providers = new Map();

export function registerProvider(provider) {
  if (!provider || typeof provider.name !== "string") {
    throw new Error("Provider must have a string `name` property");
  }
  providers.set(provider.name, provider);
}

export function getProvider(name) {
  return providers.get(name);
}

export function getAllProviders() {
  return Array.from(providers.values());
}

// Load built‑in provider adapters
// (paths are relative to the extension root)
importScripts(
  '/js/providers/virusTotal.js',
  '/js/providers/safeBrowsing.js',
  '/js/providers/anyRun.js',
  '/js/providers/urlscan.js',
  '/js/providers/phishTank.js',
  '/js/providers/otx.js',
  '/js/providers/securityTrails.js',
  '/js/providers/shodan.js',
  '/js/providers/censys.js',
  '/js/providers/openPhish.js'
);

// Export the registry for debugging (optional)
export const __registry = providers;
