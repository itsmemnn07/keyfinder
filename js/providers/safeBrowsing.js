import { registerProvider } from '/js/providers.js';

function canHandle(indicator, type) {
  // Safe Browsing works with URLs only
  return type === 'url';
}

async function request(indicator, apiKey) {
  // Placeholder for Google Safe Browsing API call
  return {
    status: 'queued',
    verdict: 'unknown',
    reportUrl: '',
    details: `Safe Browsing placeholder for ${indicator}`,
  };
}

registerProvider({
  name: 'safeBrowsing',
  canHandle,
  request,
});
