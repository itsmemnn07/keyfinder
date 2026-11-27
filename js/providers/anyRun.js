import { registerProvider } from '/js/providers.js';

function canHandle(indicator, type) {
  // ANY.RUN supports URL submissions for sandbox analysis
  return type === 'url';
}

async function request(indicator, apiKey) {
  // Placeholder for ANY.RUN API call
  return {
    status: 'queued',
    verdict: 'unknown',
    reportUrl: '',
    details: `ANY.RUN placeholder for ${indicator}`,
  };
}

registerProvider({
  name: 'anyRun',
  canHandle,
  request,
});
