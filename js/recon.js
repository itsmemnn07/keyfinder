(function (root) {
  "use strict";

  const MAX_ENDPOINTS_PER_SCAN = 30;
  const MAX_SOURCEMAPS_PER_SCAN = 20;

  /**
   * Passively detect sourceMappingURL comments in already-fetched/inline script text.
   * Does not perform any outbound requests.
   * @param {string} text
   * @param {string} sourceUrl
   * @returns {Array<{ sourceUrl: string, mapUrl: string }>}
   */
  function extractSourceMapRefs(text, sourceUrl) {
    if (!text || text.length < 20) return [];
    const refs = [];
    const seen = new Set();
    const re = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)|\/\*[#@]\s*sourceMappingURL=([^\s*'"]+)\s*\*\//g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const mapRef = (m[1] || m[2] || "").trim();
      if (!mapRef || mapRef.startsWith("data:") || seen.has(mapRef)) continue;
      seen.add(mapRef);
      let resolved = mapRef;
      try {
        resolved = new URL(mapRef, sourceUrl).href;
      } catch {}
      refs.push({ sourceUrl: sourceUrl || "", mapUrl: resolved });
      if (refs.length >= MAX_SOURCEMAPS_PER_SCAN) break;
    }
    return refs;
  }

  /**
   * Extract high-signal API/auth/admin/websocket endpoint references from script/response text.
   * @param {string} text
   * @returns {string[]}
   */
  function extractHighSignalEndpoints(text) {
    if (!text || text.length < 10) return [];
    const found = new Set();
    const relRe = /['"`](\/(?:api|v[1-9]|auth|oauth|admin|internal|graphql|webhook)[a-zA-Z0-9_\-./{}:]{1,100})['"`]/g;
    const wsRe = /['"`](wss?:\/\/[a-zA-Z0-9.-]+(?::[0-9]+)?\/[^\s'"`]{0,100})['"`]/g;

    let m;
    while ((m = relRe.exec(text)) !== null) {
      found.add(m[1]);
      if (found.size >= MAX_ENDPOINTS_PER_SCAN) return [...found];
    }
    while ((m = wsRe.exec(text)) !== null) {
      found.add(m[1]);
      if (found.size >= MAX_ENDPOINTS_PER_SCAN) return [...found];
    }
    return [...found];
  }

  /**
   * Inventory unique third-party script origins and SRI usage from a document.
   * @param {Document} doc
   * @param {string} pageOrigin
   * @returns {Array<{ origin: string, hasSri: boolean }>}
   */
  function collectThirdPartyScripts(doc, pageOrigin) {
    if (!doc || !doc.querySelectorAll) return [];
    const byOrigin = new Map();
    const scripts = doc.querySelectorAll("script[src]");
    for (const s of scripts) {
      try {
        const u = new URL(s.src, pageOrigin);
        if (u.origin === pageOrigin || u.protocol === "chrome-extension:" || u.protocol === "moz-extension:") {
          continue;
        }
        const prev = byOrigin.get(u.origin);
        const hasSri = Boolean(s.integrity);
        if (!prev) {
          byOrigin.set(u.origin, { origin: u.origin, hasSri });
        } else if (!hasSri) {
          // Mark false if any script from this origin lacks SRI
          prev.hasSri = false;
        }
      } catch {}
    }
    return [...byOrigin.values()];
  }

  const api = {
    extractSourceMapRefs,
    extractHighSignalEndpoints,
    collectThirdPartyScripts,
  };

  root.KeyFinderRecon = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);
