(function (root) {
  "use strict";

  /**
   * Compute Shannon entropy (bits per character) of a string.
   * @param {string} str
   * @returns {number}
   */
  function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const freq = Object.create(null);
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Return true when a string has enough length and randomness to resemble a secret.
   * @param {string} str
   * @param {number} [minLen=12]
   * @param {number} [threshold=3.5]
   * @returns {boolean}
   */
  function isHighEntropy(str, minLen = 12, threshold = 3.5) {
    if (!str || str.length < minLen) return false;
    return shannonEntropy(str) > threshold;
  }

  /**
   * Resolve a potentially relative URL against a base URL without throwing.
   * @param {string} rawUrl
   * @param {string} [baseUrl]
   * @returns {string}
   */
  function normalizeUrl(rawUrl, baseUrl) {
    const raw = rawUrl == null ? "" : String(rawUrl).trim();
    if (!raw) return baseUrl ? String(baseUrl) : "";
    try {
      return baseUrl ? new URL(raw, baseUrl).href : new URL(raw).href;
    } catch {
      return raw;
    }
  }

  /**
   * Mask a secret value for safe display/export while keeping recognizable edges.
   * @param {string} value
   * @returns {string}
   */
  function maskSecret(value) {
    const str = value == null ? "" : String(value);
    if (str.length <= 8) return "*".repeat(str.length || 4);
    const head = Math.min(6, Math.floor(str.length / 4));
    const tail = 4;
    if (head + tail >= str.length) return str.slice(0, 2) + "****" + str.slice(-2);
    return str.slice(0, head) + "****" + str.slice(-tail);
  }

  /**
   * Normalize a finding object to Schema v2 while preserving v1 backward compatibility.
   * @param {object} raw
   * @returns {object}
   */
  function normalizeFinding(raw) {
    const now = Date.now();
    const ts = typeof raw.timestamp === "number" ? raw.timestamp : now;
    const pageUrl = normalizeUrl(raw.pageUrl || "");
    const url = normalizeUrl(raw.url || pageUrl, pageUrl || undefined);
    let domain = raw.domain || "";
    if (!domain && (pageUrl || url)) {
      try {
        domain = new URL(pageUrl || url).hostname;
      } catch {}
    }

    const severity = raw.severity || "medium";
    return {
      ...raw,
      schemaVersion: 2,
      url,
      pageUrl: pageUrl || url,
      domain,
      severity,
      confidence: raw.confidence || "medium",
      timestamp: ts,
      firstSeen: typeof raw.firstSeen === "number" ? raw.firstSeen : ts,
      lastSeen: typeof raw.lastSeen === "number" ? raw.lastSeen : ts,
      occurrenceCount: typeof raw.occurrenceCount === "number" && raw.occurrenceCount >= 1 ? raw.occurrenceCount : 1,
      status: raw.status || "open",
      riskScore: typeof raw.riskScore === "number" ? raw.riskScore : null,
      riskLevel: raw.riskLevel || severity,
      riskFactors: Array.isArray(raw.riskFactors) ? raw.riskFactors : [],
      context: raw.context || null,
      reconResults: Array.isArray(raw.reconResults) ? raw.reconResults : [],
      duplicateGroupId: raw.duplicateGroupId || null,
    };
  }

  /**
   * Build a deterministic deduplication key scoped by domain, normalized URL, pattern, and match.
   * @param {object} finding
   * @returns {string}
   */
  function getFindingDedupeKey(finding) {
    return [
      finding.domain || "",
      finding.url || "",
      finding.patternName || "",
      finding.match || "",
    ].join("\0");
  }

  const api = {
    shannonEntropy,
    isHighEntropy,
    normalizeUrl,
    maskSecret,
    normalizeFinding,
    getFindingDedupeKey,
  };

  root.KeyFinderUtils = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);
