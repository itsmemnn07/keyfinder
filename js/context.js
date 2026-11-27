(function (root) {
  "use strict";

  const DOCS_HOSTS = new Set([
    "github.com", "gist.github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com", "developer.mozilla.org",
    "npmjs.com", "www.npmjs.com", "pypi.org", "codepen.io", "jsfiddle.net",
  ]);

  const PLACEHOLDER_WORDS = [
    "example", "dummy", "mock", "sample", "placeholder", "changeme",
    "replace_me", "insert_here", "your_api_key", "your-api-key",
    "your_secret", "your_token", "fake", "redacted", "not_a_secret",
    "test_key", "testkey", "demo_",
  ];

  const PUBLIC_BY_DESIGN_PATTERNS = new Set([
    "Stripe Publishable Key",
    "Sentry DSN",
    "Mapbox Public Token",
    "Google OAuth Client ID",
    "Firebase Database URL",
    "AWS Cognito Pool ID",
    "Twilio Account SID",
    "New Relic Browser Key",
  ]);

  /**
   * Classify the page's runtime environment from its URL.
   * @param {string} pageUrl
   * @returns {{ environment: string, protocol: string, hostname: string }}
   */
  function classifyEnvironment(pageUrl) {
    let hostname = "";
    let pathname = "";
    let protocol = "";
    try {
      const u = new URL(pageUrl);
      hostname = (u.hostname || "").toLowerCase();
      pathname = (u.pathname || "").toLowerCase();
      protocol = (u.protocol || "").toLowerCase();
    } catch {
      return { environment: "production", protocol: "", hostname: "" };
    }

    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "[::1]" ||
      hostname === "0.0.0.0" ||
      /\.(local|localhost|test|internal)$/i.test(hostname)
    ) {
      return { environment: "localhost", protocol, hostname };
    }

    if (
      DOCS_HOSTS.has(hostname) ||
      /^(docs|swagger|redoc|developer|learn|wiki)\./i.test(hostname) ||
      /\/(docs|documentation|examples|tutorial|tutorials|swagger|redoc)\b/i.test(pathname)
    ) {
      return { environment: "docs-example", protocol, hostname };
    }

    if (/(^|\.)(dev|staging|stage|qa|uat|sandbox|preview|demo)(\.|$)/i.test(hostname)) {
      return { environment: "dev-staging", protocol, hostname };
    }

    return { environment: "production", protocol, hostname };
  }

  /**
   * Decode a base64url string into UTF-8 text without throwing.
   * @param {string} seg
   * @returns {string|null}
   */
  function decodeBase64Url(seg) {
    if (!seg) return null;
    try {
      const b64 = seg.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((seg.length + 3) % 4);
      if (typeof atob === "function") {
        return atob(b64);
      }
      if (typeof Buffer !== "undefined") {
        return Buffer.from(b64, "base64").toString("utf8");
      }
    } catch {}
    return null;
  }

  /**
   * Inspect a JWT locally for header algorithm and expiration metadata.
   * @param {string} token
   * @returns {object|null}
   */
  function inspectJwt(token) {
    if (!token || typeof token !== "string") return null;
    const parts = token.trim().split(".");
    if (parts.length !== 3) return null;

    try {
      const headerRaw = decodeBase64Url(parts[0]);
      const payloadRaw = decodeBase64Url(parts[1]);
      if (!headerRaw || !payloadRaw) return null;

      const header = JSON.parse(headerRaw);
      const payload = JSON.parse(payloadRaw);
      if (!header || typeof header !== "object" || !payload || typeof payload !== "object") {
        return null;
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const hasExp = typeof payload.exp === "number";
      const expired = hasExp ? payload.exp < nowSec : false;
      const alg = typeof header.alg === "string" ? header.alg : "";
      const sensitiveClaims = ["email", "role", "admin", "scope", "permissions"].filter(
        (k) => k in payload
      );

      return {
        validStructure: true,
        alg,
        weakAlg: alg.toLowerCase() === "none",
        hasExp,
        expired,
        sensitiveClaims,
      };
    } catch {
      return { validStructure: false, alg: "", weakAlg: false, hasExp: false, expired: false, sensitiveClaims: [] };
    }
  }

  /**
   * Extract a safe bounded snippet (secret replaced by [MATCH]) and key context around a text match.
   * @param {string} text
   * @param {number} matchIndex
   * @param {number} matchLength
   * @param {string} matchedValue
   * @returns {{ snippet: string, keyName: string, inComment: boolean, isMinified: boolean }}
   */
  function extractTextContext(text, matchIndex, matchLength, matchedValue) {
    if (!text || typeof matchIndex !== "number" || matchIndex < 0) {
      return { snippet: "", keyName: "", inComment: false, isMinified: false };
    }

    const start = Math.max(0, matchIndex - 60);
    const end = Math.min(text.length, matchIndex + matchLength + 60);
    const before = text.slice(start, matchIndex);
    const rawSlice = text.slice(matchIndex, matchIndex + matchLength);
    const after = text.slice(matchIndex + matchLength, end);

    const safeSegment = matchedValue && rawSlice.includes(matchedValue)
      ? rawSlice.replace(matchedValue, "[MATCH]")
      : "[MATCH]";

    const snippet = (before + safeSegment + after)
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 160);

    // Infer surrounding variable/property name right before the match
    let keyName = "";
    const keyMatch = before.match(/([A-Za-z0-9_.-]{2,48})['"]?\s*[:=]\s*['"`]?\s*$/);
    if (keyMatch) {
      keyName = keyMatch[1];
    }

    // Check line bounds around the match for comment or minified bundle detection
    const lineStart = text.lastIndexOf("\n", matchIndex) + 1;
    let lineEnd = text.indexOf("\n", matchIndex);
    if (lineEnd === -1) lineEnd = text.length;
    const lineLen = lineEnd - lineStart;
    const lineBefore = text.slice(lineStart, matchIndex);

    const inComment =
      /^\s*(\/\/|\/\*|\*|#|<!--)/.test(lineBefore) ||
      (before.includes("/*") && !before.slice(before.lastIndexOf("/*")).includes("*/")) ||
      (before.includes("<!--") && !before.slice(before.lastIndexOf("<!--")).includes("-->"));

    return {
      snippet,
      keyName,
      inComment,
      isMinified: lineLen > 500,
    };
  }

  /**
   * Detect test, placeholder, or low-diversity signals on a finding and its surrounding text.
   * @param {object} input
   * @returns {string[]}
   */
  function detectPlaceholderSignals({ match = "", keyName = "", snippet = "", patternName = "" }) {
    const signals = [];
    const m = String(match);
    const combined = `${m} ${keyName} ${snippet}`.toLowerCase();

    if (/^(sk|pk|rk)_test_/i.test(m)) {
      signals.push("test-prefix");
    }
    if (m === "AKIAIOSFODNN7EXAMPLE" || /^AIzaSyDummy/i.test(m)) {
      signals.push("example-key");
    }
    if (PLACEHOLDER_WORDS.some((w) => combined.includes(w))) {
      signals.push("placeholder-word");
    }
    if (/(.)\1{6,}|012345|123456|abcdef/i.test(m)) {
      signals.push("repeated-pattern");
    }
    if (PUBLIC_BY_DESIGN_PATTERNS.has(patternName)) {
      signals.push("public-by-design");
    }
    return [...new Set(signals)];
  }

  /**
   * Build the full context object attached to a candidate finding.
   * @param {object} input
   * @returns {object}
   */
  function analyzeContext(input) {
    const env = classifyEnvironment(input.pageUrl || input.url || "");
    const type = input.type || "";
    const inComment = Boolean(input.inComment || type === "html-comment");
    const keyName = (input.keyName || "").slice(0, 64);
    const snippet = (input.snippet || "").slice(0, 160);
    const placeholderSignals = detectPlaceholderSignals({
      match: input.match,
      keyName,
      snippet,
      patternName: input.patternName,
    });
    const jwtMeta =
      input.patternName === "JSON Web Token" || /^eyJhbGci/i.test(input.match || "")
        ? inspectJwt(input.match)
        : null;

    return {
      environment: env.environment,
      protocol: env.protocol,
      surface: type,
      keyName,
      snippet,
      inComment,
      isMinified: Boolean(input.isMinified),
      placeholderSignals,
      jwtMeta,
    };
  }

  /**
   * Conservative hard filter for clear generic false positives.
   * Structured vendor secrets with test/example markers are kept and downgraded instead.
   * @param {object} finding
   * @param {object} context
   * @param {function} [entropyFn]
   * @returns {boolean}
   */
  function shouldSuppressFinding(finding, context, entropyFn) {
    const provider = finding.provider || "";
    const match = String(finding.match || "");
    const signals = (context && context.placeholderSignals) || [];
    const entropy = typeof entropyFn === "function" ? entropyFn(match) : null;

    const isGeneric = provider === "Generic" || provider === "Keyword Match";

    // Generic keyword/regex matches with obvious placeholder text and low entropy are noise
    if (isGeneric && signals.includes("placeholder-word") && entropy !== null && entropy < 2.8) {
      return true;
    }

    // Generic keyword matches inside minified JS bundles with low entropy are usually bundle labels
    if (provider === "Keyword Match" && context && context.isMinified && entropy !== null && entropy < 3.2) {
      return true;
    }

    // Repeated synthetic blocks on generic matches (non-vendor-prefixed)
    if (isGeneric && signals.includes("repeated-pattern") && entropy !== null && entropy < 2.6) {
      return true;
    }

    return false;
  }

  const api = {
    PUBLIC_BY_DESIGN_PATTERNS,
    classifyEnvironment,
    inspectJwt,
    extractTextContext,
    detectPlaceholderSignals,
    analyzeContext,
    shouldSuppressFinding,
  };

  root.KeyFinderContext = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);
