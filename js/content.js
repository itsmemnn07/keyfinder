(async function () {
  "use strict";

  const pageUrl = location.href;
  const pageDomain = location.hostname;
  const seen = new Set();
  const fetchedScripts = new Set();
  const { shannonEntropy, isHighEntropy, normalizeUrl } = KeyFinderUtils;
  const ContextEngine = typeof KeyFinderContext !== "undefined" ? KeyFinderContext : null;
  const RiskEngine = typeof KeyFinderRisk !== "undefined" ? KeyFinderRisk : null;
  const ReconEngine = typeof KeyFinderRecon !== "undefined" ? KeyFinderRecon : null;
  const reconSourceMaps = [];
  const reconEndpoints = new Set();

  let keywords = [];
  let settings = { paused: false, excludedDomains: [] };
  try {
    const [kwResp, setResp] = await Promise.all([
      chrome.runtime.sendMessage({ type: "getKeywords" }),
      chrome.runtime.sendMessage({ type: "getSettings" }),
    ]);
    keywords = ((kwResp && kwResp.keywords) || []).map((k) => k.toLowerCase());
    if (setResp && setResp.settings) settings = setResp.settings;
  } catch {
    return;
  }

  const hostLower = pageDomain.toLowerCase();
  const isExcluded = (settings.excludedDomains || []).some(
    (d) => hostLower === d || hostLower.endsWith("." + d)
  );
  if (settings.paused || isExcluded) {
    return;
  }

  // Shared allowlists used by both initial DOM scan and MutationObserver
  const CSRF_INPUT_NAMES = [
    "authenticity_token", "csrf_token", "csrf", "_csrf", "__requestverificationtoken",
    "csrfmiddlewaretoken", "react-codespace-csrf", "_token", "xsrf-token", "anticsrf",
  ];
  const BENIGN_INPUT_NAMES = [
    "return_to", "redirect", "redirect_uri", "next", "ref", "referer",
    "utm_source", "utm_medium", "utm_campaign", "notice_name", "host", "method",
    "pinned_items_id_and_type[]", "repo_topics[]", "timestamp_secret",
  ];
  const SENSITIVE_INPUT_NAMES = [
    "api_key", "apikey", "secret_key", "access_token", "private_key", "password",
  ];
  const IGNORED_DATA_ATTRS = [
    "data-hotkey", "data-hotkey-scope", "data-hotkey-within",
    "data-provider-key",
    "data-pjax-key", "data-turbo-key",
  ];

  function isFalsePositive(match) {
    if (!match || match.length < 8) return true;
    const lower = match.toLowerCase();
    const fp = [
      "true", "false", "null", "undefined", "function", "return",
      "window", "document", "object", "string", "number", "boolean",
      "prototype", "constructor", "adsbygoogle", "googletag",
      "use strict", "text/javascript", "application/json",
      "content-type", "text/html", "text/css", "image/png",
      "image/jpeg", "charset=utf-8", "viewport", "width=device",
      "http-equiv", "stylesheet", "text/plain",
    ];
    for (const f of fp) {
      if (lower === f) return true;
    }
    if (/^(0+|1+|a+|f+|x+)$/i.test(match)) return true;
    if (/^[a-z]+$/i.test(match) && match.length < 20) return true;
    if (/^(https?:\/\/)?[a-z0-9.-]+\.(js|css|html|png|jpg|gif|svg|woff|ttf|eot|ico)$/i.test(match)) return true;
    return false;
  }

  function report(data) {
    const resolvedUrl = normalizeUrl(data.url || pageUrl, pageUrl);
    const key = `${data.type}:${data.match}:${resolvedUrl}`;
    if (seen.has(key)) return;
    seen.add(key);

    const { contextMeta, entropyTarget, ...cleanData } = data;
    const entropyValue = shannonEntropy(entropyTarget || cleanData.match || "");

    let finalFinding = {
      ...cleanData,
      url: resolvedUrl,
      domain: pageDomain,
      pageUrl,
      timestamp: Date.now(),
    };

    if (ContextEngine) {
      const ctx = ContextEngine.analyzeContext({
        match: entropyTarget || cleanData.match,
        url: resolvedUrl,
        pageUrl,
        type: cleanData.type,
        patternName: cleanData.patternName,
        provider: cleanData.provider,
        keyName: contextMeta && contextMeta.keyName,
        snippet: contextMeta && contextMeta.snippet,
        inComment: contextMeta && contextMeta.inComment,
        isMinified: contextMeta && contextMeta.isMinified,
      });

      if (ContextEngine.shouldSuppressFinding(finalFinding, ctx, () => entropyValue)) {
        return;
      }

      if (RiskEngine) {
        finalFinding = RiskEngine.evaluateFinding(finalFinding, ctx, entropyValue);
      } else {
        finalFinding.context = ctx;
      }
    }

    try {
      chrome.runtime.sendMessage({
        type: "finding",
        data: finalFinding,
      });
    } catch {}
  }

  function scanText(text, sourceUrl, sourceType) {
    if (!text || text.length < 10) return;

    if (ReconEngine && (sourceType === "inline-script" || sourceType === "external-script" || sourceType === "fetch-response" || sourceType === "xhr-response")) {
      for (const ref of ReconEngine.extractSourceMapRefs(text, sourceUrl)) {
        reconSourceMaps.push(ref);
      }
      for (const ep of ReconEngine.extractHighSignalEndpoints(text)) {
        reconEndpoints.add(ep);
      }
    }

    for (const pattern of SECRET_PATTERNS) {
      pattern.re.lastIndex = 0;
      let m;
      while ((m = pattern.re.exec(text)) !== null) {
        const matched = m[1] || m[0];
        if (isFalsePositive(matched)) continue;
        const contextMeta = ContextEngine
          ? ContextEngine.extractTextContext(text, m.index, m[0].length, matched)
          : null;
        report({
          url: sourceUrl,
          match: matched.substring(0, 200),
          entropyTarget: matched,
          type: sourceType,
          patternName: pattern.name,
          severity: pattern.severity,
          confidence: pattern.confidence,
          provider: pattern.provider,
          contextMeta,
        });
      }
    }

    for (const kw of keywords) {
      const escaped = kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      // Require word boundary around keyword to avoid matching "hotkey", "monkey", "turkey" for "key"
      const kwRegex = new RegExp(
        `(?:^|[^a-zA-Z])(?:${escaped})(?:[^a-zA-Z]|$)\\s*[:=]\\s*['"\`]([^'"\`\\n]{8,200})['"\`]`,
        "gi"
      );
      let m;
      while ((m = kwRegex.exec(text)) !== null) {
        const val = m[1];
        if (isFalsePositive(val)) continue;
        // Skip values that look like JS function/method names (camelCase identifiers)
        if (/^[a-z][a-zA-Z0-9_]*$/.test(val) && val.length < 60) continue;
        const contextMeta = ContextEngine
          ? ContextEngine.extractTextContext(text, m.index, m[0].length, val)
          : null;
        if (contextMeta && !contextMeta.keyName) {
          contextMeta.keyName = kw;
        }
        report({
          url: sourceUrl,
          match: val.substring(0, 200),
          entropyTarget: val,
          type: sourceType,
          patternName: `Keyword: ${kw}`,
          severity: "medium",
          confidence: isHighEntropy(val) ? "high" : "medium",
          provider: "Keyword Match",
          contextMeta,
        });
      }
    }
  }

  function scanScriptUrl(src) {
    if (!src) return;
    for (const kw of keywords) {
      if (src.toLowerCase().includes(kw)) {
        report({
          url: src, match: src, type: "script-src",
          patternName: `Script URL contains: ${kw}`,
          severity: "medium", confidence: "medium", provider: "URL Scan",
        });
      }
    }
    try {
      const url = new URL(src, pageUrl);
      for (const [param, value] of url.searchParams) {
        if (value.length >= 16 && isHighEntropy(value)) {
          report({
            url: src, match: `${param}=${value.substring(0, 100)}`,
            type: "url-param", patternName: "High-Entropy URL Parameter",
            severity: "medium", confidence: "medium", provider: "URL Scan",
          });
        }
      }
    } catch {}
  }

  async function scanExternalScriptContent(src) {
    try {
      const resolved = new URL(src, pageUrl).href;
      if (fetchedScripts.has(resolved)) return;
      if (new URL(resolved).origin !== location.origin) return;
      fetchedScripts.add(resolved);
      const resp = await fetch(resolved, { credentials: "omit" });
      if (!resp.ok) return;
      const text = await resp.text();
      scanText(text, resolved, "external-script");
    } catch {}
  }

  function scanScriptSrcUrls() {
    const scripts = document.querySelectorAll("script[src]");
    for (const script of scripts) {
      scanScriptUrl(script.src);
    }
  }

  function scanInlineScripts() {
    const scripts = document.querySelectorAll("script:not([src])");
    for (const script of scripts) {
      scanText(script.textContent, pageUrl, "inline-script");
    }
  }

  async function scanExternalScripts() {
    const scripts = document.querySelectorAll("script[src]");
    for (const script of scripts) {
      await scanExternalScriptContent(script.src);
    }
  }

  function scanMetaTags() {
    const metas = document.querySelectorAll("meta");
    for (const meta of metas) {
      const content = meta.getAttribute("content");
      if (!content || content.length < 12) continue;
      const name = (meta.getAttribute("name") || meta.getAttribute("property") || "").toLowerCase();
      const sensitive = ["api-key", "api_key", "apikey", "token", "secret", "access-token", "csrf-token", "csrf_token"];
      if (sensitive.some((s) => name.includes(s))) {
        report({
          url: pageUrl, match: `meta[${name}]=${content.substring(0, 100)}`,
          entropyTarget: content,
          type: "meta-tag", patternName: "Sensitive Meta Tag",
          severity: "high", confidence: "high", provider: "DOM Scan",
          contextMeta: { keyName: name, snippet: `<meta name="${name}" content="[MATCH]">` },
        });
      }
      scanText(`${name}=${content}`, pageUrl, "meta-tag");
    }
  }

  function scanHiddenInputElement(input) {
    const name = (input.name || input.id || "").toLowerCase();
    const value = input.value;
    if (!value || value.length < 8) return;
    // Skip known framework CSRF tokens — these are ephemeral anti-CSRF nonces, not secrets
    if (CSRF_INPUT_NAMES.some((c) => name === c || name.startsWith(c))) return;
    // Skip common non-secret hidden fields
    if (BENIGN_INPUT_NAMES.some((b) => name === b || name.startsWith(b))) return;
    if (SENSITIVE_INPUT_NAMES.some((s) => name.includes(s)) || isHighEntropy(value)) {
      report({
        url: pageUrl, match: `${name}=${value.substring(0, 100)}`,
        entropyTarget: value,
        type: "hidden-input", patternName: "Hidden Form Field",
        severity: isHighEntropy(value) ? "high" : "medium",
        confidence: SENSITIVE_INPUT_NAMES.some((s) => name.includes(s)) ? "high" : "medium",
        provider: "DOM Scan",
        contextMeta: { keyName: name, snippet: `<input type="hidden" name="${name}" value="[MATCH]">` },
      });
    }
  }

  function scanHiddenInputs() {
    const inputs = document.querySelectorAll('input[type="hidden"]');
    for (const input of inputs) {
      scanHiddenInputElement(input);
    }
  }

  function scanElementDataAttributes(el) {
    if (!el.attributes) return;
    for (const attr of el.attributes) {
      if (!/^data-.*(?:key|token|secret|auth|api|credential|password)/i.test(attr.name)) continue;
      if (!attr.value || attr.value.length < 8) continue;
      if (IGNORED_DATA_ATTRS.includes(attr.name)) continue;
      if (/(?:Mod|Shift|Alt|Ctrl|Meta)\+/i.test(attr.value)) continue;
      report({
        url: pageUrl, match: `${attr.name}="${attr.value.substring(0, 100)}"`,
        entropyTarget: attr.value,
        type: "data-attribute", patternName: "Sensitive Data Attribute",
        severity: "medium", confidence: isHighEntropy(attr.value) ? "high" : "medium",
        provider: "DOM Scan",
        contextMeta: { keyName: attr.name, snippet: `${attr.name}="[MATCH]"` },
      });
    }
  }

  function scanDataAttributes() {
    const all = document.querySelectorAll("*");
    for (const el of all) {
      scanElementDataAttributes(el);
    }
  }

  function scanHtmlComments() {
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT, null);
    while (walker.nextNode()) {
      const text = walker.currentNode.textContent;
      if (text && text.length >= 20) {
        scanText(text, pageUrl, "html-comment");
      }
    }
  }

  function scanLinkHrefs() {
    const links = document.querySelectorAll("a[href], link[href]");
    // URL param names that look sensitive but aren't
    const benignParams = ["author", "assignee", "reviewer", "creator", "user", "username",
      "sort", "order", "page", "per_page", "tab", "type", "language", "q", "query",
      "ref", "branch", "path", "since", "until", "direction", "state", "label",
      "source", "plan", "return_to", "redirect", "onload", "render", "style",
      "method", "host", "fromHostedPage", "countryBlackList"];
    for (const link of links) {
      try {
        const href = link.href;
        if (!href) continue;
        const url = new URL(href);
        for (const [param, value] of url.searchParams) {
          const p = param.toLowerCase();
          if (benignParams.includes(p)) continue;
          const sensitive = ["api_key", "apikey", "token", "secret", "access_token", "password", "session_id", "private_key"];
          // Require exact match on the param name, not substring — "author" was matching "auth"
          if (sensitive.some((s) => p === s || p.endsWith(`_${s}`) || p.startsWith(`${s}_`)) && value.length >= 8) {
            report({
              url: href, match: `${param}=${value.substring(0, 100)}`,
              type: "url-param", patternName: "Sensitive URL Parameter",
              severity: "high", confidence: "high", provider: "URL Scan",
            });
          }
        }
      } catch {}
    }
  }

  function scanWebStorage() {
    const stores = [
      { store: localStorage, label: "localStorage" },
      { store: sessionStorage, label: "sessionStorage" },
    ];
    // Keys that are known non-sensitive framework/platform storage — never flag these
    const ignoredKeyPrefixes = [
      "ref-selector:",           // GitHub branch selector cache
      "jump_to:",                // GitHub navigation cache
      "soft-nav:",               // GitHub SPA navigation state
      "react-router-scroll",     // React Router scroll positions
      "COPILOT_SELECTED_MODEL",  // GitHub Copilot UI preference
      "rc::",                    // reCAPTCHA state
      "debug:",                  // Debug flags
      "ajs_",                    // Analytics.js state
      "_ga",                     // Google Analytics
      "intercom",                // Intercom chat widget
      "amplitude_",              // Amplitude analytics
      "mp_",                     // Mixpanel
      "optimizely",              // Optimizely experiments
    ];
    // Specific exact keys that look sensitive but aren't
    const ignoredExactKeys = [
      "COPILOT_AUTH_TOKEN",      // GitHub Copilot ephemeral session (browser-local, not extractable)
      "COPILOT_AUTH_TOKEN:expiry",
      "id",                      // Generic session IDs in iframes (e.g., Stripe m.stripe.network)
    ];
    for (const { store, label } of stores) {
      try {
        for (let i = 0; i < store.length; i++) {
          const key = store.key(i);
          const value = store.getItem(key);
          if (!value || value.length < 12) continue;
          const kl = key.toLowerCase();
          // Skip known benign keys
          if (ignoredKeyPrefixes.some((p) => key.startsWith(p))) continue;
          if (ignoredExactKeys.includes(key)) continue;
          // Skip keys whose values are clearly JSON branch/ref data (GitHub caches)
          if (value.startsWith('{"refs":') || value.startsWith('{"billing":')) continue;
          const sensitive = ["token", "secret", "auth", "credential", "password", "jwt", "bearer", "private_key"];
          // Require a stronger match — "key" alone is too broad (matches "hotkey", "monkey", etc.)
          // Remove "key" and "session" from sensitive list to reduce noise
          if (sensitive.some((s) => kl.includes(s)) || isHighEntropy(value.substring(0, 100))) {
            report({
              url: pageUrl, match: `${label}.${key}=${value.substring(0, 120)}`,
              entropyTarget: value.substring(0, 120),
              type: "web-storage", patternName: `${label} Secret`,
              severity: "high",
              confidence: sensitive.some((s) => kl.includes(s)) ? "high" : "medium",
              provider: "Storage Scan",
              contextMeta: { keyName: `${label}.${key}`, snippet: `${label}["${key}"] = [MATCH]` },
            });
          }
          scanText(`${key}=${value}`, pageUrl, "web-storage");
        }
      } catch {}
    }
  }

  function scanCookies() {
    try {
      const cookies = document.cookie.split(";");
      for (const cookie of cookies) {
        const [name, ...rest] = cookie.split("=");
        if (!name) continue;
        const value = rest.join("=").trim();
        const n = name.trim().toLowerCase();
        const sensitive = ["token", "session", "auth", "jwt", "bearer", "api_key", "apikey", "secret", "credential"];
        if (value && value.length >= 16 && sensitive.some((s) => n.includes(s))) {
          report({
            url: pageUrl, match: `cookie:${name.trim()}=${value.substring(0, 80)}`,
            entropyTarget: value,
            type: "cookie", patternName: "Sensitive Cookie",
            severity: "medium", confidence: "medium", provider: "Cookie Scan",
            contextMeta: { keyName: name.trim(), snippet: `document.cookie: ${name.trim()}=[MATCH] (non-HttpOnly)` },
          });
        }
      }
    } catch {}
  }

  function handleInterceptorEvent(data) {
    if (!data) return;

    if (data.rawText) {
      scanText(data.rawText, data.sourceUrl || pageUrl, data.type);
      if (!data.match) return;
    }

    if (data.match) {
      const rawGlobalVal = data.match.includes("=") ? data.match.slice(data.match.indexOf("=") + 1) : data.match;
      const globalName = data.match.includes("=") ? data.match.slice(0, data.match.indexOf("=")) : "";
      report({
        url: data.sourceUrl || pageUrl,
        match: data.match,
        entropyTarget: rawGlobalVal,
        type: data.type,
        patternName: data.patternName || data.type,
        severity: data.severity || "medium",
        confidence: data.confidence || "medium",
        provider: data.provider || "Runtime Scan",
        contextMeta: globalName ? { keyName: globalName, snippet: `${globalName} = [MATCH]` } : null,
      });
    }
  }

  if (typeof window.__kfRegisterReceiver === "function") {
    window.__kfRegisterReceiver(handleInterceptorEvent);
  }

  scanScriptSrcUrls();
  scanInlineScripts();
  scanMetaTags();
  scanHiddenInputs();
  scanDataAttributes();
  scanHtmlComments();
  scanLinkHrefs();
  scanWebStorage();
  scanCookies();
  await scanExternalScripts();

  if (ReconEngine) {
    const thirdPartyScripts = ReconEngine.collectThirdPartyScripts(document, location.origin);
    if (thirdPartyScripts.length > 0 || reconSourceMaps.length > 0 || reconEndpoints.size > 0) {
      try {
        chrome.runtime.sendMessage({
          type: "recon",
          data: {
            domain: pageDomain,
            pageUrl,
            thirdPartyScripts,
            sourceMaps: reconSourceMaps,
            endpoints: [...reconEndpoints],
            timestamp: Date.now(),
          },
        });
      } catch {}
    }
  }

  // Observe DOM mutations for SPA support
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.tagName === "SCRIPT") {
          if (node.src) {
            scanScriptUrl(node.src);
            scanExternalScriptContent(node.src);
          } else if (node.textContent) {
            scanText(node.textContent, pageUrl, "inline-script");
          }
        }
        const hiddenInputs = node.matches && node.matches('input[type="hidden"]')
          ? [node]
          : (node.querySelectorAll ? Array.from(node.querySelectorAll('input[type="hidden"]')) : []);
        for (const input of hiddenInputs) {
          scanHiddenInputElement(input);
        }
        const elementsToCheck = node.querySelectorAll ? [node, ...node.querySelectorAll("*")] : [node];
        for (const el of elementsToCheck) {
          scanElementDataAttributes(el);
        }
      }
    }
  });
  observer.observe(document.body || document.documentElement, { childList: true, subtree: true });

  if (seen.size > 0) {
    console.log(`[KeyFinder] ${seen.size} potential secret(s) found on ${pageDomain}`);
  }
})();
