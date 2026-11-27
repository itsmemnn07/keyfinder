(function (root) {
  "use strict";

  const BASE_SEVERITY_SCORE = {
    critical: 75,
    high: 55,
    medium: 35,
    low: 15,
    info: 5,
  };

  const SURFACE_WEIGHT = {
    "inline-script": 15,
    "external-script": 15,
    "html-comment": 15,
    "meta-tag": 15,
    "url-param": 15,
    "data-attribute": 12,
    "hidden-input": 12,
    "fetch-response": 10,
    "xhr-response": 10,
    "window-global": 12,
    "web-storage": 10,
    "cookie": 5,
    "script-src": 0,
  };

  const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };
  const RANK_TO_CONFIDENCE = ["low", "medium", "high"];

  function shiftConfidence(level, delta) {
    const cur = CONFIDENCE_RANK[level] ?? 1;
    const next = Math.max(0, Math.min(2, cur + delta));
    return RANK_TO_CONFIDENCE[next];
  }

  /**
   * Classify confidence ("high" | "medium" | "low") from pattern specificity, entropy, and context.
   * Confidence represents certainty that the value matches a real secret format, distinct from risk.
   * @param {object} finding
   * @param {object} context
   * @param {number} entropy
   * @returns {string}
   */
  function classifyConfidence(finding, context, entropy) {
    let conf = finding.confidence || "medium";
    const provider = finding.provider || "";
    const signals = (context && context.placeholderSignals) || [];
    const isGeneric = provider === "Generic" || provider === "Keyword Match" || provider === "DOM Scan" || provider === "Storage Scan";

    if (context && context.jwtMeta) {
      conf = context.jwtMeta.validStructure ? "high" : "low";
    } else if (isGeneric && typeof entropy === "number") {
      if (entropy >= 3.8 && String(finding.match || "").length >= 16) {
        conf = shiftConfidence(conf, 1);
      } else if (entropy < 3.0) {
        conf = shiftConfidence(conf, -1);
      }
    }

    if (signals.includes("placeholder-word") || signals.includes("repeated-pattern")) {
      // Vendor test prefixes like sk_test_ still have high format confidence, even if risk is low
      if (!signals.includes("test-prefix")) {
        conf = shiftConfidence(conf, -1);
      }
    }

    if (context && context.isMinified && isGeneric) {
      conf = shiftConfidence(conf, -1);
    }

    return conf;
  }

  /**
   * Map numeric 0-100 riskScore to a normalized risk level.
   * @param {number} score
   * @returns {string}
   */
  function scoreToLevel(score) {
    if (score >= 80) return "critical";
    if (score >= 60) return "high";
    if (score >= 35) return "medium";
    if (score >= 15) return "low";
    return "info";
  }

  /**
   * Compute an explainable, deterministic 0-100 risk assessment for a finding.
   * @param {object} finding
   * @param {object} context
   * @param {number} [entropy]
   * @returns {{ riskScore: number, riskLevel: string, confidence: string, riskFactors: string[] }}
   */
  function assessRisk(finding, context, entropy) {
    const ctx = context || {};
    const factors = [];
    const baseSev = finding.severity || "medium";
    let score = BASE_SEVERITY_SCORE[baseSev] ?? 35;
    factors.push(`+${score} Base pattern severity (${baseSev}: ${finding.patternName || finding.type})`);

    // 1. Exposure surface weight
    const surface = ctx.surface || finding.type || "";
    const surfaceDelta = SURFACE_WEIGHT[surface] ?? 5;
    if (surfaceDelta !== 0) {
      score += surfaceDelta;
      factors.push(`+${surfaceDelta} Exposure surface (${surface})`);
    }

    // 2. Environment and transport modifiers
    if (ctx.environment === "production") {
      score += 10;
      factors.push("+10 Production-like public origin");
      if (ctx.protocol === "http:") {
        score += 5;
        factors.push("+5 Unencrypted HTTP transport");
      }
    } else if (ctx.environment === "dev-staging") {
      score -= 10;
      factors.push("-10 Non-production dev/staging domain");
    } else if (ctx.environment === "localhost") {
      score -= 25;
      factors.push("-25 Local development host (localhost)");
    } else if (ctx.environment === "docs-example") {
      score -= 30;
      factors.push("-30 Documentation or code-hosting page");
    }

    // 3. Token-specific and placeholder modifiers
    const signals = ctx.placeholderSignals || [];
    if (signals.includes("test-prefix")) {
      score -= 45;
      factors.push("-45 Test/sandbox key prefix (e.g., sk_test_/rk_test_)");
    }
    if (signals.includes("public-by-design")) {
      score -= 25;
      factors.push("-25 Client/publishable identifier by design");
    }
    if (signals.includes("example-key")) {
      score -= 40;
      factors.push("-40 Known documentation example key");
    }
    if (signals.includes("placeholder-word")) {
      score -= 25;
      factors.push("-25 Placeholder or mock indicator near value");
    }
    if (signals.includes("repeated-pattern")) {
      score -= 15;
      factors.push("-15 Low-diversity repeated character sequence");
    }

    // 4. JWT claims context
    if (ctx.jwtMeta && ctx.jwtMeta.validStructure) {
      if (ctx.jwtMeta.weakAlg) {
        score += 15;
        factors.push("+15 JWT uses insecure alg=none");
      }
      if (ctx.jwtMeta.expired) {
        score -= 25;
        factors.push("-25 JWT exp claim is already expired");
      } else if (ctx.jwtMeta.sensitiveClaims && ctx.jwtMeta.sensitiveClaims.length > 0) {
        score += 5;
        factors.push(`+5 JWT exposes claims (${ctx.jwtMeta.sensitiveClaims.join(", ")})`);
      }
    }

    // 5. Code comment context
    if (ctx.inComment && baseSev !== "critical") {
      score -= 5;
      factors.push("-5 Found inside a comment block");
    }

    // 6. Confidence alignment
    const confidence = classifyConfidence(finding, ctx, entropy);
    if (confidence === "low") {
      score -= 10;
      factors.push("-10 Low detection confidence");
    }

    const clamped = Math.max(0, Math.min(100, Math.round(score)));
    const riskLevel = scoreToLevel(clamped);

    return {
      riskScore: clamped,
      riskLevel,
      confidence,
      riskFactors: factors,
    };
  }

  /**
   * Enrich a candidate finding with context, confidence, risk score, and risk level.
   * @param {object} finding
   * @param {object} context
   * @param {number} [entropy]
   * @returns {object}
   */
  function evaluateFinding(finding, context, entropy) {
    const assessment = assessRisk(finding, context, entropy);
    return {
      ...finding,
      severity: assessment.riskLevel,
      riskLevel: assessment.riskLevel,
      riskScore: assessment.riskScore,
      confidence: assessment.confidence,
      riskFactors: assessment.riskFactors,
      context: context || null,
    };
  }

  const api = {
    classifyConfidence,
    scoreToLevel,
    assessRisk,
    evaluateFinding,
  };

  root.KeyFinderRisk = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);
