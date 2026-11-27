(function (root) {
  "use strict";

  const nowSec = Math.floor(Date.now() / 1000);
  const b64url = (obj) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const ACTIVE_JWT = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user42", role: "admin", exp: nowSec + 3600 })}.sig_active_1234567890`;
  const EXPIRED_JWT = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user42", exp: 1500000000 })}.sig_expired_123456789`;
  const MINIFIED_PAD = "var _0x1a2b=function(){return 1};".repeat(18);

  /**
   * Labeled synthetic dataset:
   * - expectedActionable: true  => genuine secret exposure that should be flagged medium/high/critical
   * - expectedActionable: false => benign, placeholder, test-only, or public-by-design (should be suppressed or downgraded to low/info)
   */
  const DATASET = [
    // --- True Positives (12) ---
    {
      id: "TP-01",
      label: "AWS Access Key in prod inline script",
      expectedActionable: true,
      pageUrl: "https://app.acme.io/dashboard",
      type: "inline-script",
      text: 'const awsKey = "AKIA1234567890ABCDEF";',
    },
    {
      id: "TP-02",
      label: "Stripe Live Secret Key in prod fetch response",
      expectedActionable: true,
      pageUrl: "https://api.shopfront.dev/v2/config",
      type: "fetch-response",
      text: '{"stripeSecret":"' + 'sk_live_' + '51RealProdKeyForEval12345678"}',
    },
    {
      id: "TP-03",
      label: "GitHub PAT in prod external script",
      expectedActionable: true,
      pageUrl: "https://portal.acme.io/assets/app.js",
      type: "external-script",
      text: 'const ghToken = "ghp_RealEvalToken123456789012345678901234";',
    },
    {
      id: "TP-04",
      label: "OpenAI Project Key in prod web-storage",
      expectedActionable: true,
      pageUrl: "https://ai.acme.io/",
      type: "web-storage",
      text: 'openai_key="sk-proj-EvalProdKey1234567890123456789012345678901234"',
    },
    {
      id: "TP-05",
      label: "Google API Key in prod inline script",
      expectedActionable: true,
      pageUrl: "https://maps.acme.io/",
      type: "inline-script",
      text: 'window.gKey = "AIzaSyProdEvalKey98765432109876543210987";',
    },
    {
      id: "TP-06",
      label: "Active unexpired JWT with admin claim in prod",
      expectedActionable: true,
      pageUrl: "https://app.acme.io/session",
      type: "web-storage",
      text: `auth_jwt="${ACTIVE_JWT}"`,
    },
    {
      id: "TP-07",
      label: "Slack Bot Token in prod HTML comment",
      expectedActionable: true,
      pageUrl: "https://status.acme.io/",
      type: "html-comment",
      text: "<!-- backup bot: " + "xoxb-" + "12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx -->",
    },
    {
      id: "TP-08",
      label: "PostgreSQL connection string in prod fetch",
      expectedActionable: true,
      pageUrl: "https://app.acme.io/config",
      type: "fetch-response",
      text: '{"db":"postgres://admin:Str0ngP4ss!@db.acme.io:5432/prod"}',
    },
    {
      id: "TP-09",
      label: "RSA Private Key block in prod script",
      expectedActionable: true,
      pageUrl: "https://auth.acme.io/",
      type: "inline-script",
      text: 'const pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAK...";',
    },
    {
      id: "TP-10",
      label: "High-entropy generic api_key in prod script",
      expectedActionable: true,
      pageUrl: "https://app.acme.io/init",
      type: "inline-script",
      text: 'const api_key = "9f8e7d6c5b4a3210fedcba9876543210";',
    },
    {
      id: "TP-11",
      label: "Azure SAS Token at end of URL",
      expectedActionable: true,
      pageUrl: "https://cdn.acme.io/files",
      type: "fetch-response",
      text: '{"url":"https://acct.blob.core.windows.net/c/b?sv=2023-01-01&sig=ProdBase64Signature12345678"}',
    },
    {
      id: "TP-12",
      label: "SendGrid API Key in prod XHR response",
      expectedActionable: true,
      pageUrl: "https://mail.acme.io/send",
      type: "xhr-response",
      text: '{"sg":"SG.AbCdEfGhIjKlMnOpQrStUv.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789012345678"}',
    },

    // --- False Positives / Non-Actionable Cases (12) ---
    {
      id: "FP-01",
      label: "Stripe test key (sk_test_) on prod",
      expectedActionable: false,
      pageUrl: "https://app.acme.io/billing",
      type: "inline-script",
      text: 'const stripeTest = "sk_test_51MockKeyForLocalTesting1234";',
    },
    {
      id: "FP-02",
      label: "Stripe publishable key (pk_live_) on prod",
      expectedActionable: false,
      pageUrl: "https://app.acme.io/checkout",
      type: "inline-script",
      text: 'const stripePub = "pk_live_51PublicClientKey1234567890123";',
    },
    {
      id: "FP-03",
      label: "AWS documentation example key on github.com",
      expectedActionable: false,
      pageUrl: "https://github.com/awsdocs/example",
      type: "inline-script",
      text: 'const example = "AKIAIOSFODNN7EXAMPLE";',
    },
    {
      id: "FP-04",
      label: "Expired JWT on localhost",
      expectedActionable: false,
      pageUrl: "http://localhost:3000/login",
      type: "web-storage",
      text: `token="${EXPIRED_JWT}"`,
    },
    {
      id: "FP-05",
      label: "Placeholder generic api_key string",
      expectedActionable: false,
      pageUrl: "https://app.acme.io/setup",
      type: "inline-script",
      text: 'const api_key = "your_api_key_placeholder";',
    },
    {
      id: "FP-06",
      label: "Dummy generic secret_key string",
      expectedActionable: false,
      pageUrl: "https://app.acme.io/setup",
      type: "inline-script",
      text: 'const secret_key = "example_dummy_secret_value";',
    },
    {
      id: "FP-07",
      label: "Minified bundle generic keyword label",
      expectedActionable: false,
      pageUrl: "https://app.acme.io/bundle.min.js",
      type: "external-script",
      text: `${MINIFIED_PAD}var token="navigation_state_label";`,
    },
    {
      id: "FP-08",
      label: "Google API key in MDN documentation",
      expectedActionable: false,
      pageUrl: "https://developer.mozilla.org/en-US/docs/Web/API",
      type: "inline-script",
      text: 'const demoKey = "AIzaSyDummyTestKey000000000000000000000";',
    },
    {
      id: "FP-09",
      label: "Stripe test key on localhost",
      expectedActionable: false,
      pageUrl: "http://127.0.0.1:8765/",
      type: "inline-script",
      text: 'const s = "sk_test_51LocalhostTestKey1234567890";',
    },
    {
      id: "FP-10",
      label: "Repeated low-diversity generic password",
      expectedActionable: false,
      pageUrl: "https://app.acme.io/form",
      type: "inline-script",
      text: 'const password = "aaaaaaaaaaaaaaaaaaaa";',
    },
    {
      id: "FP-11",
      label: "Public Sentry DSN on prod",
      expectedActionable: false,
      pageUrl: "https://app.acme.io/",
      type: "inline-script",
      text: 'Sentry.init({ dsn: "https://0123456789abcdef0123456789abcdef@o123.sentry.io/456" });',
    },
    {
      id: "FP-12",
      label: "Public Mapbox pk. token on prod",
      expectedActionable: false,
      pageUrl: "https://maps.acme.io/",
      type: "inline-script",
      text: 'mapboxgl.accessToken = "' + 'pk.' + 'eyJ1IjoiZGVtbyIsImEiOiJjbDF2M3g0eTUwMDAwM2pwMDFhMnIzbTRuIn0.AbCdEfGhIjKlMnOpQrStUv";',
    },
  ];

  root.KeyFinderEvalDataset = DATASET;
})(typeof globalThis !== "undefined" ? globalThis : self);
