(function (root) {
  "use strict";

  const PROVIDER_GUIDANCE = {
    AWS: {
      title: "AWS Credential Exposure",
      summary: "Rotate compromised IAM keys immediately and move AWS access to backend services or short-lived STS credentials.",
      steps: [
        "Deactivate and delete the exposed IAM Access Key in the AWS IAM Console.",
        "Review AWS CloudTrail logs for unauthorized API activity during the exposure window.",
        "Never embed long-lived IAM credentials in frontend code; use backend proxies or Cognito temporary credentials.",
      ],
    },
    Google: {
      title: "Google / GCP Credential Exposure",
      summary: "Restrict or regenerate the exposed Google key/token and audit GCP API usage.",
      steps: [
        "Regenerate the API key or revoke OAuth credentials in Google Cloud Console.",
        "Apply strict HTTP referrer, IP, and API scope restrictions to any browser-facing keys.",
        "Move OAuth client secrets and Service Account JSON files exclusively to server-side environments.",
      ],
    },
    Firebase: {
      title: "Firebase Configuration Exposure",
      summary: "Verify Firebase Security Rules; browser Firebase API keys are identifiers, not authorization controls.",
      steps: [
        "Audit Realtime Database, Firestore, and Storage Security Rules to deny unauthenticated reads/writes.",
        "Revoke any exposed legacy FCM server keys in Firebase Project Settings.",
      ],
    },
    Azure: {
      title: "Azure Storage / SAS Exposure",
      summary: "Rotate Storage Account keys or revoke SAS policies to prevent unauthorized blob/table access.",
      steps: [
        "Regenerate the primary/secondary Storage Account access keys in Azure Portal.",
        "For SAS tokens, rotate the signing key or revoke the Stored Access Policy and shorten token lifetimes.",
      ],
    },
    GitHub: {
      title: "GitHub Token Exposure",
      summary: "Revoke the exposed GitHub token immediately to prevent repository, package, or CI/CD compromise.",
      steps: [
        "Revoke the token under GitHub Settings -> Developer settings -> Personal access tokens.",
        "Audit repository security logs, webhooks, and workflow runs for unexpected changes.",
        "Replace broad classic PATs with least-privilege, short-lived GitHub App or fine-grained tokens stored server-side.",
      ],
    },
    GitLab: {
      title: "GitLab Token Exposure",
      summary: "Revoke the exposed GitLab PAT, pipeline, or runner token and inspect CI/CD logs.",
      steps: [
        "Revoke the token in GitLab User Settings / Project Access Tokens.",
        "Re-register affected runners if a Runner Token was exposed.",
      ],
    },
    Stripe: {
      title: "Stripe Key Exposure",
      summary: "Roll secret or restricted keys immediately; publishable (pk_) and test (sk_test_) keys have limited client scope.",
      steps: [
        "If this is a live secret (sk_live_), restricted (rk_live_), or webhook secret (whsec_), roll it immediately in Stripe Dashboard -> Developers -> API keys.",
        "Confirm test keys (sk_test_) are not shipped in production bundles even though they cannot process live charges.",
        "Keep publishable keys (pk_) only for Stripe.js client tokenization.",
      ],
    },
    Slack: {
      title: "Slack Token / Webhook Exposure",
      summary: "Revoke the exposed Slack token or regenerate the Incoming Webhook URL.",
      steps: [
        "Revoke the Bot/User/App token in Slack App settings or regenerate the webhook URL.",
        "Audit workspace channels and app installations for unauthorized messages or data reads.",
      ],
    },
    OpenAI: {
      title: "OpenAI API Key Exposure",
      summary: "Revoke the exposed OpenAI key immediately to stop unauthorized billing and data access.",
      steps: [
        "Delete/revoke the key in the OpenAI API Keys dashboard and issue a replacement.",
        "Route all LLM API calls through a backend server with per-user rate limits.",
      ],
    },
    Anthropic: {
      title: "Anthropic API Key Exposure",
      summary: "Revoke the exposed Anthropic key and proxy model requests through your backend.",
      steps: [
        "Revoke the key in Anthropic Console -> API Keys.",
        "Move API calls to server-side routes so secrets never reach browser bundles.",
      ],
    },
    JWT: {
      title: "JSON Web Token Exposure",
      summary: "Avoid exposing long-lived JWTs in HTML, URLs, or localStorage where XSS can steal them.",
      steps: [
        "Store session tokens in HttpOnly, Secure, SameSite cookies rather than localStorage or URL parameters.",
        "Ensure short expiration (exp) lifetimes and reject alg=none on the server.",
      ],
    },
    Crypto: {
      title: "Private Key Block Exposure",
      summary: "Private cryptographic keys must never appear in client-side assets. Revoke and reissue immediately.",
      steps: [
        "Revoke any certificates or SSH/PGP keys tied to this private key.",
        "Generate a fresh key pair in a secure server/HSM environment and purge the leaked copy from version history.",
      ],
    },
  };

  const SURFACE_GUIDANCE = {
    "web-storage": "Avoid storing bearer tokens or secrets in localStorage/sessionStorage because any XSS vulnerability can read them. Prefer HttpOnly, Secure cookies.",
    "cookie": "Mark sensitive session cookies as HttpOnly, Secure, and SameSite so JavaScript (and XSS) cannot read them via document.cookie.",
    "url-param": "Never pass tokens or API keys in URL query parameters; they leak via browser history, Referer headers, and server access logs. Use Authorization headers or POST bodies.",
    "html-comment": "Remove debug comments and credentials from HTML templates before deploying.",
    "hidden-input": "Do not place API keys or long-lived secrets inside hidden form inputs; use ephemeral server-validated CSRF nonces instead.",
    "meta-tag": "Remove private secrets from <meta> tags, which are readable by any script or crawler.",
  };

  /**
   * Look up deterministic, actionable remediation advice for a finding.
   * @param {object} finding
   * @returns {{ title: string, summary: string, steps: string[] }}
   */
  function getRemediation(finding) {
    if (!finding) {
      return {
        title: "Secret Exposure",
        summary: "Verify whether this value is a live credential and remove it from client-side code.",
        steps: ["Rotate the credential if valid and move secret usage to a secure backend service."],
      };
    }

    const base = PROVIDER_GUIDANCE[finding.provider] || {
      title: `${finding.provider || "Credential"} Exposure`,
      summary: "Rotate the credential if it is active in production and remove it from client-accessible surfaces.",
      steps: [
        "Confirm whether the matched value is a real secret or a benign/placeholder string.",
        "If live, revoke and rotate it at the issuing service and store replacements in server-side environment variables.",
      ],
    };

    const steps = [...base.steps];
    const surfaceTip = SURFACE_GUIDANCE[finding.type];
    if (surfaceTip) {
      steps.push(surfaceTip);
    }

    if (finding.context && Array.isArray(finding.context.placeholderSignals)) {
      if (finding.context.placeholderSignals.includes("test-prefix")) {
        steps.unshift("Detected test-mode prefix: confirm no live secret key is deployed alongside it and strip test secret keys from production builds.");
      } else if (finding.context.environment === "localhost") {
        steps.unshift("Detected on localhost: verify this secret is not committed to source control or reused in production.");
      }
    }

    return {
      title: base.title,
      summary: base.summary,
      steps,
    };
  }

  const api = { getRemediation };
  root.KeyFinderRemediation = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);
