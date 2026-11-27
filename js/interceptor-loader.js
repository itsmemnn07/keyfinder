(function () {
  "use strict";

  const el = document.documentElement;
  if (!el) return;

  const nonce = crypto.randomUUID();
  const MAX_EARLY_BUFFER = 200;
  const earlyQueue = [];
  let receiver = null;

  // Register ISOLATED-world receiver bridge so content.js (loaded at document_idle)
  // drains any MAIN-world events dispatched between document_start and document_idle.
  window.__kfRegisterReceiver = function (fn) {
    receiver = fn;
    while (earlyQueue.length > 0) {
      const item = earlyQueue.shift();
      try {
        fn(item);
      } catch {}
    }
  };

  window.addEventListener("__kf_finding__", (e) => {
    const data = e && e.detail;
    if (!data || data.__kfNonce !== nonce) return;
    if (typeof receiver === "function") {
      receiver(data);
    } else if (earlyQueue.length < MAX_EARLY_BUFFER) {
      earlyQueue.push(data);
    }
  });

  // interceptor.js reads and immediately removes data-kf-nonce in MAIN world.
  el.setAttribute("data-kf-nonce", nonce);

  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("js/interceptor.js");
  (document.head || el).appendChild(script);
  script.onload = () => script.remove();
})();
