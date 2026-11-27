let allFindings = [];
let firstRenderDone = false;

const REDUCE_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

document.addEventListener("DOMContentLoaded", init);

async function init() {
  const versionLabel = document.getElementById("versionLabel");
  if (versionLabel) versionLabel.textContent = "v" + chrome.runtime.getManifest().version;

  renderSkeleton();

  const response = await chrome.runtime.sendMessage({ type: "getFindings" });
  allFindings = response.findings || [];
  let allRecon = {};
  const reconResp = await chrome.runtime.sendMessage({ type: "getRecon" });
  allRecon = (reconResp && reconResp.recon) || {};
  window.__kfReconCache = allRecon;
  renderRecon(allRecon);

  populateFilters();
  renderStats();
  renderAnalytics();
  renderFindings();
  renderTicker();
  firstRenderDone = true;

  document.getElementById("severityFilter").addEventListener("change", renderFindings);
  document.getElementById("typeFilter").addEventListener("change", renderFindings);
  document.getElementById("providerFilter").addEventListener("change", renderFindings);
  document.getElementById("statusFilter").addEventListener("change", renderFindings);
  document.getElementById("groupBySelect").addEventListener("change", renderFindings);
  document.getElementById("searchBox").addEventListener("input", renderFindings);
  document.getElementById("exportJsonBtn").addEventListener("click", exportJson);
  document.getElementById("exportCsvBtn").addEventListener("click", exportCsv);
  document.getElementById("exportReportBtn").addEventListener("click", exportMarkdownReport);
  document.getElementById("exportCfgBtn").addEventListener("click", exportConfig);
  document.getElementById("importCfgBtn").addEventListener("click", () => document.getElementById("importCfgInput").click());
  document.getElementById("importCfgInput").addEventListener("change", importConfig);
  document.getElementById("clearBtn").addEventListener("click", clearAll);

  const searchBox = document.getElementById("searchBox");
  document.addEventListener("keydown", (e) => {
    const tag = document.activeElement && document.activeElement.tagName;
    const typing = tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA";
    if (e.key === "/" && !typing) {
      e.preventDefault();
      searchBox.focus();
    } else if (e.key === "Escape" && document.activeElement === searchBox) {
      searchBox.value = "";
      renderFindings();
      searchBox.blur();
    }
  });
}

/* eased count-up for stat numerals */
function setNumber(el, target) {
  if (!el) return;
  const from = parseInt(el.textContent, 10);
  const start = Number.isFinite(from) ? from : 0;
  if (REDUCE_MOTION || start === target) {
    el.textContent = target;
    return;
  }
  const duration = 400;
  const t0 = performance.now();
  (function tick(t) {
    const p = Math.min(1, (t - t0) / duration);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(start + (target - start) * eased);
    if (p < 1) requestAnimationFrame(tick);
  })(t0);
}

function renderSkeleton() {
  const tbody = document.getElementById("findingsBody");
  tbody.classList.remove("fresh");
  tbody.innerHTML = "";
  const widths = ["skl-w2", "skl-w1", "skl-w3", "skl-w4", "skl-w2", "skl-w3"];
  for (let i = 0; i < 6; i++) {
    const tr = document.createElement("tr");
    tr.className = "skl-row";
    const td = document.createElement("td");
    td.colSpan = 12;
    const bar = document.createElement("div");
    bar.className = "skl " + widths[i % widths.length];
    td.appendChild(bar);
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

function getFiltered() {
  const severity = document.getElementById("severityFilter").value;
  const type = document.getElementById("typeFilter").value;
  const provider = document.getElementById("providerFilter").value;
  const status = document.getElementById("statusFilter").value;
  const search = document.getElementById("searchBox").value.toLowerCase();

  return allFindings.filter((f) => {
    if (severity !== "all" && f.severity !== severity) return false;
    if (type !== "all" && f.type !== type) return false;
    if (provider !== "all" && f.provider !== provider) return false;
    if (status !== "all" && (f.status || "open") !== status) return false;
    if (search && !JSON.stringify(f).toLowerCase().includes(search)) return false;
    return true;
  });
}

function populateFilters() {
  const types = [...new Set(allFindings.map((f) => f.type))].sort();
  const providers = [...new Set(allFindings.map((f) => f.provider))].sort();

  const typeSelect = document.getElementById("typeFilter");
  for (const t of types) {
    const opt = document.createElement("option");
    opt.value = t;
    opt.textContent = t;
    typeSelect.appendChild(opt);
  }

  const providerSelect = document.getElementById("providerFilter");
  for (const p of providers) {
    const opt = document.createElement("option");
    opt.value = p;
    opt.textContent = p;
    providerSelect.appendChild(opt);
  }
}

function renderStats() {
  const bar = document.getElementById("statsBar");
  const critical = allFindings.filter((f) => f.severity === "critical").length;
  const high = allFindings.filter((f) => f.severity === "high").length;
  const medium = allFindings.filter((f) => f.severity === "medium").length;
  const low = allFindings.filter((f) => f.severity === "low").length;
  const info = allFindings.filter((f) => f.severity === "info").length;
  const domains = new Set(allFindings.map((f) => f.domain)).size;

  bar.innerHTML = "";
  const stats = [
    { label: "Total", value: allFindings.length, cls: "stat-total", filter: "all" },
    { label: "Critical", value: critical, cls: "stat-critical", filter: "critical" },
    { label: "High", value: high, cls: "stat-high", filter: "high" },
    { label: "Medium", value: medium, cls: "stat-medium", filter: "medium" },
    { label: "Low", value: low, cls: "stat-low", filter: "low" },
    { label: "Info", value: info, cls: "stat-info", filter: "info" },
    { label: "Domains", value: domains, cls: "stat-domains", filter: null },
  ];
  for (const s of stats) {
    const el = document.createElement("div");
    el.className = `stat-item ${s.cls}`;

    const top = document.createElement("span");
    top.className = "stat-top";
    const led = document.createElement("span");
    led.className = "stat-led";
    const lbl = document.createElement("span");
    lbl.className = "stat-lbl";
    lbl.textContent = s.label;
    top.appendChild(led);
    top.appendChild(lbl);

    const num = document.createElement("span");
    num.className = "stat-num";

    el.appendChild(top);
    el.appendChild(num);
    setNumber(num, s.value);

    if (s.filter) {
      el.dataset.filter = s.filter;
      el.title = s.filter === "all" ? "Show all severities" : `Filter: ${s.label.toLowerCase()} only`;
      el.addEventListener("click", () => {
        document.getElementById("severityFilter").value = s.filter;
        renderFindings();
      });
    }
    bar.appendChild(el);
  }
}

function syncStatActive() {
  const current = document.getElementById("severityFilter").value;
  document.querySelectorAll(".stat-item[data-filter]").forEach((el) => {
    el.classList.toggle("active", el.dataset.filter === current);
  });
}

function renderFindings() {
  const filtered = getFiltered();
  const tbody = document.getElementById("findingsBody");
  const empty = document.getElementById("emptyState");

  tbody.innerHTML = "";
  tbody.classList.toggle("fresh", !firstRenderDone && !REDUCE_MOTION);

  updateMeta(filtered.length);
  syncStatActive();

  if (filtered.length === 0) {
    const title = document.getElementById("emptyTitle");
    const copy = document.getElementById("emptyCopy");
    if (allFindings.length === 0) {
      title.textContent = "No findings yet";
      copy.textContent = "KeyFinder passively scans every page you visit. Browse around — leaked keys, tokens and credentials will surface here.";
    } else {
      title.textContent = "No matches in view";
      copy.textContent = "The current filters hide every finding. Adjust or clear them to bring results back.";
    }
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  filtered.sort((a, b) => {
    const sevDiff = (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5);
    if (sevDiff !== 0) return sevDiff;
    return (b.riskScore ?? -1) - (a.riskScore ?? -1);
  });

  const groupBy = document.getElementById("groupBySelect").value;
  let lastGroupKey = null;

  filtered.forEach((f, i) => {
    if (groupBy !== "none") {
      const gKey = groupBy === "domain" ? (f.domain || "unknown") : (f.patternName || "unknown");
      if (gKey !== lastGroupKey) {
        lastGroupKey = gKey;
        const groupItems = filtered.filter((x) => (groupBy === "domain" ? (x.domain || "unknown") : (x.patternName || "unknown")) === gKey);
        const maxRisk = Math.max(...groupItems.map((x) => typeof x.riskScore === "number" ? x.riskScore : 0));
        const gTr = document.createElement("tr");
        gTr.className = "group-row";
        const gTd = document.createElement("td");
        gTd.colSpan = 12;
        gTd.textContent = `${groupBy}: ${gKey} (${groupItems.length} finding${groupItems.length === 1 ? "" : "s"} · max risk ${maxRisk})`;
        gTr.appendChild(gTd);
        tbody.appendChild(gTr);
      }
    }

    const sev = f.severity || "medium";
    const tr = document.createElement("tr");
    tr.className = "sev-" + sev;
    if (i < 30) tr.style.setProperty("--i", i);

    const tdNum = document.createElement("td");
    tdNum.textContent = String(i + 1).padStart(2, "0");
    tdNum.className = "td-num";

    const tdSev = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge badge-${sev}`;
    badge.textContent = sev.toUpperCase();
    tdSev.appendChild(badge);

    const tdRisk = document.createElement("td");
    const riskEl = document.createElement("span");
    riskEl.className = "risk-score";
    riskEl.textContent = typeof f.riskScore === "number" ? String(f.riskScore) : "-";
    tdRisk.appendChild(riskEl);

    const tdConf = document.createElement("td");
    const confVal = (f.confidence || "medium").toLowerCase();
    const confEl = document.createElement("span");
    confEl.className = `conf-badge conf-${confVal}`;
    confEl.textContent = confVal;
    tdConf.appendChild(confEl);

    const tdProvider = document.createElement("td");
    tdProvider.textContent = f.provider || "-";
    tdProvider.className = "td-provider";

    const tdPattern = document.createElement("td");
    tdPattern.textContent = f.patternName || "-";
    tdPattern.className = "td-pattern";
    if ((f.occurrenceCount || 1) > 1) {
      const occ = document.createElement("span");
      occ.className = "occ-badge";
      occ.textContent = `×${f.occurrenceCount}`;
      occ.title = `Seen ${f.occurrenceCount} times`;
      tdPattern.appendChild(occ);
    }

    const tdMatch = document.createElement("td");
    const matchCode = document.createElement("code");
    const rawMatch = f.match || "-";
    const maskedMatch = typeof KeyFinderUtils !== "undefined" && f.match
      ? KeyFinderUtils.maskSecret(f.match)
      : rawMatch;
    let isRevealed = false;
    matchCode.textContent = maskedMatch;
    matchCode.className = "match-value";
    matchCode.title = "click to copy";
    matchCode.addEventListener("click", () => {
      navigator.clipboard.writeText(rawMatch);
      flashCopied(copyBtn);
    });
    tdMatch.appendChild(matchCode);

    const tdType = document.createElement("td");
    const typeBadge = document.createElement("span");
    typeBadge.className = "type-badge";
    typeBadge.textContent = f.type || "-";
    tdType.appendChild(typeBadge);

    const tdDomain = document.createElement("td");
    tdDomain.textContent = f.domain || "-";
    tdDomain.className = "td-domain";

    const tdSource = document.createElement("td");
    tdSource.className = "td-source";
    if (f.url && f.url.startsWith("http")) {
      const a = document.createElement("a");
      a.href = f.url;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = truncateUrl(f.url, 30);
      a.title = f.url;
      tdSource.appendChild(a);
    } else {
      tdSource.textContent = f.url ? truncateUrl(f.url, 30) : "-";
    }

    const tdTime = document.createElement("td");
    tdTime.textContent = f.timestamp ? formatTime(f.timestamp) : "-";
    tdTime.className = "td-time";
    if (f.timestamp) tdTime.title = new Date(f.timestamp).toLocaleString();

    const tdActions = document.createElement("td");
    tdActions.className = "td-actions";
    const copyBtn = document.createElement("button");
    copyBtn.className = "btn-icon";
    copyBtn.textContent = "copy";
    copyBtn.title = "Copy match value";
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(f.match || "");
      flashCopied(copyBtn);
    });

    const delBtn = document.createElement("button");
    delBtn.className = "btn-icon btn-icon-danger";
    delBtn.textContent = "del";
    delBtn.title = "Remove finding";
    delBtn.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "removeFinding", findingId: f.id });
      allFindings = allFindings.filter((x) => x.id !== f.id);
      renderStats();
      renderFindings();
      renderTicker();
    });

    const statusSelect = document.createElement("select");
    statusSelect.className = "status-select";
    statusSelect.title = "Finding lifecycle status";
    for (const st of ["open", "acknowledged", "false_positive", "resolved"]) {
      const opt = document.createElement("option");
      opt.value = st;
      opt.textContent = st;
      if ((f.status || "open") === st) opt.selected = true;
      statusSelect.appendChild(opt);
    }
    statusSelect.addEventListener("change", async () => {
      const nextStatus = statusSelect.value;
      await chrome.runtime.sendMessage({ type: "updateFindingStatus", findingId: f.id, status: nextStatus });
      f.status = nextStatus;
    });

    const revealBtn = document.createElement("button");
    revealBtn.className = "btn-icon";
    revealBtn.textContent = "show";
    revealBtn.title = "Reveal or mask secret value";
    revealBtn.addEventListener("click", () => {
      isRevealed = !isRevealed;
      matchCode.textContent = isRevealed ? rawMatch : maskedMatch;
      revealBtn.textContent = isRevealed ? "mask" : "show";
    });

    const whyBtn = document.createElement("button");
    whyBtn.className = "btn-icon";
    whyBtn.textContent = "why";
    whyBtn.title = "View risk factors & remediation";

    tdActions.appendChild(statusSelect);
    tdActions.appendChild(revealBtn);
    tdActions.appendChild(whyBtn);
    tdActions.appendChild(copyBtn);
    tdActions.appendChild(delBtn);

    tr.appendChild(tdNum);
    tr.appendChild(tdSev);
    tr.appendChild(tdRisk);
    tr.appendChild(tdConf);
    tr.appendChild(tdProvider);
    tr.appendChild(tdPattern);
    tr.appendChild(tdMatch);
    tr.appendChild(tdType);
    tr.appendChild(tdDomain);
    tr.appendChild(tdSource);
    tr.appendChild(tdTime);
    tr.appendChild(tdActions);
    tbody.appendChild(tr);

    const detailRow = buildDetailRow(f);
    detailRow.hidden = true;
    whyBtn.addEventListener("click", () => {
      detailRow.hidden = !detailRow.hidden;
      whyBtn.textContent = detailRow.hidden ? "why" : "hide";
    });
    tbody.appendChild(detailRow);
  });
}

function buildDetailRow(f) {
  const tr = document.createElement("tr");
  tr.className = "detail-row";
  const td = document.createElement("td");
  td.colSpan = 12;

  const grid = document.createElement("div");
  grid.className = "detail-grid";

  // Left box: Context & Risk Factors
  const left = document.createElement("div");
  left.className = "detail-box";
  const leftTitle = document.createElement("div");
  leftTitle.className = "detail-title";
  leftTitle.textContent = "Context & Risk Breakdown";
  left.appendChild(leftTitle);

  const ctx = f.context || {};
  const meta = document.createElement("div");
  meta.className = "detail-meta";
  meta.textContent = `env: ${ctx.environment || "unknown"} · surface: ${f.type || "-"} · key: ${ctx.keyName || "-"} · occurrences: ${f.occurrenceCount || 1}`;
  left.appendChild(meta);

  if (ctx.snippet) {
    const snip = document.createElement("code");
    snip.className = "detail-snippet";
    snip.textContent = ctx.snippet;
    left.appendChild(snip);
  }

  const factorsList = document.createElement("ul");
  factorsList.className = "detail-list";
  const factors = Array.isArray(f.riskFactors) && f.riskFactors.length > 0
    ? f.riskFactors
    : ["Legacy finding (no context score recorded)"];
  for (const factor of factors) {
    const li = document.createElement("li");
    li.textContent = factor;
    factorsList.appendChild(li);
  }
  left.appendChild(factorsList);

  // Right box: Remediation Guidance
  const right = document.createElement("div");
  right.className = "detail-box";
  const rem = typeof KeyFinderRemediation !== "undefined"
    ? KeyFinderRemediation.getRemediation(f)
    : { title: "Remediation", summary: "Verify and rotate if active.", steps: [] };

  const rightTitle = document.createElement("div");
  rightTitle.className = "detail-title";
  rightTitle.textContent = rem.title;
  right.appendChild(rightTitle);

  const summary = document.createElement("div");
  summary.className = "detail-meta";
  summary.textContent = rem.summary;
  right.appendChild(summary);

  const stepsList = document.createElement("ul");
  stepsList.className = "detail-list";
  for (const step of rem.steps) {
    const li = document.createElement("li");
    li.textContent = step;
    stepsList.appendChild(li);
  }
  right.appendChild(stepsList);

  grid.appendChild(left);
  grid.appendChild(right);
  td.appendChild(grid);
  tr.appendChild(td);
  return tr;
}

function flashCopied(btn) {
  if (!btn) return;
  btn.textContent = "copied";
  btn.classList.add("copied");
  setTimeout(() => {
    btn.textContent = "copy";
    btn.classList.remove("copied");
  }, 1200);
}

function updateMeta(shown) {
  const metaLine = document.getElementById("metaLine");
  if (metaLine) {
    metaLine.innerHTML = "";
    metaLine.append(
      "showing ",
      strong(shown),
      " of ",
      strong(allFindings.length)
    );
  }
  const shellMeta = document.getElementById("shellMeta");
  if (shellMeta) shellMeta.textContent = shown + (shown === 1 ? " row" : " rows");
}

function strong(n) {
  const el = document.createElement("strong");
  el.textContent = n;
  return el;
}

function renderTicker() {
  const ticker = document.getElementById("ticker");
  const tickerText = document.getElementById("tickerText");
  if (!ticker || !tickerText) return;
  if (!allFindings.length) {
    ticker.hidden = true;
    return;
  }
  const latest = [...allFindings].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))[0];
  tickerText.innerHTML = "";
  const head = document.createElement("span");
  head.textContent = `${latest.provider || "unknown"} · ${latest.patternName || "match"} @ ${latest.domain || "—"} `;
  tickerText.appendChild(head);
  if (latest.match) {
    const code = document.createElement("code");
    code.textContent = truncateUrl(latest.match, 28);
    tickerText.appendChild(code);
  }
  ticker.hidden = false;
}

function truncateUrl(url, max) {
  if (url.length <= max) return url;
  return url.substring(0, max - 3) + "...";
}

function formatTime(ts) {
  const d = new Date(ts);
  const diff = Date.now() - d.getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60);
  if (h < 24) return h + "h ago";
  const days = Math.floor(h / 24);
  if (days < 7) return days + "d ago";
  return d.toLocaleDateString();
}

function exportJson() {
  const mask = document.getElementById("maskExportToggle")?.checked ?? true;
  const filtered = getFiltered().map((f) =>
    mask && typeof KeyFinderUtils !== "undefined" && f.match
      ? { ...f, match: KeyFinderUtils.maskSecret(f.match) }
      : f
  );
  const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: "application/json" });
  downloadBlob(blob, `keyfinder-findings-${Date.now()}.json`);
}

function csvSafe(value) {
  let str = String(value || "");
  if (/^[=+\-@\t\r\n]/.test(str)) str = "'" + str;
  str = str.replace(/"/g, '""');
  return `"${str}"`;
}

function exportCsv() {
  const mask = document.getElementById("maskExportToggle")?.checked ?? true;
  const filtered = getFiltered();
  const headers = ["Severity", "Risk Score", "Confidence", "Status", "Environment", "Provider", "Pattern", "Match", "Type", "Domain", "URL", "Page URL", "Risk Factors", "Timestamp"];
  const rows = filtered.map((f) => [
    csvSafe(f.severity),
    csvSafe(typeof f.riskScore === "number" ? f.riskScore : ""),
    csvSafe(f.confidence || ""),
    csvSafe(f.status || "open"),
    csvSafe((f.context && f.context.environment) || ""),
    csvSafe(f.provider),
    csvSafe(f.patternName),
    csvSafe(mask && typeof KeyFinderUtils !== "undefined" && f.match ? KeyFinderUtils.maskSecret(f.match) : f.match),
    csvSafe(f.type),
    csvSafe(f.domain),
    csvSafe(f.url),
    csvSafe(f.pageUrl),
    csvSafe(Array.isArray(f.riskFactors) ? f.riskFactors.join(" | ") : ""),
    csvSafe(f.timestamp ? new Date(f.timestamp).toISOString() : ""),
  ]);
  const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  downloadBlob(blob, `keyfinder-findings-${Date.now()}.csv`);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function clearAll() {
  if (!confirm("Remove all findings?")) return;
  await chrome.runtime.sendMessage({ type: "clearFindings" });
  await chrome.runtime.sendMessage({ type: "clearRecon" });
  allFindings = [];
  renderStats();
  renderFindings();
  renderTicker();
  renderRecon({});
}

function renderAnalytics() {
  const container = document.getElementById("analyticsContainer");
  const meta = document.getElementById("analyticsMeta");
  if (!container) return;
  container.innerHTML = "";

  const scored = allFindings.filter((f) => typeof f.riskScore === "number");
  const avgRisk = scored.length > 0
    ? Math.round(scored.reduce((s, f) => s + f.riskScore, 0) / scored.length)
    : 0;
  if (meta) meta.textContent = `${allFindings.length} findings · avg risk ${avgRisk}/100`;

  const countTop = (keyFn) => {
    const counts = new Map();
    for (const f of allFindings) {
      const k = keyFn(f) || "unknown";
      counts.set(k, (counts.get(k) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  };

  const renderBox = (titleText, entries) => {
    const box = document.createElement("div");
    box.className = "detail-box";
    const t = document.createElement("div");
    t.className = "detail-title";
    t.textContent = titleText;
    box.appendChild(t);

    if (entries.length === 0) {
      const empty = document.createElement("div");
      empty.className = "detail-meta";
      empty.textContent = "No data yet.";
      box.appendChild(empty);
      return box;
    }

    const max = entries[0][1] || 1;
    for (const [label, count] of entries) {
      const row = document.createElement("div");
      row.className = "bar-row";
      const lbl = document.createElement("span");
      lbl.className = "bar-label";
      lbl.textContent = label;
      lbl.title = label;
      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = "bar-fill";
      fill.style.width = `${Math.max(6, Math.round((count / max) * 100))}%`;
      track.appendChild(fill);
      const val = document.createElement("span");
      val.className = "bar-val";
      val.textContent = String(count);
      row.append(lbl, track, val);
      box.appendChild(row);
    }
    return box;
  };

  container.appendChild(renderBox("Top Domains", countTop((f) => f.domain)));
  container.appendChild(renderBox("Exposure Surfaces", countTop((f) => f.type)));
}

function exportMarkdownReport() {
  const mask = document.getElementById("maskExportToggle")?.checked ?? true;
  const filtered = getFiltered();
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of filtered) counts[f.severity || "medium"] = (counts[f.severity || "medium"] || 0) + 1;
  const reconEntries = Object.values(window.__kfReconCache || {});

  const lines = [
    "# KeyFinder Security Assessment Report",
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Executive Summary",
    `- **Total Findings (Filtered):** ${filtered.length}`,
    `- **Severity Breakdown:** Critical: ${counts.critical}, High: ${counts.high}, Medium: ${counts.medium}, Low: ${counts.low}, Info: ${counts.info}`,
    `- **Recon Domains Recorded:** ${reconEntries.length}`,
    "",
    "## Findings",
    "",
    "| Severity | Risk | Confidence | Status | Provider | Pattern | Match | Domain |",
    "|---|---:|---|---|---|---|---|---|",
    ...filtered.slice(0, 100).map((f) => {
      const m = mask && typeof KeyFinderUtils !== "undefined" && f.match ? KeyFinderUtils.maskSecret(f.match) : (f.match || "-");
      return `| ${(f.severity || "medium").toUpperCase()} | ${f.riskScore ?? "-"} | ${f.confidence || "-"} | ${f.status || "open"} | ${f.provider || "-"} | ${f.patternName || "-"} | \`${String(m).replace(/\|/g, "\\|")}\` | ${f.domain || "-"} |`;
    }),
  ];

  const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
  downloadBlob(blob, `keyfinder-report-${Date.now()}.md`);
}

async function exportConfig() {
  const [kwResp, setResp] = await Promise.all([
    chrome.runtime.sendMessage({ type: "getKeywords" }),
    chrome.runtime.sendMessage({ type: "getSettings" }),
  ]);
  const payload = {
    version: 1,
    keywords: (kwResp && kwResp.keywords) || [],
    settings: (setResp && setResp.settings) || { paused: false, excludedDomains: [] },
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  downloadBlob(blob, `keyfinder-config-${Date.now()}.json`);
}

async function importConfig(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  try {
    const parsed = JSON.parse(await file.text());
    if (parsed.settings) {
      await chrome.runtime.sendMessage({ type: "updateSettings", patch: parsed.settings });
    }
    if (Array.isArray(parsed.keywords)) {
      for (const kw of parsed.keywords) {
        await chrome.runtime.sendMessage({ type: "addKeyword", keyword: String(kw) });
      }
    }
    alert("Configuration imported.");
  } catch {
    alert("Invalid configuration JSON file.");
  } finally {
    e.target.value = "";
  }
}

function renderRecon(reconMap) {
  const container = document.getElementById("reconContainer");
  const meta = document.getElementById("reconMeta");
  if (!container) return;
  const entries = Object.values(reconMap || {});
  if (meta) meta.textContent = `${entries.length} domain${entries.length === 1 ? "" : "s"}`;
  if (entries.length === 0) {
    container.textContent = "No passive recon data recorded yet.";
    return;
  }
  container.innerHTML = "";
  for (const item of entries) {
    const box = document.createElement("div");
    box.className = "detail-box";
    box.style.marginBottom = "10px";

    const title = document.createElement("div");
    title.className = "detail-title";
    title.textContent = `${item.domain} · ${(item.thirdPartyScripts || []).length} 3p scripts · ${(item.sourceMaps || []).length} source maps · ${(item.endpoints || []).length} endpoints`;
    box.appendChild(title);

    if (item.thirdPartyScripts && item.thirdPartyScripts.length > 0) {
      const p = document.createElement("div");
      p.className = "detail-meta";
      p.textContent = "3rd-party scripts: " + item.thirdPartyScripts.map((s) => `${s.origin}${s.hasSri ? " [SRI]" : " [no-SRI]"}`).join(", ");
      box.appendChild(p);
    }
    if (item.sourceMaps && item.sourceMaps.length > 0) {
      const p = document.createElement("div");
      p.className = "detail-meta";
      p.textContent = "Source maps: " + item.sourceMaps.map((m) => m.mapUrl).join(", ");
      box.appendChild(p);
    }
    if (item.endpoints && item.endpoints.length > 0) {
      const p = document.createElement("div");
      p.className = "detail-meta";
      p.textContent = "Endpoints: " + item.endpoints.slice(0, 15).join(", ") + (item.endpoints.length > 15 ? ` (+${item.endpoints.length - 15} more)` : "");
      box.appendChild(p);
    }
    container.appendChild(box);
  }
}
