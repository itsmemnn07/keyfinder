# Changelog

All notable changes to KeyFinder are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-11-27

### Added
- **Context-aware detection engine** (`js/context.js`): classifies page environment (`production`, `dev-staging`, `localhost`, `docs-example`), extracts redacted context snippets, detects placeholder/test/public-by-design signals, detects minified/comment contexts, and performs local zero-egress JWT header/claim inspection (`exp`, `alg`, sensitive claims)
- **Risk scoring & confidence** (`js/risk.js`): computes 0–100 `riskScore`, derived `riskLevel` (`critical`/`high`/`medium`/`low`/`info`), `confidence` (`high`/`medium`/`low`), and explainable `riskFactors` per finding
- **Remediation guidance** (`js/remediation.js`): provider- and surface-specific remediation steps displayed in the expandable `why` row drawer on the dashboard
- **Privacy & scope controls**: default secret masking in the dashboard (`show`/`mask` per-row toggle) and exports (`Mask Exports` toggle), Pause/Resume scanning toggle, and per-domain exclusion list in the popup
- **Finding lifecycle & grouping**: per-finding status (`open`, `acknowledged`, `false-positive`, `resolved`) with filter dropdown, occurrence count (`×N`) tracking, and Group-by (`none`, `domain`, `pattern`) view
- **Passive recon engine** (`js/recon.js`): detects `//# sourceMappingURL=` references, high-signal API/auth/admin/webhook endpoints, third-party script origins with SRI status, and cloud storage asset URLs (AWS S3, GCS, Azure Blob) in `recon.log`
- **Analytics, report & config management**: `analytics.log` panel with top domains, exposure surface charts, and average risk score; Markdown report export (`↓ Report`); settings/keywords JSON export and import
- **Evaluation suite** (`eval/`): 24-case labeled synthetic dataset (`eval/dataset.js`), baseline vs. enhanced benchmark runner (`eval/benchmark.html`) measuring Precision, Recall, F1, FPR, and scan latency, plus unit test runners (`eval/step0-tests.html`, `eval/step1-tests.html`)

### Changed
- Findings normalized to Schema v2 (`js/utils.js`) with `occurrenceCount`, `firstSeen`, `lastSeen`, `status`, `riskScore`, `riskLevel`, `riskFactors`, and `context`
- Deduplication key changed to `(domain, url, patternName, match)`, incrementing `occurrenceCount` and updating `lastSeen` on repeat detections
- `js/interceptor-loader.js` buffers up to 200 early `document_start` findings until `content.js` registers its receiver at `document_idle`
- `js/interceptor.js` normalizes relative XHR/fetch URLs against `location.href`

### Fixed
- Azure SAS Token regex in `js/patterns.js` now matches `sig=` at the end of a URL without requiring a trailing `&`
- Consolidated duplicated DOM allowlists and scan helpers in `js/content.js`

## [2.2.1] - 2026-07-18

### Changed
- Anti-slop UI refinement: removed scanline/vignette overlays, colored glows, gradient washes, and card grids in favor of flat value-step surfaces, segmented stat strips with hairline dividers, sharp corners, reverse-video active states and hover emphasis, and a titled-border (`findings.log`) table shell — stricter terminal discipline throughout
- Store listing screenshots regenerated from the flattened UI

## [2.2.0] - 2026-07-18

### Added
- Ops-console UI redesign of the popup and findings dashboard: radar-sweep brand mark, ARMED/PASSIVE status LEDs, scanline texture, monospace UI chrome, and a semantic color system (amber = actions, teal = recovered secrets, red/orange/yellow/teal severity scale)
- Popup: count-up stat numerals, numbered watchlist entries, command-prompt keyword input with glowing focus ring, and a terminal status line typed with the live keyword/finding counts
- Dashboard: clickable severity stat tiles that filter the table, LATEST ticker for the most recent finding, `findings.log` table shell with severity-coded row edges, LED severity badges, click-to-copy match chips, relative timestamps (absolute on hover), skeleton loading rows, staggered first-paint rows, and an animated radar empty state that distinguishes "no findings yet" from "filters hide everything"
- Keyboard shortcuts on the dashboard: `/` focuses search, `Esc` clears and blurs it
- `prefers-reduced-motion` support across all animations

### Fixed
- Severity sort treated `critical` as lowest priority (`severityOrder[s] || 5` maps `critical: 0` to the fallback), so critical findings rendered last; they now lead the table
- Latest-finding ticker no longer stays visible when storage is empty (`display: flex` was overriding the `hidden` attribute)

## [2.1.1] - 2026-05-14

### Added
- `SECURITY.md` with threat model, disclosure policy, and known limitations of the MAIN <-> ISOLATED nonce bridge
- `.github/dependabot.yml` for weekly GitHub Actions version bumps
- `CHANGELOG.md`

### Changed
- CSV export sanitiser now also prefixes cells starting with LF (`\n`), not just `=`, `+`, `-`, `@`, tab, CR
- Popup and results page version label is now read from the manifest at runtime instead of being hardcoded

### Fixed
- Window-global scan in `js/interceptor.js` now runs at `document_start`, `DOMContentLoaded`, and `load`, with per-name dedupe. The previous implementation only scanned at `document_start` when page globals had not yet been assigned, making the entire pass dead code on most real pages

## [2.1.0] - 2026-04-14

### Added
- Per-session nonce validation between MAIN-world interceptor and ISOLATED content script to prevent forged finding injection
- CSV formula-injection sanitiser on findings export
- Serialised storage writes to eliminate cross-tab race conditions
- 5000-finding cap with FIFO eviction
- Per-tab alert badge with red-dot icon overlay when secrets are detected
- MutationObserver scans dynamically-injected DOM nodes for SPA coverage
- Explicit Content Security Policy in Chrome and Firefox manifests
- `js/interceptor-loader.js` for both browsers, replacing direct MAIN-world content script on Firefox so the nonce handoff actually works
- GitHub Actions release pipeline (`.github/workflows/release.yml`): on `v*` tag, build Chrome + Firefox zips, compute SHA256, attach to GitHub Release
- GitHub Actions CI pipeline (`.github/workflows/ci.yml`): manifest JSON validation, Chrome <-> Firefox version parity check, build verification, `web-ext lint` on the Firefox bundle

### Changed
- Keyword input validation: 50 character maximum, 50 keyword maximum
- Findings are now deleted by unique ID instead of URL substring match
- URL parameter scanner uses exact match instead of substring (was matching `author` as `auth`)
- Keyword scanner enforces word boundaries (was matching `key` inside `hotkey`, `monkey`)
- camelCase JS identifiers are now skipped in keyword value matches
- Sentry DSN downgraded from `high` to `low` severity (public by design)

### Fixed
- Stored finding race conditions across concurrent tabs
- False positives from GitHub localStorage caches (`ref-selector:*`, `jump_to:*`, `soft-nav:*`, `COPILOT_*`)
- False positives from common CSRF tokens (`authenticity_token`, `csrf_token`, `__RequestVerificationToken`)
- False positives from keyboard shortcut data attributes (`data-hotkey`, `data-hotkey-scope`)

## [2.0.0] - 2026-04-07

### Added
- Complete rewrite to Manifest V3
- Enterprise-grade secret detection with 80+ regex patterns covering AWS, GCP, Azure, GitHub, GitLab, Stripe, PayPal, Square, Slack, Discord, and more
- Firefox support (MV3, Firefox 128+)
- Privacy policy
- Replaced demo gifs with professional logo

### Removed
- Manifest V2 background page
- Legacy jQuery dependency
