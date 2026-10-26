# OBSIDIAN BLACKSITE 0.21 — execution audit

Assessment date: 2026-10-27. This is an implementation/fixture audit, not an independent assessment or commercial-scanner comparison.

## Root causes and execution path

The scanner was not entirely passive. `WebSecurityTab.start_scan` creates `WebAuditWorker`; its `WebAuditorAdapter.run_scan` calls `audit_url`, `_crawl_same_origin` and `_probe_query_parameters`. Actual GET requests use `_bounded_get`: exact-origin checks, TLS validation, disabled redirects, response cap, rate limiting, cancellation and a native request budget. Discovery determines which inputs reach probes. Only bounded discovered GET/query inputs were supported; unknown/unlinked, authenticated and application workflow inputs were not implicitly tested. Ten active parameters are a budget, not complete coverage.

`WebAuditWorker.run` stores results with `DatabaseManager`, invokes eligible API/session/external adapters, updates actual request totals and emits stored findings to `_on_scan_finished`. `export_assessment` reloads the selected scan/findings from SQLite; `ReportGenerator.generate_docx` renders that data. Tool availability is checked rather than inferred from executable labels.

Concrete weaknesses repaired:

- Unlinked routes had no traffic-input integration: offline HAR route import now feeds eligible synthetic query inputs into the existing dispatcher after explicit approval. Captured credentials/values/bodies are not replayed.
- Discovery, collection and actual security checks were not separated in one inventory: `route_coverage` now keeps route/method/query/context signatures and real provenance. Collection does not establish safety.
- A single redirect probe could create a validated finding: `_verify_open_redirect` now requires a baseline, relative control and two independent destination matches. Non-reproduction, denial and interrupted checks retain coverage evidence.
- Access setup was hidden behind right-click: a compact visible Assessment setup menu now exposes the existing account comparison. The primary identity is revalidated after unexpected access, so expired/changed sessions become inconclusive.
- SQL probes continued after baseline ambiguity: existing database-error controls now stop early and retain supporting/contradicting observations as bounded hypotheses.
- Overlapping live-crawl/HAR query routes scheduled redundant probes and repeated findings: imported synthetic signatures now defer to existing live crawl defaults. Real crawler value variants are preserved. The frozen-runtime check detected this and the scan-button regression now includes overlapping HAR input.
- Missing application-map state on a failed/mocked collection could raise before returning FAILED: route coverage now tolerates unavailable maps.

## Capability matrix

| Capability | Status | Implementation and evidence |
|---|---|---|
| Actual scan-button HTTP execution | IMPLEMENTED_AND_TESTED | `src/ui/tabs.py`, `src/adapters/web_auditor.py`; `tools/tests/test_controlled_verification.py` clicks the real button/QThread and checks server-observed requests |
| Crawling, query/GET form and JS discovery | PARTIAL | Existing crawler/JS collector; `test_depth_upgrade.py`, `test_web_auditor.py`; no arbitrary SPA/authenticated crawl |
| HAR discovery and eligible synthetic inputs | IMPLEMENTED_AND_TESTED | `src/core/traffic_inventory.py`, `test_blacksite.py`; exact origin, offline/privacy/default discovery-only tests |
| SQL-error controls/hypotheses | IMPLEMENTED_AND_TESTED | `_controlled_sql_error`, `assessment_intelligence.sql_hypothesis`, `test_obsidian.py`; error disclosure only, not proven SQL injection |
| Controlled HTTP open redirect | IMPLEMENTED_AND_TESTED | `_verify_open_redirect`, `test_controlled_verification.py`; verified local positive, benign and fixed-redirect controls |
| Reflected browser XSS | PARTIAL | Existing `src/adapters/browser_xss.py` and `test_browser_xss.py`; requires compatible installed browser; current release does not establish new live-browser proof |
| Template arithmetic / synthetic file boundary | PARTIAL | Existing `_verify_template_arithmetic`, `_verify_file_canary`; arithmetic does not establish command execution; file canary requires declaration |
| Supplied-account access review | IMPLEMENTED_AND_TESTED | `session_review.py`, `test_session_review.py`; synthetic resource markers, repeated comparison, expiry suppression; role/ownership facts are assessor-declared |
| API definition review | PARTIAL | `api_review.py`, API regression tests; bounded declared anonymous GET only |
| Controlled resilience sample | IMPLEMENTED_AND_TESTED | `resilience_review.py`, visible setup, actual worker and Word test; serial only, <=20 requests, <=2/sec, explicit owned/read-only approval and stop thresholds |
| Canonical finding / stable key / report identity | IMPLEMENTED_AND_TESTED | `models.py`, `assessment_intelligence.py`, `export_service.py`; persistent UUID plus derived dedup key; no title-only root-cause merging |
| Saved graph/timeline/confidence/coverage | IMPLEMENTED_AND_TESTED | `intelligence_workspace.py`, `surface_graph.py`, `test_blacksite.py`; graph is observed discovery, UI caps disclosed, legacy coverage unknown |
| Arbitrary PoC/plugin execution | MISSING | No unreviewed exploit loader. Reviewed procedures are implemented directly through scoped adapters |
| Stateful writes and cleanup runner | BLOCKED | No declared reversible workflows/record identifiers; no generic write executor enabled |
| Stored/blind/complete DOM XSS, NoSQL, parser exploits | MISSING | No complete reviewed execution modules; ledger records gaps |
| SSRF callbacks, uploads, mass assignment, tenant/workflow/race logic | BLOCKED | Dedicated executors and synthetic scenarios/callback infrastructure are missing; not silently reported as tested |
| Exploit-chain correlation / saved verification replay | MISSING | Discovery relationships are available; no claim of verified multi-step exploitation |
| Pixel-level Word layout review | BLOCKED | LibreOffice renderer unavailable; DOCX structure/content reopening is tested, visual layout unverified |
| ZAP/Nmap operational assessment | IMPLEMENTED_UNVERIFIED | Existing integrations retained; external engines intentionally unavailable in local integration tests, no public targets scanned |

## Reproducible measurements

`docs/verification/BLACKSITE_BENCHMARK_0.21.0.json` records three synthetic otherwise-unlinked query endpoints. Without HAR: TP 0, TN 2, FP 0, FN 1. With approved HAR discovery: TP 1, TN 2, FP 0, FN 0. Assisted precision/recall are 1.0 only on these three error-disclosure cases; this is not SQL-injection accuracy or universal coverage. The assisted positive checks one of two route signatures (50%), not 100% website coverage.

The redirect corpus has one positive and two negative controls; the test also verifies refusal of out-of-origin/POST/state-changing route requests. Actual GUI-to-Word integration checks matching canonical IDs, validated evidence and server/request counts. Session regression includes identity expiry after a valid baseline. Resilience cases cover completion, backpressure, emergency stop and pre-network policy rejection.

Run from the repository root:

```powershell
python -m pytest tools/tests -q
python tools/build_exe.py
python tools/package_release.py
```

Frozen diagnostics accept loopback targets only: `OBSIDIAN.exe --verify-startup output.json`, `--verify-local-traffic URL capture.har output.json`, and existing local scanner/session/API diagnostics. Diagnostics are not public-target permission controls; normal scans still require operator authorization.

## Delivery boundaries

The product remains OBSIDIAN with BLACKSITE visual/evidence improvements. Historical data/settings paths and immutable older releases retain compatible legacy names. This release is unsigned. It is a usable bounded assessment application, not a complete replacement for an expert-led engagement. No website can be declared secure from zero findings. New creator links are static public GitHub/Telegram destinations; they never upload reports or send messages.

## Change inventory

Engine/network verification: `src/adapters/web_auditor.py`, `src/adapters/session_review.py`, new `src/adapters/resilience_review.py`. Discovery/evidence identity: new `src/core/traffic_inventory.py`, `src/core/assessment_intelligence.py`, plus `src/core/models.py` and `src/core/config.py`. Runtime diagnostics: `src/__main__.py`.

UI: `src/ui/tabs.py`, `main_window.py`, `theme.py`, `hud.py`, `scan_visual.py`; new `intelligence_workspace.py`, `surface_graph.py`, `traffic_import_worker.py`. Reporting: `src/reporting/docx_report.py`. Build/delivery: `tools/StartObsidian.cs`, `tools/package_release.py`.

Tests: new `tools/tests/test_blacksite.py`, `test_controlled_verification.py`; extended `test_session_review.py`, `test_scanner_ui.py`, `test_depth_upgrade.py`, `test_web_auditor.py`, `test_obsidian.py`. Docs: README, English/Persian guides, localized download links, security policy, this audit, release notes and versioned verification records. No dependency was added.

## Final local verification

318 tests passed with zero failures/errors in 149.054 seconds. The final frozen Windows EXE sent 33 loopback HTTP requests; server-observed and recorded counts matched. One redirect finding was VALIDATED and persisted/exported consistently. DOCX reopening passed; visual Word layout remains unverified. Both public creator links were visible. See the versioned verification JSON for code hashes and limits.
