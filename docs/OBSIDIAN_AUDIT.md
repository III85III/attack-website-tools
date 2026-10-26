# OBSIDIAN implementation and rename audit

Audit date: 2026-10-26. Existing project upgraded in place; no second scanner framework. Findings and runtime evidence are not generated from UI progress or finding-count targets.

## Execution path

`main.py` starts Qt and the responsible-use notice. `MainWindow` lazily opens `WebSecurityTab`; `start_scan` validates the URL and asks for scope authorization. `WebAuditWorker.run` stores the parent scan and invokes `WebAuditorAdapter.run_scan`. The adapter runs bounded same-origin collection, application mapping, discovered GET-input checks, browser attempts and evidence sanitation. Optional OpenAPI, declared-session, ZAP and Nmap child runs are persisted under the parent. `DatabaseManager` stores models and structured execution logs. `export_assessment` loads the selected assessment and children, consolidates exact duplicates and dispatches to the existing DOCX/HTML/Markdown/JSON exporters.

## Highest-value weaknesses fixed

1. Query/form context was lost: names were lowercased and defaults replaced with `1`. Discovery now preserves case and available defaults and excludes credential-bearing/disabled/unchecked controls. Endpoint discovery and application relationships remain bounded; this is not a complete runtime call graph.
2. Verification confused errors with proof: SQL errors lacked an original/control baseline; static HTML context could receive CONFIRMED confidence; a system-file-shaped substring could receive Critical. SQL now requires two negative controls and repeated new signatures; static reflection remains a candidate until actual browser proof; file checking needs a declared synthetic canary and controls. No automatic sensitive-file probe remains.
3. Coverage and reporting were incomplete: native requests lacked consistent provenance, no native cancellation existed, backpressure did not stop follow-up collection, and reports retained old names/limits. Real operation coverage and gaps now reach UI, logs and exports. Only identical evidence records are consolidated; different endpoints or observations are preserved.

## Scanner inventory and coverage gaps

| Module | Operations and evidence | Verification and remaining coverage |
|---|---|---|
| `web_auditor.py` | Same-origin GET/HEAD; headers/cookies, selected exposure paths, CORS random-origin controls, four-response SQL error controls, two template arithmetic challenges, approved canary files, redirect/CRLF observations | Partial web coverage. No error-to-SQLi promotion, no automatic Critical file-read claim. GET does not guarantee a target has no side effects. |
| `javascript_assets.py` / `javascript_analysis.py` | Collected JS, literal routes, parsed v3 maps, credential-shaped values with redaction, lexical local aliases and sink candidates | Partial. No provider credential validation; no full AST/interprocedural/runtime taint engine. |
| `browser_xss.py` | Signed system Edge/Chrome, isolated Playwright browser, unique benign computation and matching main-document proof | Reflected candidates only. Missing runtime/version is inconclusive, not a clean result. Stored/blind XSS and exhaustive DOM flows missing. |
| `api_review.py` | OpenAPI/Swagger JSON schema and authentication declarations, bounded anonymous GET and query candidates | Partial. Readability/schema mismatch does not prove private data access. POST/JSON, mass assignment and property ownership need explicit scenarios. |
| `session_review.py` | Provisioned identities, anonymous canary, synthetic expected-content records, isolated cookies, repeated unexpected access and identity revalidation | Partial authorization/ownership coverage. Declared ownership/roles need assessor validation; login/MFA/reset/session revocation and state transitions are not implemented as generic automated tests. |
| `zap_adapter.py` | Existing local API version check, temporary origin-scoped context, bounded spider/active scan, alert parsing | External reported alerts remain source-reported. No live ZAP available in this audit. |
| `nmap_adapter.py` | Existing version check and bounded explicit-host TCP-connect profile | Ports/services only; not web application proof. Nmap 7.99 detected; no public scan executed. |
| `report_import_adapter.py` | Size/record-bounded Nuclei JSONL, SARIF, Nmap XML, supported source JSON and provenance | No tool execution or replay; scanner-reported state retained. |
| `pcap_adapter.py` | Existing supported classic-PCAP parser | Captured traffic evidence, not active vulnerability verification. |
| `defender_adapter.py` | Existing local Windows status and threat evidence | Host protection telemetry, not website scanning. |
| `external_tool_catalog.py` | Existing PATH/archive inventory; no archive execution | Presence is not version/capability proof. No new heavyweight tools installed. |
| `cve_intel.py` | Existing local-cache/version correlation | Correlation is not exploit proof and cache may be stale. |

| Requested category | Status | Evidence boundary |
|---|---|---|
| Authorization and object ownership | Partial | Explicit synthetic multi-identity session cases only; no adjacent ID guessing. |
| Authentication/session behavior | Partial | Canary identity and response-cookie isolation; full lifecycle missing. |
| Business logic/multi-step workflows | Missing generically | Requires application-specific synthetic, reversible workflows. |
| JS/API endpoint mapping | Implemented with limits | Static literal routes, forms and bounded relationships; dynamic routes can be missed. |
| Context-aware injection | Partial | Browser-confirmed reflected XSS when available, repeated template indicators, controlled SQL error disclosure; command injection not implemented. |
| Source-to-sink analysis | Partial | Lexical JS subset; no whole-program source analysis. |
| API schema analysis | Implemented with limits | Supported JSON specs and anonymous read-only operations; no full authorization proof. |
| Differential response analysis | Implemented with limits | Four-response SQL/file controls and declared identity comparisons. |
| Evidence/false-positive suppression | Improved | Controls, provenance, sanitized bodies/headers, distinct confidence and verification state. |

## Tests and measured limits

Baseline: 270 passed. Final source suite: 289 passed in 147.04 seconds. Further targeted checks after the last cancellation/backpressure guards: 28 passed; database/migration/corpus checks: 21 passed. API/report integration: 50 passed. Exact outcomes are in the versioned verification JSON.

The new labeled corpus contains six SQL-error cases (one positive, five negative) and three canary cases (one positive, two negative). TP=2, TN=7, FP=0, FN=0; precision and recall are 1.0 only on these nine synthetic cases. The SQL positive establishes error disclosure, not SQL injection. The canary positive depends on assessor-declared placement. Both positives remain POTENTIAL. Retained JavaScript lexical tests cover 13 cases; no universal accuracy claim.

Tests cover literal reflection, pre-existing database errors, transient errors, access-denied pages, secure responses, repeated canary markers and always-present markers, no-canary zero traffic, scope rejection, budget exhaustion, cancellation, target backpressure, redaction, exact duplicate consolidation, partial/empty reports, legacy state and scan names. Existing browser/session/API/import/UI regressions remain in the suite.

DOCX files were generated from actual runtime evidence and reopened to verify branding, coverage, numbered guidance, redaction and unconfirmed status. Visual page rendering was attempted with the supplied document renderer but failed because LibreOffice `soffice.exe` is absent. Page layout is therefore unverified and not a passed release gate.

## Rename and compatibility

Canonical name: **OBSIDIAN**. Application name/title, scanner labels, notice, HTML/DOCX/JSON/Markdown branding, report filenames/metadata, launcher display/version, build/package names, current guides, issue templates and screenshot use OBSIDIAN. New executable: `OBSIDIAN.exe`; portable package: `OBSIDIAN_0.20.0_Windows-x64.zip`.

Intentional exceptions:

- `sentinel.db` and `%LOCALAPPDATA%/III85III/Qolam Sentinel`: existing state is reused in place. No schema or record rewrite is required; the tested resolver retains both portable and previous per-user state.
- `qolam-sentinel-scan-log-v1`: preserved log schema identifier for existing consumers.
- Historical stored scan/tool names and release notes/verification records: not rewritten. DOCX recognizes both old and new engine names.
- `create_sentinel_icon`, `SentinelHud`: internal import compatibility; canonical `create_obsidian_icon`/`ObsidianHud` aliases are provided.
- `StartSentinel.cs` / class name: existing launcher source filename and entry point retained; displayed product/package paths changed.
- Existing nonce/payload prefixes, reserved `sentinel.invalid` destination, browser proof property, temporary-context names, logger namespaces and speech subprocess environment keys: protocol/internal implementation identifiers, not product display branding. No unrelated external tool/API names changed.
- Existing `assets/sentinel.*` retained for old integrations; current build/docs use matching `assets/obsidian.*` assets.
- Old EXEs, archives, ignored build directories and actual user data are preserved. The original directory name can remain `Qolam_Hacker` without affecting product branding. GitHub repository URL is intentionally unchanged.

The responsible-use notice is reacknowledged for its new displayed identity; stored credentials/settings/history remain untouched.

## Run and report

```powershell
python -m pip install -r requirements.txt
python main.py
```

Enter the explicitly authorized website URL and select Scan Website. Optional synthetic-account/OpenAPI setup remains on the button's context menu. Export Word report from the selected completed/partial/cancelled assessment. Empty or partial output must not be treated as a proof of security.

```powershell
# Release QA only; accepts a disposable loopback URL, not public targets.
python main.py --verify-local-browser http://127.0.0.1:PORT cache/qa.json
python main.py --verify-startup cache/startup.json
python -m pytest tests -q
python build_exe.py
python package_release.py
```

Canary engine setup uses `run_scan(..., options={"deep_scan": True, "file_canaries": [...]})`. Each bounded entry needs `endpoint`, `parameter`, `value`, a synthetic `marker` of at least 24 characters, and `boundary_confirmed: true`. Keep this assessment configuration private. No credential/provider validation or real sensitive file collection is performed.

## Changed files

- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/config.yml`
- `README.md`
- `SECURITY.md`
- `StartSentinel.cs`
- `THIRD_PARTY_NOTICES.md`
- `assets/obsidian.ico`
- `assets/obsidian.png`
- `build_exe.py`
- `docs/ARCHITECTURE.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/OBSIDIAN_AUDIT.md`
- `docs/RELEASE_NOTES_0.20.0.md`
- `docs/RESPONSIBLE_USE.md`
- `docs/SECURITY_MODEL.md`
- `docs/USER_GUIDE_EN.md`
- `docs/USER_GUIDE_FA.md`
- `docs/images/scanner.png`
- `docs/verification/LEGACY_NAMES_0.20.0.json`
- `docs/verification/VERIFICATION_0.20.0.json`
- `main.py`
- `package_release.py`
- `src/__init__.py`
- `src/adapters/base.py`
- `src/adapters/defender_adapter.py`
- `src/adapters/external_tool_catalog.py`
- `src/adapters/nmap_adapter.py`
- `src/adapters/pcap_adapter.py`
- `src/adapters/report_import_adapter.py`
- `src/adapters/session_review.py`
- `src/adapters/web_auditor.py`
- `src/adapters/zap_adapter.py`
- `src/core/config.py`
- `src/core/coverage.py`
- `src/core/cve_intel.py`
- `src/core/database.py`
- `src/core/evidence.py`
- `src/core/models.py`
- `src/core/scope.py`
- `src/core/usage_notice.py`
- `src/reporting/docx_report.py`
- `src/reporting/export_service.py`
- `src/system_guard/monitor.py`
- `src/ui/hud.py`
- `src/ui/main_window.py`
- `src/ui/tabs.py`
- `src/ui/theme.py`
- `src/ui/usage_notice_dialog.py`
- `src/voice/voice_assistant.py`
- `tests/test_api_review.py`
- `tests/test_assessment_exports.py`
- `tests/test_database.py`
- `tests/test_export_privacy.py`
- `tests/test_obsidian.py`
- `tests/test_reporting.py`
- `tests/test_scan_pipeline.py`
- `tests/test_scanner_ui.py`
- `tests/test_web_auditor.py`

## Implementation anchors

- `src/adapters/web_auditor.py:2155`
- `src/adapters/web_auditor.py:1438`
- `src/adapters/web_auditor.py:1479`
- `src/adapters/web_auditor.py:1141`
- `src/core/config.py:14`
- `src/reporting/docx_report.py:366`
- `src/ui/tabs.py:726`
