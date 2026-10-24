# Mirage Sentinel architecture

## Assessment flow

`main.py` initializes the Windows desktop application after the responsible-use notice.
`src/ui/main_window.py` loads tabs on demand. The Scanner keeps one URL and scan action;
session and API configuration are grouped in Assessment setup.

`WebAuditWorker` runs the native web engine, then configured API/session checks and available
ZAP/Nmap integrations. Engines retain individual scan records linked to the parent assessment.
Incomplete required HTTP collection prevents optional engines from starting; incomplete optional
coverage is retained and reported without discarding existing findings.

## Modules

| Module | Responsibility |
|---|---|
| `src/adapters/web_auditor.py` | Bounded same-origin HTTP collection, web checks and query-input probes |
| `src/adapters/browser_xss.py` | Isolated signed-system-browser execution evidence for eligible reflected input |
| `src/adapters/api_review.py` | Scope-bound OpenAPI/Swagger parsing, anonymous GET assessment and coverage records |
| `src/adapters/session_review.py` | Explicit read-only known-content session and access expectations |
| `src/adapters/zap_adapter.py` | Optional local origin-scoped ZAP API integration |
| `src/adapters/nmap_adapter.py` | Optional Nmap invocation, bounded port configuration and XML parsing |
| `src/adapters/report_import_adapter.py` | Supported report parsing, source provenance and import limits |
| `src/core/models.py` | Dataclasses for findings, scans and tool-health records |
| `src/core/database.py` | SQLite persistence, linked assessments and atomic imports |
| `src/core/privacy.py` | Shared heuristic credential filtering |
| `src/reporting/` | Assessment-specific Word/JSON export with evidence and coverage |
| `src/ui/` | PyQt widgets and background workers for scanning, import, health and export |

The database is `sentinel.db`. Source runs keep state beside the project; frozen installs
use the per-user state path or preserve an existing legacy project database.

## Trust and evidence

Remote responses, definitions and imported reports are untrusted. Definitions do not execute
code or resolve external references. Browser confirmation uses a fresh anonymous context,
retains the browser sandbox and TLS checks, and applies request/lifetime bounds.
Supplied account sessions are not forwarded to that browser or external scanners.

A finding's severity, confidence, source and validation status are separate fields.
Native browser validation requires matching observed execution evidence. Imported scanner
matches and API authentication declaration mismatches are not automatically treated as
confirmed exploitability. See [Security Model](SECURITY_MODEL.md) for precise boundaries.

## Verification and distribution

The Windows suite uses disposable loopback targets and synthetic accounts.
The portable package includes the frozen runtime, matching application source, collected
license documents, dependency metadata and file hashes. Release assets preserve the verified
build snapshot; repository documentation includes publication updates.
