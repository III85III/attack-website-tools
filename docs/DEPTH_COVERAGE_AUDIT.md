# Qolam_Hacker — implementation audit

## Actual execution path

`WebSecurityTab.start_scan` validates target and supplied plans, confirms target authorization and starts `WebAuditWorker`. The worker invokes `WebAuditorAdapter.run_scan`, saves findings and child engine runs, then performs bounded API discovery/review, declared session review and available ZAP/Nmap integrations. `DatabaseManager` associates children with the assessment; `AssessmentReportActions` and `export_assessment` load that assessment for Word/JSON/Markdown/HTML. The UI display cap does not truncate exports.

The native HTTP client disables redirects, verifies TLS, caps response bodies and counts collection attempts. New shared collection policy adds a 240-request native budget and at least 50 ms between request starts. Browser requests use the separate pre-existing sandboxed verifier and its own limits. Passive CT is a separate third-party request, never authorization to test discovered hosts.

## Coverage matrix grounded in source

| Area | State | Actual implementation and limits |
|---|---|---|
| Authorization/object ownership | Partial | `session_review.validate_plan/run_scan`: supplied identities and explicit read-only resources, denied-marker comparison, anonymous canary control and repeated observations. No object enumeration or independent proof of ownership. |
| Authentication/session behavior | Partial | Session isolation, identity marker checks, response-cookie clearing and secondary identity revalidation. Login, MFA, password reset, logout/revocation and expiration workflows are not automatically exercised. |
| Business workflows | Partial | Explicit read-only content invariants only. State-changing transactions, race conditions and multi-step invariants require developer-provided scenarios. |
| JS/API mapping | Partial, improved | `javascript_analysis.route_literals`, `javascript_assets.audit_assets`, `application_map.ApplicationMap`: bounded same-origin relationships and provenance, parsed source maps and redacted candidate tokens. Dynamic computed routes can be missed. |
| Contextual injection | Partial, improved | Existing HTML context and browser XSS confirmation remain. CORS and arithmetic evidence have independent controls. SQL/error, path and header indicators retain their separate limitations. Stored/blind XSS and exhaustive injection are not claimed. |
| Static source-to-sink analysis | Partial, improved | `javascript_analysis.analyze_flows`: lexical statement-level subset; comments, literal strings, reassignment and scope controls. Not a full AST, interprocedural analyzer or proof of runtime exploitability. |
| API schemas | Partial | `api_review`: OpenAPI/Swagger JSON and bounded anonymous GET review. Discovered definitions reuse validation; references are not downloaded. Full GraphQL authorization, mutation testing and complete schema semantics are not implemented. |
| Differential analysis | Partial, improved | Explicit access expectations and reproducible protected-marker comparisons. Response length/status alone never proves IDOR or authentication bypass. |
| False-positive suppression | Improved within tested subset | Structured map parsing, random CORS origins, two arithmetic challenges, anonymous identity controls, repeated access checks and static lexical negative cases. No universal precision/recall claim. |
| SSRF | Requires declared scenario | Generic server-loopback probes are excluded. Approved callback infrastructure and a reliable fetch oracle are required for verification. |
| Passive subdomain intelligence | Partial | Existing CT integration retained, narrowed to the selected hostname rather than guessing an apex from two labels. Bounded response, source provenance and explicit lack of active authorization. |
| Supply chain | Partial | Existing manifest/advisory hints remain; version matching alone is not exploit verification. Full transitive resolution and an independent dependency audit are not claimed. |

## Baseline and measurement

The pre-upgrade source suite produced **226 passed, 16 failed**. Failures included stale HTTP request expectations, incomplete response mocks, missing required model fields, a mismatched JS audit argument, and the unsigned-JWT extraction bug. Fixtures were corrected to assert the current contracts and actual observed requests; missing status/content fields were not treated as successful collection.

The added labeled lexical corpus has 13 cases: direct/alias/minified/navigation flows plus comments, quoted code, reassignment, safe sinks, sanitization and scope negatives. Its generated `cache/depth_static_metrics.json` reports TP/FP/TN/FN, precision and recall. These are measurements of that narrow corpus only, not estimates for real websites.

Additional loopback fixtures cover real JS/map collection, HTML impersonating JSON, static versus reflecting CORS, server-error CORS, arithmetic evaluation versus literal/fixed responses, ambiguous canaries, transient access, no adjacent-ID guessing, and actual UI plus Word/HTML/Markdown/JSON integration. Final run records are stored locally in `cache/depth_upgrade_0.19.1.xml` and `.log`.

## Remaining limits

No public target was execution-tested for this upgrade. No credentials were checked against external providers. Business logic still requires explicit invariants and synthetic accounts. Dynamic JavaScript, complex scoping, complete login/session lifecycle and stored/blind issues remain coverage gaps. An observed source map or credential-shaped identifier is not proof of a security incident. DOCX generation/reopening is tested; a completed visual Word layout audit and independent security audit are not claimed.

## Exact changed source/document/test files

- `README.md`

- `START HERE.txt`
- `StartSentinel.cs`
- `docs/DEPTH_COVERAGE_AUDIT.md`
- `docs/RELEASE_NOTES_0.19.1.md`
- `docs/USER_GUIDE_EN.md`
- `main.py`
- `package_release.py`
- `src/adapters/api_review.py`
- `src/adapters/javascript_analysis.py`
- `src/adapters/javascript_assets.py`
- `src/adapters/session_review.py`
- `src/adapters/web_auditor.py`
- `src/core/application_map.py`
- `src/core/config.py`
- `src/core/database.py`
- `src/core/privacy.py`
- `src/ui/main_window.py`
- `src/ui/tabs.py`
- `tests/test_api_review.py`
- `tests/test_browser_xss.py`
- `tests/test_depth_upgrade.py`
- `tests/test_reporting.py`
- `tests/test_session_review.py`
- `tests/test_web_auditor.py`

Final source run: **270 passed in 150.80 seconds**. Labeled static subset: TP 4, TN 9, FP 0, FN 0; precision 1.0 and recall 1.0 on those 13 cases only.
