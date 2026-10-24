# Release Checklist — 0.19.0

## Observed checks

- [x] 227 source tests passed on this Windows environment, including the local HTTP integration target (87.31 seconds).
- [x] Regression: finalizing a scan preserves finding-to-assessment links.
- [x] Word/JSON export one selected assessment, include child engines, exclude other targets, and exceed the UI row limit without truncation.
- [x] Scanner-to-background-export UI regression passed; invalid ZAP API payload and artifact-privacy regressions also passed.
- [x] Scanner and Reports layouts were visually inspected in 0.14.0; 0.19.0 uses a shared background import control.
- [x] Native Nuclei object/array/JSONL imports, failed matcher exclusion, credential filtering, import provenance and report-limit rejection tests passed.
- [x] Background import event-loop responsiveness, duplicate-start prevention, atomic rollback and parser/database-open failure checks passed.
- [x] Malformed generic/SARIF/Hydra records, numeric severity bounds and valid SARIF optional-field regressions passed.
- [x] Tool-health background responsiveness, duplicate-refresh prevention, isolated detector failures and atomic health-row rollback checks passed.
- [x] Initial/follow-up response-body failure, body cap disclosure, Word/JSON limitations and partial pipeline preservation regressions passed.
- [x] Initial non-success HTTP status coverage, unfollowed redirect and Word/JSON limitation regressions passed.
- [x] Responsible-use notice gating, local acknowledgement version/hash, decline startup ordering, save warnings and read-only review tests passed.
- [x] Supplied-session canaries, anonymous/second-account policy, no credential forwarding, read-only assertions, coverage reports and session diagnostic checks passed with synthetic local accounts.
- [x] Word without a scan record and inert-reflection and matching browser-proof XSS reporting regressions passed.
- [x] Matching GPL application source and dependency-license collection are produced by the release packaging command.
- [x] Real signed-browser positive, encoded, plain-text, CSP, redirect, popup/mutation/WebSocket scope, budget, cleanup ownership and unresponsive-page lifetime tests passed.

- [x] OpenAPI/Swagger parser, origin checks, references, operation limits, cookie-free requests, authentication declaration policy, browser XSS and actual Word export regressions passed.

Packaged runtime self-check and ZIP integrity results are recorded in VERIFICATION_0.19.0.json alongside the release artifacts.

## Remaining public stable-release gates

- [ ] Validate install/launch, upgrade, data migration and report opening on clean supported Windows 10/11 machines without development tools.
- [ ] Complete the transitive dependency/native DLL license and source/relink-material audit. Collected license files and a dependency inventory do not finish this audit.
- [ ] Visually review generated Persian Word reports in supported Word versions. Bundled LibreOffice is unavailable in this environment.
- [ ] Add the publisher's code-signing certificate and installer/distribution policy when available.
- [ ] Supply a real support/security contact and vulnerability-disclosure process.

The web scanner performs bounded DAST, optional configured session/access checks and limited reflected-XSS browser confirmation. ZAP/Nmap require separate configuration and user scope confirmation. A clean scan is not proof of complete security. Unknown source archives are never executed automatically.

The release is prepared locally; no public upload, independent security audit, clean-machine validation or signing is implied.
