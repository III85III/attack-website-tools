# OBSIDIAN 0.20.0

The existing desktop application now uses OBSIDIAN branding. This is an unsigned Windows release candidate, with the existing architecture and integrations retained.

- New frozen installations use `%LOCALAPPDATA%\III85III\OBSIDIAN`. Existing portable or per-user `Qolam Sentinel` databases are used in place. No history, settings or credentials are copied, reset or renamed.
- SQL error checks now compare the original request, an alphanumeric control and two quote requests. Only new repeated database signatures become potential error-disclosure findings. SQL injection or extraction is not inferred.
- Automatic system-file probes and their unsupported Critical classification are replaced by explicitly provisioned synthetic file canaries with two controls and repeated observations. The assessor must declare the boundary. This capability is an engine option; there is no file-canary setup screen.
- GET form discovery preserves parameter case and supplied defaults, omitting passwords, tokens, disabled and unchecked controls.
- Verification coverage, redacted native request provenance, cancellation and stopping after target 429/503 responses are integrated into the existing scanner. Native operations stop before the next request; already-running optional engines finish their bounded operation before the next engine is cancelled.
- Word includes coverage states, evidence prerequisites, numbered reproduction guidance when recorded, and a clear statement when no finding is validated. Exact duplicates are consolidated across exports. HTML and Markdown include readable coverage too.

No heavy dependencies or new external scanner engines were installed. ZAP is unavailable on the verification machine; its existing optional adapter is retained. Tool imports remain source-reported, not independently validated.

The complete source regression suite passed 289 tests. Local labeled SQL/file corpus: 9 cases, 2 true positives, 7 true negatives, 0 false positives and 0 false negatives. These are narrow synthetic error-disclosure/file-canary cases, not general SQL injection or website accuracy measurements.

Actual frozen-runtime and report results are recorded in `docs/verification/VERIFICATION_0.20.0.json`. DOCX generation/reopening and factual checks were exercised. Visual DOCX rendering is unverified because LibreOffice is not installed; the renderer reported `soffice.exe was not found on PATH`.

Stored/blind XSS, command injection, SSRF callbacks, full authentication lifecycle, property-level API authorization, mass assignment and business workflows remain incomplete or require declared synthetic scenarios. No complete-production-readiness or universal coverage claim is made.
