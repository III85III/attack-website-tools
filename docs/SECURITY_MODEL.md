# Security Model

## Product boundary

OBSIDIAN is a local Windows desktop assessment workbench. It is not a hosted scanner, a vulnerability-management service, or a substitute for an authorized professional penetration test. The user is responsible for target ownership, written authorization, and the impact of scans.

## Network behavior

- Web requests go from the user's computer to the entered HTTP/S target. A per-target confirmation is required before each scan.
- The native HTTP collector uses GET-only requests, bounds same-origin crawl to 25 pages, disables redirects, verifies TLS, caps response analysis at 1 MB and disables environment proxies. The separate browser verifier has the boundary described below.
- The deep profile adds one arbitrary-Origin CORS check and at most 10 discovered query parameters. It sends a unique inert reflection marker and one single-quote input per parameter. Up to three raw HTML reflection candidates receive an additional benign JavaScript computation probe in an isolated browser. No personal session or supplied credentials are forwarded to that browser; it submits no forms or data-changing methods.
- When installed, OWASP ZAP uses a temporary context constrained to the entered origin for crawling and active scanning. Active probes can affect the service; only use them with explicit written authorization. ZAP is not bundled, and alerts remain scanner-reported until manually validated.
- The built-in scanner does not perform brute force, login attempts or server-side command execution. Browser confirmation only observes the benign client-side computation described below. The optional ZAP active scanner runs ZAP's enabled active rules; their impact depends on the installed ZAP scan policy.
- Nmap is optional. The unified scanner invokes it only after the per-target authorization confirmation and limits its TCP Connect scan to ports 80, 443, 8080, and 8443 on the entered hostname/IP.
- CISA KEV updating is not performed on normal startup. It is a network operation if invoked.
- Online speech is opt-in. The text selected for speech is sent to Microsoft Edge TTS only after a confirmation dialog; Windows SAPI is the default local option.
- There is no OBSIDIAN telemetry endpoint or background cloud scanner.

## Local data

Scan records are stored in SQLite and reports are written locally. New frozen installs use `%LOCALAPPDATA%\III85III\OBSIDIAN`. Raw HTTP response bodies are not stored as full pages; findings may include response headers, paths, banners, imported evidence, and target URLs. Treat generated reports and imported scanner files as sensitive.

## Trust boundaries and input handling

- Target URLs, remote headers, HTML, imported files, Nmap XML, and scan outputs are untrusted.
- Imports are size-bounded; XML is parsed with `defusedxml`; subprocesses use argument arrays with `shell=False`; Nmap port input accepts only numeric ports/ranges.
- Imported reports remain scanner-reported until manually validated; evidence is not silently promoted to confirmed vulnerabilities.
- Word/JSON exports filter all model fields using the shared privacy filter. Structured logs and imported text use the same filter, including full authentication/cookie headers and common credential URL parameters. ZAP alert evidence is filtered before normalization/storage. Filtering is heuristic; review reports before sharing them.
- A successful ZAP HTTP response with a missing/malformed alerts array or API error is a collection failure. Only an explicit valid empty alerts list counts as zero reported alerts.

## OpenAPI input and live API review

Only local JSON definitions up to 2 MB are parsed; duplicate keys, non-finite JSON constants, unsupported versions and invalid structures are rejected. At most 250 paths and 500 operations are imported. No external reference resolution or schema code execution occurs. The first server must match the exact target scheme/host/port; concrete paths reject encoding, traversal, credentials and fragments. Per-operation server overrides and resource templates are excluded with reasons. The complete plan is revalidated against the entered target before API traffic.

The API engine uses a separate anonymous native collector, clearing response cookies before every request. It does not receive supplied session headers or use schema examples/defaults as values. Up to 20 GET operations and ten query parameters are assessed, with up to three isolated browser confirmations in this engine. Non-GET methods, known state-changing paths, unresolved references and credential-like query inputs are recorded as not tested. A GET can still change state on a poorly designed service; the assessor must verify the read-only scope at confirmation. API response analysis shares the native 1 MB cap; browser limits remain separate. Schema authentication declarations are untrusted policy evidence: a mismatch is potential, not proof of sensitive-data access or validated authorization bypass. No blanket API safety is inferred from HTTP 200 or zero findings.

## Known limits

The built-in deep profile is bounded DAST, not a full penetration test. It cannot cover POST/JSON inputs, stored/blind XSS, exhaustive DOM analysis or full business logic. Up to three raw HTML reflection candidates receive a benign browser execution probe; only observed main-document execution is validated. All other reflection and database error candidates require further review. Authenticated read-only checks require explicit supplied-session configuration. CVE matching is a limited heuristic and the offline seed is not a full current vulnerability database. Defender and process/socket visibility vary by Windows configuration and permissions. The application has not received an independent security audit.

## Browser validation boundary

Only fixed system Edge/Chrome installation paths with a valid vendor Authenticode signature are launched. Playwright uses a temporary anonymous context, Chromium sandbox enabled, certificate verification enabled, service workers blocked, no granted permissions and downloads disabled. Browser contexts and processes are closed after each candidate. Requests are limited to 20 GET attempts per candidate and the exact original origin; redirects, child-frame navigation, additional main-frame navigation, off-origin requests, WebSockets and mutations are blocked. There is a navigation/proof time window; failure remains inconclusive. The browser network stack is distinct from requests: its requests are counted separately and browser response bodies do not use the native HTTP collector's 1 MB analysis cap. Origin routing is an application constraint, not an operating-system network sandbox. Third-party assets being blocked can reduce coverage. Only the injected parameter can set the random computed proof; the evaluator reads it without initializing it. No screenshot, response body, cookies or existing query values are retained in proof records.

## Reporting a vulnerability in OBSIDIAN

Do not include real target credentials, customer data, or live exploit payloads in a public issue. Until a maintainer contact is published, keep reports private to the project owner.

## Supplied-session review

Session/access checks use explicit same-origin read-only GET paths with a primary known-content baseline. A second account and anonymous identity are isolated, and the anonymous cookie jar is cleared between paths. Remote credentials require HTTPS; redirects and unsafe methods are not followed. Credentials remain in memory in the GUI and are cleared from worker/session references after use. This is not secure memory zeroization or proof of account identity. No login, MFA or state-changing business workflow is automatically tested. Reports contain outcomes and response hashes rather than response bodies or header secrets. Read-only content assertions and access matches remain potential/scanner-reported findings until reviewed.
