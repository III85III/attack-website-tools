# Qolam Sentinel — User Guide

## Scan a website

1. Enter the website URL in **Scanner**.
2. Select **Scan Website** and confirm that you own the target or have written authorization.
3. Sentinel runs its bounded web assessment. If Nmap is installed, it checks TCP ports 80, 443, 8080, and 8443. If OWASP ZAP is running locally, it also crawls and actively scans within a temporary context restricted to the entered origin.
4. Review the severity summary and double-click a finding to read its evidence and remediation.
5. Use **Export Word report** or **Export JSON** below the results. Export runs in the background; select **Open report** when it finishes.

Active scans can affect the target. Use the scanner only within your written authorization and agreed test window.

## Documented API assessment

Enter the authorized target URL and choose **Assessment setup > Import OpenAPI / Swagger JSON**. JSON definitions up to 2 MB are supported for OpenAPI 3.0/3.1 and Swagger 2.0. Sentinel uses the first declared server only when it matches the exact target origin; unresolved references are never downloaded. Definition examples, tokens and default values are not submitted or persisted. Re-import after changing the target origin. Clear API definition removes the setup without deleting reports.

At scan confirmation, verify that the documented GET routes are read-only. Up to 20 concrete GET operations are requested with synthetic query values; the existing query checks cover up to ten parameters and browser verification up to three candidates within this API engine. These are separate from the website engine's counts and three-candidate budget. Each API request drops cookies received by previous responses. API sessions are anonymous and supplied account sessions are not forwarded. Operation/path server overrides, parameter references, path templates, credential-like query parameters, known state-changing route names, unsupported methods and routes beyond the limit stay NOT_TESTED with a reason.

COLLECTED means the response was received successfully, not that the operation is secure. Non-success responses, body caps and collection failures are inconclusive. Every declared operation remains in Word/JSON, with source SHA-256 and actual HTTP/browser counts. A security requirement in the definition followed by a successful anonymous non-empty response creates only a potential authentication-policy mismatch: stale definitions and intentionally public content must be ruled out. Empty security alternatives correctly permit anonymous access. POST/JSON bodies, path-resource values, full API authorization and business workflows require explicit assessment scenarios.

## Optional tools

- **Browser XSS confirmation:** install Microsoft Edge or Google Chrome normally. Sentinel checks its executable signature and uses a fresh anonymous headless context for up to three raw-reflection candidates during a deep scan. No personal profile or supplied session is loaded. A confirmed result includes parameter, benign payload, browser version and matching expected/observed computation. Inconclusive results do not prove safety. Browser GET counts are separate from native HTTP counts. No browser download occurs.

- **OWASP ZAP:** install separately and run its API locally at `http://127.0.0.1:8080`.
- **Nmap:** install separately and ensure `nmap` is available on `PATH`.
- **TShark:** install Wireshark to inspect additional capture formats.
- **Other security CLIs:** the Tool Integrations page reports which supported tools are detected. Sentinel does not launch these tools automatically. Import compatible SARIF, Nuclei JSON/JSONL, JSON, or XML reports from the Findings page.
- **Your source bundles:** Shannon, Sn1per, Strix, THC Hydra, and Wireshark ZIP files in `Desktop\pen test` appear as **Archive Found** in Tool Integrations. They are source code archives, not installed Windows tools; Sentinel never extracts or executes them. Hydra execution is disabled. Install tools separately from their official sources if you need their standalone applications, then import supported reports.
- **Direct actions:** use **Import Tool Report** on Tool Integrations to import supported SARIF, Nuclei JSON/JSONL, JSON, or Nmap-compatible XML files. Select an archive row and choose **Open Selected Archive Folder** to open its local folder.

## Findings and reports

Findings are stored locally. Use **Findings** to inspect evidence, change validation status, or import a scanner report. In **Reports**, choose a specific assessment from the history. Word and JSON include all findings from that assessment and its optional engine runs. Findings from other targets are excluded; the UI's display limit does not truncate exports. Review reports before sharing them; they can contain target URLs, response details, or imported evidence.

The infinity animation runs only during a visible scan. Actual request count, HTTP status, elapsed time, completion reason, and engine errors appear beside the results. A partial or failed assessment can be exported with its failure details. Finish an active scan/export before closing the app.

## Local data

New Windows installs store data under `%LOCALAPPDATA%\III85III\Qolam Sentinel`. The application does not send telemetry to Sentinel servers. A scan sends requests from this computer to the entered target. Online voice output sends the selected summary to Microsoft Edge TTS; local Windows SAPI remains available.

## Import Nuclei reports

Choose a native Nuclei JSON or JSONL export. Matches retain source severity and are marked scanner-reported. Explicit failed matcher/error records are excluded and recorded as a partial import. Import sends zero network requests; it does not execute templates or validate matches. The execution log includes the source SHA-256 and record counts. Files are limited to 50 MB and 2,000 records (or 2,000 normalized Nmap observations/Hydra service groups). Split larger reports; oversized imports are rejected without silent truncation. Parsing and saving run in the background. The import button stays disabled until completion; the inline message shows the outcome. If parsing or storage fails, no partial imported assessment is saved. Finish active imports before closing Sentinel.

## Invalid imported records

Generic JSON collections must contain objects with a nonempty text title, name, rule or ID. Malformed records are rejected; fix or re-export the report before retrying. SARIF run/result/location structures and Hydra object rows are checked too. A numeric security-severity score must be finite and within 0 through 10 to override the text severity. Invalid scores fall back to the source text severity. This does not validate exploit impact or source scan coverage.

## Check tool availability

Open Tool Integrations to start background availability checks. The status line names the current check. Refresh stays disabled until completion, and repeated requests do not launch more probes. A failed detector is marked EXECUTION_FAILED; remaining checks continue. If results cannot be saved, the page shows a warning. Unverified voice synthesis and cache freshness do not claim readiness. Wait for health checks to finish before closing Sentinel.

## Incomplete response collection

HTTP headers can arrive even when the body later fails. An initial body-read failure is FAILED and retains the received HTTP status. Later collection errors and response body limit hits produce PARTIAL, with limits in the completion reason and JSON execution log. Word includes that reason too. A body exactly at the 1,000,000-byte cap is conservatively partial because the scanner stops there. When the required built-in assessment is not complete, optional engines are not started. Fix connectivity or review coverage before deciding whether to run another assessment.

## Redirects and access-limited responses

An initial non-2xx response is PARTIAL and keeps its actual HTTP status. Redirect destinations are not followed; enter the authorized destination URL separately if needed. HTTP 401/403 indicates limited access, and protected application coverage is unverified. Other non-success initial responses also limit normal application coverage. These limitations appear in Word, JSON and the scanner completion reason. The scanner cannot establish authenticated coverage from a successful status alone.

## First launch and responsible use

Read the responsible-use notice and tick its acknowledgement before continuing. Exit closes the app before opening the workspace. The local record contains notice version/hash, timestamp and app version, without your identity or target, and is never sent to the creators. Updated notice text requires acknowledgement again. Review it anytime using Responsible use notice in the sidebar. This does not replace target-specific permission. Authorized public websites are supported; only the separate release QA diagnostic is restricted to loopback. The popup does not grant target access, amend the included GPL license or establish legal immunity.

## Sessions and access expectations

1. Enter the authorized target URL, then choose Assessment setup > Test sessions / access rules.
2. Paste a Cookie request-header value or Bearer token for your test account. Use an existing authorized session; do not paste passwords. Sessions remain in app memory until cleared or exit.
3. Enter a read-only account-identifying path and unique non-secret text from that page. Supply distinct account text and a separate session for the optional second account. HTTP 200 by itself does not establish a valid session.
4. Add explicit read-only paths or GET API URLs. Give a unique marker proving the primary account sees the expected content. Tick Anonymous allowed or Second account allowed only when that identity should see this content. An unchecked box declares expected denial.
5. Optionally enter forbidden primary-response text as a read-only business expectation. This checks content only; it does not exercise purchases, refunds or state-changing workflows.
6. Confirm the paths are authorized and genuinely read-only, apply setup, then Scan Website. Remote sessions require HTTPS. Setup is revalidated if the target changes.
7. Review PASS, FAIL and INCONCLUSIVE outcomes in Word/JSON. PASS applies only to that declared expectation, not overall site security. Missing/expired sessions and unproven markers are inconclusive. Account identity, roles and exploit impact require review.
8. Clear session setup when finished. No raw Cookie/Bearer value, identifying text or response body is written to the report. Session credentials are never forwarded to optional external engines.

The dedicated release diagnostic is loopback-only and uses synthetic local plan files for QA; it is separate from the public-website GUI workflow.
