# OBSIDIAN BLACKSITE 0.21.0

An evidence-focused update to the existing Windows desktop scanner.

- Offline, scoped HAR route import and separately approved synthetic GET query probes.
- Real route/parameter/context coverage, bounded SQL-error hypotheses and stable finding keys.
- Four-response controlled redirect verification, primary-session revalidation and visible Assessment setup.
- Opt-in serial resilience sample with strict request/rate/duration-admission limits and automatic stop conditions; no capacity or DoS claims.
- Saved evidence workspace: actual surface graph, timeline, hypothesis records and confidence inspector.
- Word route coverage and resilience tables; persisted finding IDs agree with UI/JSON.
- Graphite/amethyst appearance and clickable Telegram @parsamzmz / GitHub III85III in the footer.

## Install

Download OBSIDIAN_0.21.0_Windows-x64.zip, verify SHA256SUMS_0.21.0.txt, extract the entire archive into a writable directory and open OBSIDIAN.exe. Keep _internal beside it. Python installation is unnecessary. Scan only owned or explicitly authorized targets. Assessment setup holds optional test accounts, OpenAPI, HAR and owned/read-only resilience setup. Export Word below the scan results or choose history in Reports. Matching source is in OBSIDIAN_0.21.0_Source.zip. For source setup see README and docs/USER_GUIDE_EN.md.

## Verification and limitations

See BLACKSITE_AUDIT.md and docs/verification/VERIFICATION_0.21.0.json for actual results. A three-case HAR-assisted error-disclosure benchmark improved TP from 0 to 1 and FN from 1 to 0 with FP 0; it is not confirmed SQL injection or general accuracy. Redirect proof has vulnerable and benign controls and a real scan-button/database/UI/DOCX test.

No generic autonomous business-logic/exploit-chain engine, state-changing runner, credential attacks, full stored/blind XSS, SSRF callback executor, upload/mass-assignment or complete authenticated crawling is claimed. Missing classes stay visible in coverage. Resilience is serial and measures client-observed endpoint samples only. Word content/structure is reopened; page layout is not visually verified because the renderer is unavailable. The binary is unsigned. Existing releases and user data remain intact.
