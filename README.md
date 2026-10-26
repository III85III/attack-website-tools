<p align="center"><img src="assets/obsidian.png" width="100" alt="OBSIDIAN logo"></p>
<h1 align="center">OBSIDIAN</h1>
<p align="center"><strong>Web Penetration Testing for Windows</strong><br>Website and API assessment, browser XSS evidence, and reports you can hand to a client.</p>
<p align="center">
<a href="https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0"><strong>Download Windows app</strong></a> ·
<a href="docs/USER_GUIDE_EN.md">Full user guide</a> ·
<a href="docs/DEPTH_COVERAGE_AUDIT.md">Coverage and test evidence</a> ·
<a href="https://github.com/III85III/attack-website-tools/issues/new/choose">Report an issue</a>
</p>
<p align="center">
<a href="https://github.com/III85III/attack-website-tools/actions/workflows/windows.yml"><img src="https://github.com/III85III/attack-website-tools/actions/workflows/windows.yml/badge.svg" alt="Windows checks"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0--only-blue" alt="GPL-3.0-only"></a>
<img src="https://img.shields.io/badge/release-0.20.0_RC-167c8a" alt="0.20.0 release candidate">
</p>

Enter an authorized website URL, select **Scan Website**, then review the evidence and export your report. OBSIDIAN combines a native web assessment with browser-confirmed reflected XSS, JavaScript and API discovery, and explicit test-account access checks. It runs on your computer and supports authorized public websites.

![OBSIDIAN scanner interface](docs/images/scanner.png)

## Install and run

1. Open the [0.20.0 release](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0).
2. Download **`OBSIDIAN_0.20.0_Windows-x64.zip`**. GitHub's automatic source-code archive is not the ready-to-run application.
3. Extract the **entire ZIP** into a normal folder.
4. Open **`OBSIDIAN.exe`**. Keep `_internal` beside it. Python is not required.
5. Read the first-launch notice, enter your authorized URL, then select **Scan Website**.

The Windows download contains **OBSIDIAN.exe**, its required `_internal` folder, documentation and matching source.

Use Windows x64. Browser confirmation needs a normally installed, signed Microsoft Edge or Google Chrome. Optional ZAP and Nmap are installed separately; the app reports when they are unavailable.

### Verify the download

Download `SHA256SUMS_0.20.0.txt` from the same release. In PowerShell, run this from your download folder:

```powershell
Get-FileHash .\OBSIDIAN_0.20.0_Windows-x64.zip -Algorithm SHA256
```

Compare the full result with the matching ZIP entry in the checksum file. The build is unsigned. A checksum checks integrity; it is not a signing certificate.

## What the scan does

| Area | Current behavior |
|---|---|
| Website review | Bounded same-origin crawl, headers, cookies, selected exposures and controlled query checks |
| Reflected XSS | Eligible candidates need matching execution proof in a sandboxed browser before they become validated |
| JavaScript | Literal API route discovery, source-to-sink candidates, parsed source maps and redacted credential-shaped values |
| Application mapping | Pages, forms, scripts, routes and source maps with discovery relationships and redacted query values |
| CORS | Two unpredictable origin probes distinguish arbitrary reflection from a fixed allowlist; data theft is not inferred |
| Template evaluation | Two independent benign arithmetic challenges distinguish evaluated input from reflection or fixed example output |
| API definitions | Automatic discovery or import of OpenAPI 3.0/3.1 and Swagger 2.0 JSON; bounded anonymous GET review |
| SQL error controls | Original input, alphanumeric control and repeated quote responses; potential error disclosure, never automatic SQL injection proof |
| File boundary checks | Explicit synthetic canary engine configuration with negative controls; no automatic sensitive file reads |
| Coverage and reliability | Recorded completed/skipped/blocked/inconclusive checks, redacted request provenance, stop control and target backpressure handling |
| Access expectations | Compare supplied test identities and explicit read-only resources with anonymous controls and repeated observations |
| External tools | Existing origin-scoped ZAP and bounded Nmap integrations when available; compatible third-party report imports |
| Reports | **Word, HTML, Markdown and JSON**, linked to the selected assessment and its engine runs |

One button runs the available pipeline. **Right-click Scan Website** for optional test-account sessions or a manual API definition. Credentials, ownership and business rules cannot be inferred from a URL. Supplying these expectations enables checks that an anonymous scan cannot perform.

Passive certificate-transparency results are discovery leads with provenance. Finding a subdomain does not grant authorization to scan it. See the [coverage audit](docs/OBSIDIAN_AUDIT.md) for implementation details and boundaries.

## Read the results

- **Validated:** a recorded verification method supports the observed behavior. Read its evidence and limits.
- **Potential / scanner reported:** investigate the candidate before presenting it as a confirmed vulnerability.
- **Observed:** an inventory or configuration fact that may be intentional.
- **Partial / failed / not tested:** coverage was limited; this is not a clean bill of health.

Open a finding to review its source, confidence, evidence and remediation. New policy findings include repeatable checks and verification limits. Before sending a report, confirm the target and assessment, then review it for confidential URLs, imported evidence or other customer data.

A changing response size, a successful HEAD request or a public source map does not by itself prove an authorization bypass. The app does not automatically guess adjacent object IDs, send server-loopback SSRF probes, try credentials or execute real business transactions.

## Verification

The source regression suite passed **289 tests**. The frozen EXE completed a synthetic SQL-error assessment with **31 recorded requests matching 31 server-observed requests**, four-response error controls, SQLite persistence, JSON export and request provenance. The verification record distinguishes each runtime test from source tests.

The new local SQL/error and file-canary corpus has **9 labeled cases: 2 true positives, 7 true negatives, 0 false positives and 0 false negatives**. The retained lexical JavaScript corpus has 13 cases. These small corpora do not measure general website accuracy.

[Verification record](docs/verification/VERIFICATION_0.20.0.json) · [Implementation and rename audit](docs/OBSIDIAN_AUDIT.md) · [Release notes](docs/RELEASE_NOTES_0.20.0.md)

This is an unsigned release candidate. A completed visual Word layout audit, independent security audit and universal detection coverage are not claimed. Complex business logic, full session lifecycle, stored/blind XSS and exhaustive dynamic JavaScript analysis still need explicit assessment scenarios and manual review.

## Run from source

Use Windows x64 and Python 3.11. Download and extract **OBSIDIAN_0.20.0_Source.zip** from this release, then open PowerShell in the extracted source folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe main.py
```

Run the regression suite with `.\.venv\Scripts\python.exe -m pytest tests -q`. Browser tests require a trusted system Edge/Chrome and use disposable loopback targets.

To build on Windows:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe build_exe.py
.\.venv\Scripts\python.exe package_release.py
```

Packaging refuses to overwrite an existing version. Keep the complete runtime folder together. macOS and Linux work is preserved in [development/native-platforms](https://github.com/III85III/attack-website-tools/tree/development/native-platforms); native packages are not part of this verified release.

## Privacy, support and license

Scan only within written authorization and the agreed testing window. Active probes can affect a service. Scan history is stored locally; there is no OBSIDIAN cloud analysis service. Passive CT queries disclose the queried hostname to the CT provider. Optional online speech sends selected text to Microsoft's speech service after confirmation; Windows SAPI remains the local alternative.

Never post API keys, cookies, Bearer tokens, customer reports, database files or raw captures in public issues. Use [private vulnerability reporting](https://github.com/III85III/attack-website-tools/security/advisories/new) for security problems in this project.

[Full user guide and troubleshooting](docs/USER_GUIDE_EN.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

**GPL-3.0-only.** See [LICENSE](LICENSE), [COPYRIGHT](COPYRIGHT) and [third-party notices](THIRD_PARTY_NOTICES.md). Dependencies retain their own licenses; optional external tools are separately distributed.
