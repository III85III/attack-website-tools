# III85III OBSIDIAN — IMPLEMENTATION PLAN
## Evidence-Driven Windows Cybersecurity Platform

### Milestone Overview

| Milestone | Scope | Status | Verification Method |
|---|---|---|---|
| **M1: Baseline Architecture & Persistence** | Data models, SQLite schema, evidence tracking, fixtures, unit tests | In Progress | `pytest` test suite (models & DB) |
| **M2: Unified GUI & Tool Health** | PyQt6 dark tactical UI (8 tabs), responsive threads, live tool detection | Planned | App launch & UI responsiveness check |
| **M3: Real Nmap Integration** | XML parser with defusedxml, target scope gate, safe scan profiles | Planned | Real localhost scan + fixture tests |
| **M4: OWASP ZAP & Web Security** | Local ZAP API adapter, origin-scoped temporary context, spider + active scan, passive alert parser | Implemented in 0.11.0 | Adapter API and UI integration |
| **M5: System Guard & Windows Defender** | PowerShell Defender integration, process & network monitoring via psutil | Planned | Live telemetry query & verification |
| **M6: Network Traffic & PCAP Analysis** | TShark integration & native PCAP parser, sensitive data redaction | Planned | PCAP parsing tests & interface check |
| **M7: CVE Correlation, Voice & Reports** | Offline CISA KEV / NVD cache, Persian voice (edge-tts/SAPI), DOCX report | Planned | Report generation & speech output check |
| **M8: Packaging & End-to-End Verification** | PyInstaller build, executable launch test, regression suite | Planned | Packaged EXE execution & audit check |

---

### Non-Negotiable Anti-Fabrication Principles
1. **Zero Fake Findings**: Every finding must originate from a verified tool execution or system event with timestamp and raw evidence reference.
2. **Honest Tool Health**: If a tool is missing or unconfigured, report it as `UNAVAILABLE` or `NOT INSTALLED` with installation instructions.
3. **Traceable Confidence**: Separate `Observed` from `Scanner-Reported` and `Validated`.
4. **Scope Control**: Web DAST uses a bounded same-origin crawl and per-target confirmation. Optional Nmap is limited to four common web ports; optional ZAP is constrained to an origin-scoped context.
5. **Zero-API Core**: All primary scanning, auditing, persistence, and reporting must operate completely offline without external paid LLM APIs.
