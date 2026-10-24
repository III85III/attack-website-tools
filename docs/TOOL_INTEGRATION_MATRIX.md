# Tool integration matrix — 0.19.0

| Component | Implemented behavior | Availability |
|---|---|---|
| Native web engine | Bounded same-origin crawl, transport/headers/cookies, selected exposures, CORS and query probes | Included |
| Browser XSS confirmation | Unique benign computation verified in the main document; up to three candidates per engine | Bundled Playwright; requires a signed system Edge/Chrome |
| OpenAPI / Swagger | Local JSON definition import, bounded anonymous GET assessment, explicit exclusions and evidence | Included |
| Session/access review | Supplied read-only paths, known-content baseline and anonymous/second-account comparisons | Optional assessor configuration |
| Nmap | TCP Connect checks on ports 80, 443, 8080 and 8443 of the confirmed host | Separate optional installation |
| OWASP ZAP | Local API, temporary origin-restricted context, spider, active scan and reported alerts | Separate optional installation and running API |
| PCAP | Supported classic-PCAP inspection | Included parser; TShark remains a separate tool |
| Microsoft Defender | Read local status/detections when supported by Windows policy and permissions | Windows-dependent |
| CVE correlation | Local lookup/cache; no startup feed download | Included; data may be stale or incomplete |
| Speech | Local Windows SAPI; optional explicit online Edge TTS | Windows/online service dependent |
| Report import | Supported Nuclei, SARIF, generic JSON and Nmap-compatible XML with provenance | Included; imports do not execute tools |

The inventory also recognizes selected optional security CLIs and supported source ZIP
patterns. Detection does not imply installation, successful execution or scan coverage.
Unknown archives are not extracted or executed automatically.

## Scope

The product performs bounded web penetration testing and assessment tasks.
Stored/blind XSS, exhaustive DOM coverage, POST/JSON execution and full business workflows
are not automatically covered. Request and browser counts, exclusions and incomplete states
remain visible in reports. A clean result is not proof of security.

See [User Guide](USER_GUIDE_EN.md) and [Security Model](SECURITY_MODEL.md).
