# Qolam Sentinel 0.15.0

## Native Nuclei report integration

Import Nuclei JSON objects, JSON event arrays and JSONL exports through Findings or Tool Integrations. Each match retains its template ID, target, severity, remediation, optional CVE and CWE identifiers, and bounded request/response evidence. Common credentials are filtered before storage. Encoded templates, curl commands, interaction data and arbitrary metadata are omitted.

Explicit failed matcher records and error events never become vulnerabilities. Their count is recorded and the import is marked PARTIAL. Other imported matches remain SCANNER_REPORTED and require independent validation. An absent matcher-status field is accepted for older exports; this does not establish validation. The export schema supplies no scanner version, so Sentinel does not invent one.

The importer reads files only. It does not install or execute Nuclei, load templates, run commands or contact targets. Import completion describes the file conversion, not the coverage or completion of the original scan.

Schema reference: ProjectDiscovery's official [Nuclei ResultEvent definition](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/pkg/output/output.go) and [template information definition](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/pkg/model/model.go). The pinned schema reference is not a claim about the source report's tool version.

## Import evidence and limits

All supported imports now record file SHA-256, source byte size, imported finding count, elapsed import time and zero network requests in the assessment execution log. The completion reason states that source scan completion is unknown.

SARIF and common JSON collections above 2,000 records are rejected. Nuclei JSONL/arrays above 2,000 records, Nmap imports above 2,000 observations and Hydra imports above 2,000 host/service groups are also rejected. Previous code could silently retain only the first 2,000 findings. No truncated successful assessment is now returned. Split large reports before importing them. Files are still bounded at 50 MB; the read itself now enforces that bound if a file grows after the initial size check.

Import currently runs on the UI thread; large files can briefly pause the interface. This release does not claim a live Nuclei execution integration. See the verification JSON for actual local test/build results and the release checklist for remaining distribution gates.
