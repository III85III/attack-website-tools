"""Import external security-tool reports without executing the source tools.

Supported formats are SARIF 2.1.0, Nuclei JSON/JSONL, Nmap XML, Hydra JSON, and a
small set of common JSON finding collections. Imported results are always
scanner-reported; this adapter never promotes a report to a validated finding.
Credential values from Hydra output are deliberately discarded.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import defusedxml.ElementTree as ET

from src.adapters.nmap_adapter import NmapAdapter
from src.core.privacy import sanitize_text
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
)


MAX_REPORT_BYTES = 50 * 1024 * 1024
MAX_IMPORTED_FINDINGS = 2_000


def _check_limit(count: int) -> None:
    if count > MAX_IMPORTED_FINDINGS:
        raise ValueError(
            f"Report exceeds the {MAX_IMPORTED_FINDINGS} record import limit. "
            "Split the report into smaller files; no truncated assessment was imported."
        )


def _text(value: Any, limit: int = 3000) -> str:
    if isinstance(value, dict):
        value = value.get("text") or value.get("markdown") or value.get("message") or ""
    if not isinstance(value, str):
        value = str(value or "")
    return _redact(value[:limit])


def _redact(value: str) -> str:
    """Remove common credential/token forms before anything reaches the DB."""
    return sanitize_text(value)


def _severity(value: Any, security_severity: Any = None) -> FindingSeverity:
    try:
        score = float(security_severity)
    except (TypeError, ValueError, OverflowError):
        score = -1
    if isinstance(security_severity, bool) or not math.isfinite(score) or not 0 <= score <= 10:
        score = -1
    if score >= 9:
        return FindingSeverity.CRITICAL
    if score >= 7:
        return FindingSeverity.HIGH
    if score >= 4:
        return FindingSeverity.MEDIUM
    if score > 0:
        return FindingSeverity.LOW
    if score == 0:
        return FindingSeverity.INFO

    normalized = str(value or "").strip().lower()
    if normalized in {"critical", "blocker"}:
        return FindingSeverity.CRITICAL
    if normalized in {"high", "error"}:
        return FindingSeverity.HIGH
    if normalized in {"medium", "moderate", "warning"}:
        return FindingSeverity.MEDIUM
    if normalized in {"low"}:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def _first(mapping: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return default


class ReportImportAdapter:
    """Convert supported scanner exports to OBSIDIAN evidence records."""

    def import_file(self, file_path: str | Path) -> Tuple[ScanRun, List[Finding]]:
        started = time.monotonic()
        path = Path(file_path)
        if not path.is_file():
            raise ValueError("گزارش انتخاب‌شده پیدا نشد.")

        size = path.stat().st_size
        if size <= 0:
            raise ValueError("فایل گزارش خالی است.")
        if size > MAX_REPORT_BYTES:
            raise ValueError(f"حجم گزارش بیش از حد مجاز ({MAX_REPORT_BYTES // (1024 * 1024)} مگابایت) است.")

        with path.open("rb") as source:
            raw = source.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("Report exceeds the 50 MB import limit.")
        digest = hashlib.sha256(raw).hexdigest()
        scan = ScanRun(
            tool_name="External Report Import",
            target=path.name,
            raw_command=f"import-report sha256:{digest}",
        )

        try:
            decoded = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("فقط گزارش‌های متنی UTF-8 پشتیبانی می‌شوند.") from exc

        stripped = decoded.lstrip()
        if stripped.startswith("<"):
            findings = self._import_xml(decoded, path.name, scan, digest)
        else:
            try:
                payload = json.loads(decoded)
            except json.JSONDecodeError as exc:
                # JSONL is accepted only as strict Nuclei event records, never as
                # an accidental recovery of a malformed generic JSON report.
                payload = []
                for line_number, line in enumerate(decoded.splitlines(), 1):
                    if not line.strip():
                        continue
                    try:
                        payload.append(json.loads(line))
                    except json.JSONDecodeError:
                        raise ValueError(f"Invalid JSONL record at line {line_number}.") from exc
                    _check_limit(len(payload))
            if isinstance(payload, list) or self._is_nuclei(payload):
                rows = payload if isinstance(payload, list) else [payload]
                findings = self._import_nuclei(rows, path.name, scan, digest)
            elif not isinstance(payload, dict):
                raise ValueError("Report must contain a JSON object or Nuclei event array.")
            elif self._is_sarif(payload):
                findings = self._import_sarif(payload, path.name, scan, digest)
            elif self._is_hydra(payload):
                findings = self._import_hydra(payload, path.name, scan, digest)
            else:
                findings = self._import_generic_json(payload, path.name, scan, digest)

        if scan.status == "RUNNING":
            scan.status = "COMPLETED"
        scan.end_time = datetime.now(timezone.utc).isoformat()
        scan.findings_count = len(findings)
        scan.duration_ms = max(0, int((time.monotonic() - started) * 1000))
        scan.completion_reason = (
            "Report import finished. No network requests were sent and the source scan's "
            "coverage or completion was not independently verified."
        )
        scan.execution_log.append({
            "phase": "report_import", "status": scan.status,
            "source_report": _text(path.name, 250), "source_sha256": digest,
            "source_bytes": len(raw), "imported_findings": len(findings),
            "network_requests": 0,
        })
        return scan, findings

    @staticmethod
    def _is_nuclei(payload: Any) -> bool:
        return isinstance(payload, dict) and "template-id" in payload and "info" in payload

    def _import_nuclei(self, rows: List[Any], filename: str, scan: ScanRun, digest: str) -> List[Finding]:
        """Read ResultEvent data only; never execute templates or curl commands."""
        _check_limit(len(rows))
        if not rows:
            raise ValueError("An empty array cannot identify a Nuclei report.")
        findings: List[Finding] = []
        skipped = 0
        for number, row in enumerate(rows, 1):
            if not self._is_nuclei(row):
                raise ValueError(f"Record {number} is not a Nuclei event.")
            info = row["info"]
            if (not isinstance(row["template-id"], str) or not row["template-id"].strip()
                    or not isinstance(info, dict) or not isinstance(info.get("name"), str)
                    or not info["name"].strip()):
                raise ValueError(f"Nuclei record {number} lacks a template ID or finding name.")
            matcher = row.get("matcher-status")
            if "matcher-status" in row and not isinstance(matcher, bool):
                raise ValueError(f"Invalid matcher status at Nuclei record {number}.")
            if matcher is False or row.get("error"):
                skipped += 1
                continue
            target = row.get("matched-at") or row.get("url") or row.get("host")
            if not isinstance(target, str) or not target.strip():
                raise ValueError(f"Nuclei record {number} has no target.")
            template = _text(row["template-id"], 180)
            target = _text(target, 2000)
            # Retain an allowlist. Encoded templates, commands, interactions and
            # arbitrary metadata can contain executable text or credentials.
            evidence = {
                "source_report": _text(filename, 250), "source_sha256": digest,
                "template_id": template, "matcher_name": _text(row.get("matcher-name"), 200),
                "matcher_status": matcher, "protocol": _text(row.get("type"), 60),
                "matched_at": target, "timestamp": _text(row.get("timestamp"), 100),
                "request": _text(row.get("request"), 12000),
                "response": _text(row.get("response"), 12000),
                "extracted_results": [_text(v, 1000) for v in row.get("extracted-results", [])[:20]]
                if isinstance(row.get("extracted-results"), list) else [],
            }
            classification = info.get("classification")
            cwe, cve = self._extract_ids(template + " " + json.dumps(classification, ensure_ascii=False))
            findings.append(Finding(
                scan_id=scan.id, title=_text(info["name"], 220),
                description=_text(info.get("description"), 3000) or _text(info["name"], 220),
                source_tool="Nuclei (report import)", tool_version="Not supplied by report",
                target=target, severity=_severity(info.get("severity")),
                severity_source="Nuclei template severity reported by source tool",
                confidence=FindingConfidence.MEDIUM,
                confidence_justification="Imported scanner match; OBSIDIAN has not independently validated it.",
                status=FindingStatus.SCANNER_REPORTED,
                evidence_raw=json.dumps(evidence, ensure_ascii=False),
                evidence_summary=f"{template}: {evidence['matcher_name'] or 'template match'}",
                cwe_id=cwe, cve_id=cve, affected_component=target,
                remediation=_text(info.get("remediation"), 1500)
                or "Review the source template and reproduce safely within the authorized scope.",
            ))
        scan.tool_name = "Nuclei JSON/JSONL Import"
        scan.target = _text(filename, 250)
        scan.execution_log.append({"phase": "nuclei_import", "source_records": len(rows),
                                   "failed_or_error_records_skipped": skipped,
                                   "duplicate_matches_removed": len(findings) - len(self._deduplicate(findings))})
        if skipped:
            scan.status = "PARTIAL"
            scan.error_message = f"{skipped} failed matcher or error record(s) excluded; source scan completion unknown."
        return self._deduplicate(findings)

    @staticmethod
    def _is_sarif(payload: Dict[str, Any]) -> bool:
        return str(payload.get("version", "")).startswith("2.1") and isinstance(payload.get("runs"), list)

    @staticmethod
    def _is_hydra(payload: Dict[str, Any]) -> bool:
        generator = payload.get("generator")
        return isinstance(generator, dict) and str(generator.get("software", "")).lower() == "hydra" and isinstance(payload.get("results"), list)

    def _import_xml(self, xml_text: str, filename: str, scan: ScanRun, digest: str) -> List[Finding]:
        try:
            root = ET.fromstring(xml_text)
        except Exception as exc:
            raise ValueError(f"ساختار XML گزارش معتبر نیست: {exc}") from exc
        if root.tag != "nmaprun":
            raise ValueError("XML فعلاً فقط در قالب Nmap-compatible (از جمله خروجی XML بعضی حالت‌های Sn1per) پشتیبانی می‌شود.")

        scan.tool_name = "Nmap-compatible XML Import"
        findings, error = NmapAdapter().parse_xml_output(xml_text, scan.id, filename)
        if error:
            raise ValueError(error)
        source_name = "Sn1per / Nmap XML" if "sniper" in filename.lower() else "Nmap XML Import"
        version = root.attrib.get("version", "Unknown")
        for finding in findings:
            finding.source_tool = source_name
            finding.tool_version = version
            finding.status = FindingStatus.OBSERVED
            finding.confidence = FindingConfidence.HIGH
            finding.confidence_justification = "پورت باز مستقیماً در خروجی ساختاریافتهٔ Nmap-compatible گزارش شده است؛ این مورد آسیب‌پذیری را اثبات نمی‌کند."
            finding.evidence_raw = json.dumps(
                {
                    "source_report": filename,
                    "source_sha256": digest,
                    "nmap_version": version,
                    "port_observation": finding.evidence_raw,
                },
                ensure_ascii=False,
            )
        _check_limit(len(findings))
        return findings

    def _import_sarif(self, payload: Dict[str, Any], filename: str, scan: ScanRun, digest: str) -> List[Finding]:
        for run in payload["runs"]:
            if not isinstance(run, dict):
                raise ValueError("Every SARIF run must be an object.")
            tool = run.get("tool", {})
            if not isinstance(tool, dict) or not isinstance(tool.get("driver", {}), dict):
                raise ValueError("SARIF tool and driver must be objects.")
            driver = tool.get("driver", {})
            rules = driver.get("rules", [])
            if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
                raise ValueError("SARIF driver rules must be an array of objects.")
            if any(not isinstance(rule.get("properties", {}), dict) for rule in rules):
                raise ValueError("SARIF rule properties must be an object.")
            rows = run.get("results", [])
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError("SARIF results must be an array of objects; no records were skipped.")
            for row in rows:
                if "ruleId" in row and not isinstance(row["ruleId"], str):
                    raise ValueError("SARIF rule ID must be text.")
                if "message" in row:
                    message = row["message"]
                    if (not isinstance(message, (str, dict))
                            or isinstance(message, dict) and not any(
                                isinstance(message.get(key), str) and message[key].strip()
                                for key in ("text", "markdown"))):
                        raise ValueError("SARIF message must contain text or markdown.")
                if not _text(row.get("ruleId"), 180).strip() and not _text(row.get("message"), 3000).strip():
                    raise ValueError("SARIF result needs a rule ID or message.")
                locations = row.get("locations", [])
                if not isinstance(locations, list) or any(not isinstance(loc, dict) for loc in locations):
                    raise ValueError("SARIF locations must be an array of objects.")
                for loc in locations:
                    physical = loc.get("physicalLocation", {})
                    if (not isinstance(physical, dict)
                            or not isinstance(physical.get("artifactLocation", {}), dict)
                            or not isinstance(physical.get("region", {}), dict)):
                        raise ValueError("Invalid SARIF physical location structure.")
        _check_limit(sum(len(run.get("results", [])) for run in payload.get("runs", [])
                         if isinstance(run, dict) and isinstance(run.get("results"), list)))
        results: List[Finding] = []
        driver_names: List[str] = []
        for run in payload.get("runs", []):
            if not isinstance(run, dict):
                continue
            driver = run.get("tool", {}).get("driver", {})
            if isinstance(driver, dict) and driver.get("name"):
                driver_names.append(_text(driver["name"], 120))
            rules = {}
            if isinstance(driver, dict):
                rules = {
                    str(rule.get("id")): rule
                    for rule in driver.get("rules", [])
                    if isinstance(rule, dict) and rule.get("id")
                }
            for item in run.get("results", []):
                if not isinstance(item, dict):
                    continue
                rule_id = _text(item.get("ruleId") or "scanner-result", 180)
                rule = rules.get(rule_id, {})
                props = rule.get("properties", {}) if isinstance(rule, dict) else {}
                message = _text(item.get("message"), 3000) or _text(rule.get("shortDescription"), 500) or rule_id
                title = _text(rule.get("shortDescription") or rule.get("name") or rule_id, 220)
                if not title:
                    title = rule_id
                location = self._sarif_location(item)
                severity = _severity(item.get("level"), props.get("security-severity"))
                cwe, cve = self._extract_ids(rule_id + " " + message + " " + json.dumps(props, ensure_ascii=False))
                evidence = {
                    "source_report": filename,
                    "source_sha256": digest,
                    "sarif_version": payload.get("version"),
                    "rule_id": rule_id,
                    "level": item.get("level"),
                    "location": location,
                    "message": message,
                    "fingerprints": self._safe_fingerprints(item.get("partialFingerprints", {})),
                }
                target = location.get("uri") or filename
                results.append(Finding(
                    scan_id=scan.id,
                    title=title,
                    description=message,
                    source_tool=_text(driver.get("name", "SARIF scanner"), 120) if isinstance(driver, dict) else "SARIF scanner",
                    tool_version=_text(driver.get("semanticVersion") or driver.get("version") or "Unknown", 80) if isinstance(driver, dict) else "Unknown",
                    target=_text(target, 500),
                    severity=severity,
                    severity_source="SARIF level/security-severity reported by source tool",
                    confidence=FindingConfidence.MEDIUM,
                    confidence_justification="Imported scanner report; OBSIDIAN has not independently validated this result.",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=json.dumps(evidence, ensure_ascii=False),
                    evidence_summary=f"{rule_id}: {location.get('uri', 'location not supplied')}"[:500],
                    cwe_id=cwe,
                    cve_id=cve,
                    affected_component=location.get("uri") or None,
                    remediation=_text(rule.get("help") or rule.get("helpUri"), 1500) or "Review the source report and reproduce safely within the authorized scope.",
                ))

        tool_name = ", ".join(dict.fromkeys(driver_names)) or "SARIF scanner"
        scan.tool_name = f"{tool_name} (SARIF Import)"
        scan.target = filename
        return self._deduplicate(results)

    @staticmethod
    def _sarif_location(item: Dict[str, Any]) -> Dict[str, Any]:
        locations = item.get("locations")
        if not isinstance(locations, list) or not locations:
            return {}
        physical = locations[0].get("physicalLocation", {}) if isinstance(locations[0], dict) else {}
        artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
        region = physical.get("region", {}) if isinstance(physical, dict) else {}
        return {
            "uri": _text(artifact.get("uri", ""), 500),
            "start_line": region.get("startLine"),
            "start_column": region.get("startColumn"),
        }

    def _import_hydra(self, payload: Dict[str, Any], filename: str, scan: ScanRun, digest: str) -> List[Finding]:
        generator = payload.get("generator", {})
        scan.tool_name = "THC Hydra JSON Import"
        scan.target = _text(generator.get("server") or filename, 500)
        version = _text(generator.get("version") or "Unknown", 100)
        rows = payload.get("results", [])
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError("Hydra results must contain only objects; no records were skipped.")
        # Never read or persist login/password fields. Aggregate by host/service only.
        groups: Dict[Tuple[str, str, str], int] = {}
        for row in rows:
            host = _text(row.get("host") or generator.get("server") or "unknown", 300)
            service = _text(row.get("service") or generator.get("service") or "unknown", 100)
            port = _text(row.get("port") or "unknown", 20)
            key = (host, service, port)
            groups[key] = groups.get(key, 0) + 1

        findings: List[Finding] = []
        for (host, service, port), count in groups.items():
            safe_evidence = {
                "source_report": filename,
                "source_sha256": digest,
                "hydra_version": version,
                "json_output_version": generator.get("jsonoutputversion"),
                "host": host,
                "service": service,
                "port": port,
                "credential_pairs_reported": count,
                "credential_values": "not retained",
            }
            findings.append(Finding(
                scan_id=scan.id,
                title=f"Credential accepted by {service} on {host}:{port}",
                description=(
                    f"The imported Hydra report records {count} accepted credential pair(s) for "
                    f"{service} on {host}:{port}. Usernames and passwords were discarded during import."
                ),
                source_tool="THC Hydra (report import)",
                tool_version=version,
                target=f"{host}:{port}",
                severity=FindingSeverity.HIGH,
                severity_source="Credential acceptance reported by imported Hydra output",
                confidence=FindingConfidence.MEDIUM,
                confidence_justification="Scanner-reported only; credentials are not independently replayed by OBSIDIAN.",
                status=FindingStatus.SCANNER_REPORTED,
                evidence_raw=json.dumps(safe_evidence, ensure_ascii=False),
                evidence_summary=f"{count} credential pair(s) reported; secret values omitted.",
                affected_component=service,
                remediation="Rotate exposed credentials, review authentication policy, and investigate the affected service.",
            ))
        scan.status = "COMPLETED" if payload.get("success") is True else "PARTIAL"
        if scan.status == "PARTIAL":
            errors = payload.get("errormessages", [])
            scan.error_message = _text("; ".join(str(item) for item in errors[:5]), 1000) if isinstance(errors, list) else "Hydra report indicates an incomplete run."
        _check_limit(len(findings))
        return findings

    def _import_generic_json(self, payload: Dict[str, Any], filename: str, scan: ScanRun, digest: str) -> List[Finding]:
        tool = payload.get("tool") or payload.get("scanner") or payload.get("generator") or {}
        if isinstance(tool, dict):
            tool_name = _text(_first(tool, "name", "software", "id", default="External JSON scanner"), 100)
            version = _text(_first(tool, "version", "semanticVersion", default="Unknown"), 100)
        else:
            tool_name, version = _text(tool, 100) or "External JSON scanner", "Unknown"

        collection: Optional[Iterable[Any]] = None
        collection_name = ""
        for key in ("findings", "issues", "vulnerabilities", "alerts", "results"):
            if isinstance(payload.get(key), list):
                collection = payload[key]
                collection_name = key
                break
        if collection is None:
            raise ValueError("قالب JSON شناسایی نشد؛ انتظار SARIF، Hydra JSON یا آرایهٔ findings/issues/vulnerabilities/alerts/results می‌رفت.")

        _check_limit(len(collection))

        scan.tool_name = f"{tool_name} (JSON Import)"
        scan.target = _text(_first(payload, "target", "url", "host", default=filename), 500)
        findings: List[Finding] = []
        for row in collection:
            if not isinstance(row, dict):
                raise ValueError("Finding collections must contain only objects; no records were skipped.")
            source_title = _first(row, "title", "name", "rule", "id")
            if not isinstance(source_title, str) or not source_title.strip():
                raise ValueError("Each finding needs a nonempty text title, name, rule or id.")
            title = _text(source_title, 220)
            description = _text(_first(row, "description", "message", "details", "summary", default=title), 3000)
            target = _text(_first(row, "target", "url", "uri", "host", default=scan.target), 500)
            raw_severity = _first(row, "severity", "risk", "level", default="INFO")
            location = _first(row, "location", "file", "path", default="")
            safe_evidence = {
                "source_report": filename,
                "source_sha256": digest,
                "collection": collection_name,
                "title": title,
                "severity": _text(raw_severity, 100),
                "target": target,
                "location": _text(location, 500),
                "description": description,
            }
            cwe, cve = self._extract_ids(json.dumps(row, ensure_ascii=False))
            findings.append(Finding(
                scan_id=scan.id,
                title=title or "Scanner finding",
                description=description,
                source_tool=tool_name,
                tool_version=version,
                target=target,
                severity=_severity(raw_severity, row.get("security-severity")),
                severity_source="Imported JSON severity field",
                confidence=FindingConfidence.MEDIUM,
                confidence_justification="Imported scanner report; OBSIDIAN has not independently validated this result.",
                status=FindingStatus.SCANNER_REPORTED,
                evidence_raw=json.dumps(safe_evidence, ensure_ascii=False),
                evidence_summary=f"{collection_name}: {_text(location, 350)}".strip(),
                cwe_id=cwe,
                cve_id=cve,
                affected_component=_text(location, 500) or None,
                remediation=_text(_first(row, "remediation", "solution", "fix", default=""), 1500) or "Review the source report and reproduce safely within the authorized scope.",
            ))
        return self._deduplicate(findings)

    @staticmethod
    def _extract_ids(value: str) -> Tuple[Optional[str], Optional[str]]:
        cwe = re.search(r"\bCWE[-_ ]?(\d{1,5})\b", value, re.IGNORECASE)
        cve = re.search(r"\bCVE-\d{4}-\d{4,8}\b", value, re.IGNORECASE)
        return (f"CWE-{cwe.group(1)}" if cwe else None, cve.group(0).upper() if cve else None)

    @staticmethod
    def _safe_fingerprints(value: Any) -> Dict[str, str]:
        if not isinstance(value, dict):
            return {}
        return {str(k)[:100]: _text(v, 200) for k, v in list(value.items())[:20] if isinstance(v, (str, int, float))}

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique = []
        for finding in findings:
            key = (finding.source_tool, finding.title, finding.target, finding.evidence_summary)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique
