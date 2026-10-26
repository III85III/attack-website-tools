"""
III85III OBSIDIAN — OWASP ZAP Adapter
Integrates with OWASP ZAP REST API or reports accurate offline/unavailable state.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.adapters.base import BaseToolAdapter
from src.core.config import DEFAULT_ZAP_API_KEY, DEFAULT_ZAP_API_URL
from src.core.privacy import sanitize_data
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)


class ZapAdapter(BaseToolAdapter):
    """Adapter for OWASP Zed Attack Proxy (ZAP) REST API."""

    name: str = "OWASP ZAP"

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        super().__init__(base_url or DEFAULT_ZAP_API_URL)
        self.base_url = (base_url or DEFAULT_ZAP_API_URL).rstrip("/")
        self.api_key = api_key or DEFAULT_ZAP_API_KEY
        self.headers = {"X-ZAP-API-Key": self.api_key} if self.api_key else {}

    def _api(self, component: str, kind: str, operation: str, params=None, timeout=15):
        """Call a local ZAP JSON API endpoint and reject API-level errors."""
        response = requests.get(
            f"{self.base_url}/JSON/{component}/{kind}/{operation}/",
            params=params or {}, headers=self.headers, timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and data.get("code"):
            raise RuntimeError(data.get("message") or data.get("detail") or "ZAP API error")
        return data

    def detect(self) -> ToolHealthInfo:
        """Check if ZAP is reachable on the configured host:port."""
        try:
            resp = requests.get(
                f"{self.base_url}/JSON/core/view/version/",
                headers=self.headers,
                timeout=2.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if not isinstance(data, dict) or not isinstance(data.get("version"), (str, int, float)):
                    raise ValueError("invalid response schema")
                version = data.get("version", "Active")
                if not str(version).strip():
                    raise ValueError("empty version value")
                return ToolHealthInfo(
                    name=self.name,
                    installed=True,
                    version=version,
                    path=self.base_url,
                    status_message=f"Connected to ZAP API (v{version})",
                    availability_status="INSTALLED_AND_VERIFIED",
                )
            reason = f"ZAP API returned HTTP {resp.status_code}."
        except requests.RequestException as exc:
            if isinstance(exc, ValueError):
                reason = f"ZAP version endpoint verification failed: {type(exc).__name__}."
                availability = "VERSION_CHECK_FAILED"
            else:
                reason = f"ZAP API connection failed: {type(exc).__name__}."
                availability = "MISSING"
        except (ValueError, TypeError) as exc:
            if "availability" not in locals():
                availability = "VERSION_CHECK_FAILED"
            reason = f"ZAP version endpoint verification failed: {type(exc).__name__}."
        if "availability" not in locals():
            availability = "VERSION_CHECK_FAILED"

        return ToolHealthInfo(
            name=self.name,
            installed=False,
            path=self.base_url,
            status_message=reason,
            availability_status=availability,
        )

    def fetch_alerts(
        self, baseurl: Optional[str] = None, scan_id: Optional[str] = None
    ) -> List[Finding]:
        """Fetch real passive and active alerts from ZAP API."""
        endpoint = f"{self.base_url}/JSON/core/view/alerts/"
        params: Dict[str, Any] = {}
        if baseurl:
            params["baseurl"] = baseurl

        try:
            resp = requests.get(endpoint, params=params, headers=self.headers, timeout=10)
            if resp.status_code != 200:
                raise RuntimeError(f"ZAP alerts endpoint returned HTTP {resp.status_code}.")
            data = resp.json()
            if not isinstance(data, dict) or data.get("code") or "alerts" not in data:
                raise RuntimeError("ZAP alerts endpoint did not return a valid alerts response.")
            alerts = data["alerts"]
            if not isinstance(alerts, list):
                raise RuntimeError("ZAP alerts response did not contain an alerts list.")
            if any(not isinstance(alert, dict) or not isinstance(alert.get("alert"), str)
                   or not alert["alert"].strip() for alert in alerts):
                raise RuntimeError("ZAP alerts response contained a malformed alert.")
        except (requests.RequestException, ValueError, TypeError) as exc:
            raise RuntimeError(f"ZAP alerts request failed: {type(exc).__name__}.") from exc

        findings: List[Finding] = []
        for alert in alerts:
            alert = sanitize_data(alert)
            alert_id = alert.get("id", "zap-alert")
            name = alert.get("alert", "Web Security Issue")
            risk = alert.get("risk", "Low")
            confidence_raw = alert.get("confidence", "Medium")
            url = alert.get("url", baseurl or "Target Web App")
            evidence = alert.get("evidence", "")
            param = alert.get("param", "")
            solution = alert.get("solution", "")
            desc = alert.get("description", "")
            cwe_id = alert.get("cweid")

            # Map ZAP risk to FindingSeverity
            sev_map = {
                "Informational": FindingSeverity.INFO,
                "Low": FindingSeverity.LOW,
                "Medium": FindingSeverity.MEDIUM,
                "High": FindingSeverity.HIGH,
            }
            severity = sev_map.get(risk, FindingSeverity.LOW)

            # Map ZAP confidence to FindingConfidence
            conf_map = {
                "Low": FindingConfidence.LOW,
                "Medium": FindingConfidence.MEDIUM,
                "High": FindingConfidence.HIGH,
                "Confirmed": FindingConfidence.CONFIRMED,
            }
            confidence = conf_map.get(confidence_raw, FindingConfidence.MEDIUM)

            finding = Finding(
                scan_id=scan_id,
                title=f"{name} at {url}",
                description=(
                    f"{desc}\n"
                    f"Parameter: {param or 'None'}\n"
                    f"ZAP Alert ID: {alert_id}\n"
                    f"Risk Level: {risk}\n"
                    f"ZAP Confidence: {confidence_raw}"
                ),
                source_tool="OWASP ZAP",
                tool_version="ZAP API",
                target=url,
                severity=severity,
                severity_source=f"ZAP Risk: {risk}",
                confidence=confidence,
                confidence_justification=f"Reported by ZAP with confidence rating '{confidence_raw}'",
                status=FindingStatus.SCANNER_REPORTED,
                evidence_raw=json.dumps(alert, indent=2),
                evidence_summary=f"Evidence: {evidence}" if evidence else f"Parameter: {param}",
                cwe_id=f"CWE-{cwe_id}" if cwe_id else None,
                affected_component=param or url,
                remediation=solution or "Apply standard secure coding practices and header hardening.",
            )
            findings.append(finding)

        return findings

    def run_scan(
        self,
        target: str,
        scan_run: ScanRun,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ScanRun, List[Finding]]:
        health = self.detect()
        if not health.installed:
            scan_run.status = "FAILED"
            scan_run.error_message = health.status_message
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
            return scan_run, []

        from urllib.parse import urlsplit

        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            scan_run.status = "FAILED"
            scan_run.error_message = "A valid HTTP/S URL without embedded credentials is required."
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
            return scan_run, []

        origin = f"{parsed.scheme}://{parsed.netloc}"
        context_name = f"Sentinel_{scan_run.id.replace('-', '')[:20]}"
        context_created = False
        progress = (options or {}).get("progress_callback", lambda _message: None)
        max_duration = min(max(int((options or {}).get("max_duration_seconds", 600)), 60), 900)
        started = time.monotonic()

        def poll(component, scan_id, label):
            while True:
                if time.monotonic() - started > max_duration:
                    try:
                        self._api(component, "action", "stop", {"scanId": scan_id})
                    except Exception as stop_exc:
                        scan_run.execution_log.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "operation": f"Stop timed-out ZAP {label}",
                            "state": "EXECUTION_FAILED",
                            "error_type": type(stop_exc).__name__,
                        })
                    raise TimeoutError(f"ZAP {label} reached the {max_duration}-second limit.")
                status_data = self._api(component, "view", "status", {"scanId": scan_id})
                status = int(status_data.get("status", 0))
                progress(f"ZAP {label}: {status}%")
                if status >= 100:
                    return
                time.sleep(1)

        try:
            progress("Creating a temporary ZAP context restricted to the entered origin")
            self._api("context", "action", "newContext", {"contextName": context_name})
            context_created = True
            self._api("context", "action", "includeInContext", {
                "contextName": context_name,
                "regex": "^" + re.escape(origin) + r"(?:/.*)?$",
            })
            self._api("context", "action", "setContextInScope", {
                "contextName": context_name, "booleanInScope": "true",
            })
            context = self._api("context", "view", "context", {"contextName": context_name})
            context_id = context.get("context", {}).get("id")
            if context_id is None:
                raise RuntimeError("ZAP did not return the temporary context ID.")

            progress("Crawling pages inside the approved origin")
            spider = self._api("spider", "action", "scan", {
                "url": target, "contextName": context_name, "recurse": "true",
                "subtreeOnly": "true",
            })
            spider_id = spider.get("scan")
            if spider_id is None:
                raise RuntimeError("ZAP did not start the spider.")
            poll("spider", spider_id, "crawl")

            progress("Starting the ZAP active scan within the temporary context")
            active = self._api("ascan", "action", "scan", {
                "url": target, "contextId": context_id, "recurse": "true",
                "inScopeOnly": "true",
            })
            active_id = active.get("scan")
            if active_id is None:
                raise RuntimeError("ZAP did not start the active scan.")
            poll("ascan", active_id, "active scan")

            findings = self.fetch_alerts(baseurl=origin, scan_id=scan_run.id)
            scan_run.status = "COMPLETED"
            scan_run.findings_count = len(findings)
            return scan_run, findings
        except Exception as exc:
            scan_run.status = "FAILED"
            scan_run.error_message = str(exc)
            return scan_run, []
        finally:
            if context_created:
                try:
                    self._api("context", "action", "removeContext", {"contextName": context_name})
                except Exception as cleanup_exc:
                    scan_run.execution_log.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "operation": "Remove temporary ZAP context",
                        "state": "EXECUTION_FAILED",
                        "error_type": type(cleanup_exc).__name__,
                    })
                    if scan_run.status == "COMPLETED":
                        scan_run.status = "PARTIAL"
                        scan_run.error_message = "ZAP scan completed, but its temporary context could not be removed."
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
