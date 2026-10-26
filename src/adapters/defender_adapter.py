"""
III85III OBSIDIAN — Windows Defender Adapter
Queries native Windows Defender protection status and authentic threat detections via PowerShell.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.adapters.base import BaseToolAdapter
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)


class DefenderAdapter(BaseToolAdapter):
    """Adapter for native Windows Defender protection service."""

    name: str = "Microsoft Defender"

    def __init__(self):
        super().__init__("powershell.exe")

    def detect(self) -> ToolHealthInfo:
        status = self.get_status()
        if status.get("available", False):
            version = status.get("AMProductVersion", "Windows Native")
            rtp = "Enabled" if status.get("RealTimeProtectionEnabled") else "Disabled"
            return ToolHealthInfo(
                name=self.name,
                installed=True,
                version=version,
                path="PowerShell Defender Provider",
                status_message=f"Active (Real-time Protection: {rtp})",
                availability_status="INSTALLED_AND_VERIFIED",
            )
        return ToolHealthInfo(
            name=self.name,
            installed=False,
            path="PowerShell Defender Provider",
            status_message=f"Unavailable: {status.get('error', 'Unknown error')}",
        )

    def get_status(self) -> Dict[str, Any]:
        """Fetch live Defender security status."""
        ps_cmd = (
            "Get-MpComputerStatus | Select-Object -Property "
            "AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled, "
            "AntispywareEnabled, FullScanAge, QuickScanAge, AMProductVersion, "
            "AntivirusSignatureVersion, EngineVersion | ConvertTo-Json"
        )
        code, out, err = self.run_subprocess_safe(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            timeout_sec=10,
        )
        if code != 0 or not out.strip():
            return {
                "available": False,
                "error": err.strip() or f"PowerShell exited with code {code}",
            }

        try:
            data = json.loads(out)
            data["available"] = True
            return data
        except Exception as exc:
            return {"available": False, "error": f"JSON parse error: {str(exc)}"}

    def get_threat_detections(self, limit: int = 20) -> List[Finding]:
        """Collect authentic threat detections from Defender."""
        ps_cmd = (
            f"Get-MpThreatDetection | Select-Object -First {limit} -Property "
            "DetectionID, ThreatID, ThreatStatusID, ProcessName, Resources, "
            "InitialDetectionTime, RemediationTime, ActionSuccess, AMProductVersion "
            "| ConvertTo-Json"
        )
        code, out, err = self.run_subprocess_safe(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            timeout_sec=15,
        )
        if code != 0 or not out.strip():
            return []

        try:
            data = json.loads(out)
            if isinstance(data, dict):
                items = [data]
            elif isinstance(data, list):
                items = data
            else:
                items = []
        except Exception:
            return []

        findings: List[Finding] = []
        for item in items:
            threat_id = item.get("ThreatID", "Unknown")
            proc_name = item.get("ProcessName") or "Unknown Process"
            resources = item.get("Resources") or []
            res_str = ", ".join(resources) if isinstance(resources, list) else str(resources)
            action_success = item.get("ActionSuccess", False)
            am_ver = item.get("AMProductVersion", "Defender")

            status = FindingStatus.VALIDATED if action_success else FindingStatus.SCANNER_REPORTED
            severity = FindingSeverity.HIGH if action_success else FindingSeverity.CRITICAL

            finding = Finding(
                title=f"Defender Threat {threat_id}: {proc_name}",
                description=(
                    f"Windows Defender identified an active or historical threat.\n"
                    f"Threat ID: {threat_id}\n"
                    f"Involved Process: {proc_name}\n"
                    f"Affected Resources: {res_str}\n"
                    f"Action Succeeded: {action_success}"
                ),
                source_tool="Microsoft Defender",
                tool_version=am_ver,
                target=res_str or proc_name,
                severity=severity,
                severity_source="Windows Defender Security Intelligence",
                confidence=FindingConfidence.CONFIRMED,
                confidence_justification="Verified by Windows Defender Threat Detection log",
                status=status,
                evidence_raw=json.dumps(item, indent=2),
                evidence_summary=f"Threat {threat_id} detected in {proc_name}; ActionSuccess={action_success}",
                affected_component=proc_name,
                remediation=(
                    "Verify file integrity and perform a complete Windows Defender scan. "
                    "Confirm remediation status in Windows Security Center."
                ),
            )
            findings.append(finding)

        return findings

    def run_scan(
        self,
        target: str,
        scan_run: ScanRun,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ScanRun, List[Finding]]:
        """Run system audit via Defender."""
        status = self.get_status()
        if not status.get("available"):
            scan_run.status = "FAILED"
            scan_run.error_message = status.get("error", "Defender unavailable")
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
            return scan_run, []

        threats = self.get_threat_detections(limit=50)
        for t in threats:
            t.scan_id = scan_run.id

        scan_run.status = "COMPLETED"
        scan_run.findings_count = len(threats)
        scan_run.end_time = datetime.now(timezone.utc).isoformat()
        return scan_run, threats
