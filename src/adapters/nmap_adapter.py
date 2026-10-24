"""
III85III QOLAM SENTINEL — Nmap Adapter
Real network, host, and port discovery with defusedxml parsing and strict scope bounds.
"""
from __future__ import annotations

import re
import ipaddress
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import defusedxml.ElementTree as ET

from src.adapters.base import BaseToolAdapter
from src.core.config import DEFAULT_NMAP_PATH
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)


class NmapAdapter(BaseToolAdapter):
    """Adapter for official Nmap network scanner."""

    name: str = "Nmap"

    def __init__(self, executable_path: Optional[str] = None):
        super().__init__(executable_path or DEFAULT_NMAP_PATH)
        self._cached_version: Optional[str] = None

    def _resolve_executable(self) -> Optional[str]:
        import os
        if self.executable_path:
            if shutil.which(self.executable_path) or os.path.isfile(self.executable_path):
                return self.executable_path
            # If an explicit non-default path was specified and does not exist, do not fall back
            if self.executable_path != DEFAULT_NMAP_PATH:
                return None
        which_path = shutil.which("nmap")
        if which_path:
            return which_path
        if DEFAULT_NMAP_PATH and os.path.isfile(DEFAULT_NMAP_PATH):
            return DEFAULT_NMAP_PATH
        return None

    def detect(self) -> ToolHealthInfo:
        exe = self._resolve_executable()
        if not exe:
            return ToolHealthInfo(
                name=self.name,
                installed=False,
                path=None,
                status_message="Nmap executable not found. Install Nmap from https://nmap.org",
            )

        code, out, err = self.run_subprocess_safe([exe, "--version"], timeout_sec=5)
        if code == 0:
            match = re.search(r"Nmap version\s+([0-9\.]+)", out)
            if not match:
                return ToolHealthInfo(
                    name=self.name,
                    installed=False,
                    path=exe,
                    status_message="Nmap executable responded, but its version banner could not be parsed.",
                    availability_status="VERSION_CHECK_FAILED",
                )
            version = match.group(1)
            self._cached_version = version
            return ToolHealthInfo(
                name=self.name,
                installed=True,
                version=version,
                path=exe,
                status_message=f"Ready (v{version})",
                availability_status="INSTALLED_AND_VERIFIED",
            )
        return ToolHealthInfo(
            name=self.name,
            installed=False,
            path=exe,
            status_message=f"Detection failed: {err.strip()}",
            availability_status="EXECUTION_FAILED" if code in {-1, -3} else "VERSION_CHECK_FAILED",
        )

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Accept one authorized hostname or IP, never a URL or Nmap option."""
        if not target or not target.strip():
            return False, "Target cannot be empty"

        target = target.strip()
        if target.startswith("-") or any(c in target for c in [";", "&", "|", "`", "$", "(", ")", "<", ">", "/", "\\", "@", "?", "#", "\n", "\r", " "]):
            return False, "Enter one hostname or IP address; URL paths and option-like targets are not allowed."
        try:
            ipaddress.ip_address(target.split("%", 1)[0])
            return True, "Valid IP address"
        except ValueError:
            pass
        hostname = target.rstrip(".")
        if len(hostname) > 253 or not hostname or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*",
            hostname,
        ):
            return False, "Target must be one valid hostname or IP address."
        return True, "Valid host"

    @staticmethod
    def validate_port_spec(ports: str) -> Tuple[bool, str]:
        """Accept only comma-separated TCP port numbers and inclusive ranges."""
        value = str(ports or "").strip()
        if not value or len(value) > 256:
            return False, "Enter a port list such as 80,443,8000-8100."
        for item in value.split(","):
            match = re.fullmatch(r"(\d+)(?:-(\d+))?", item.strip())
            if not match:
                return False, "Port list may contain only numbers, commas, and ranges."
            first = int(match.group(1))
            last = int(match.group(2) or first)
            if first < 1 or last > 65535 or first > last:
                return False, "Ports must be between 1 and 65535 and ranges must be ascending."
        return True, "Valid port list"

    def run_scan(
        self,
        target: str,
        scan_run: ScanRun,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ScanRun, List[Finding]]:
        opts = options or {}
        valid, msg = self.validate_target(target)
        if not valid:
            scan_run.status = "FAILED"
            scan_run.error_message = f"Invalid target: {msg}"
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
            return scan_run, []

        exe = self._resolve_executable()
        if not exe:
            scan_run.status = "FAILED"
            scan_run.error_message = "Nmap executable not found"
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
            return scan_run, []

        ports = opts.get("ports", "1-1024")
        scan_type = opts.get("profile", "SAFE_CONNECT")  # SAFE_CONNECT, FAST, SERVICE_VERSION

        if scan_type not in {"SAFE_CONNECT", "FAST", "SERVICE_VERSION"}:
            scan_run.status = "FAILED"
            scan_run.error_message = "Invalid Nmap scan profile."
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
            return scan_run, []

        if scan_type != "FAST":
            valid_ports, ports_message = self.validate_port_spec(ports)
            if not valid_ports:
                scan_run.status = "FAILED"
                scan_run.error_message = f"Invalid port list: {ports_message}"
                scan_run.end_time = datetime.now(timezone.utc).isoformat()
                return scan_run, []

        # Construct safe command arguments
        cmd = [exe, "-sT", "-oX", "-"]
        if scan_type == "FAST":
            cmd.extend(["-F", "-T4"])
        elif scan_type == "SERVICE_VERSION":
            cmd.extend(["-sV", "--version-intensity", "3", "-p", ports, "-T4"])
        else:
            cmd.extend(["-p", ports, "-T4"])

        cmd.append(target)
        scan_run.raw_command = " ".join(cmd)
        execution_started = datetime.now(timezone.utc).isoformat()

        timeout = int(opts.get("timeout_sec", 120))
        code, stdout, stderr = self.run_subprocess_safe(cmd, timeout_sec=timeout)

        scan_run.exit_code = code
        scan_run.end_time = datetime.now(timezone.utc).isoformat()
        scan_run.execution_log.append({
            "timestamp": execution_started,
            "scanner": "Nmap",
            "executable": exe,
            "arguments": cmd[1:],
            "timeout_seconds": timeout,
            "exit_code": code,
            "stdout_excerpt": stdout[:3000],
            "stderr_excerpt": stderr[:2000],
        })

        if code != 0:
            scan_run.status = "FAILED"
            scan_run.error_message = stderr.strip() or f"Process exited with code {code}"
            return scan_run, []

        # Parse XML
        findings, parse_err = self.parse_xml_output(stdout, scan_run.id, target)
        if parse_err:
            scan_run.status = "FAILED"
            scan_run.error_message = f"XML parse error: {parse_err}"
            return scan_run, []

        scan_run.status = "COMPLETED"
        scan_run.findings_count = len(findings)
        return scan_run, findings

    def parse_xml_output(
        self, xml_content: str, scan_id: str, default_target: str
    ) -> Tuple[List[Finding], Optional[str]]:
        if not xml_content or not xml_content.strip():
            return [], "Empty XML output from Nmap"

        try:
            root = ET.fromstring(xml_content)
        except Exception as exc:
            return [], f"XML malformed: {str(exc)}"

        findings: List[Finding] = []
        tool_ver = self._cached_version or root.attrib.get("version", "7.99")

        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            if status_elem is not None and status_elem.attrib.get("state") != "up":
                continue

            # Extract address
            addr_elem = host_elem.find("address")
            host_ip = addr_elem.attrib.get("addr", default_target) if addr_elem is not None else default_target

            # Extract ports
            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.attrib.get("state") != "open":
                    continue

                proto = port_elem.attrib.get("protocol", "tcp")
                portid = port_elem.attrib.get("portid", "0")
                reason = state_elem.attrib.get("reason", "syn-ack")

                service_elem = port_elem.find("service")
                service_name = service_elem.attrib.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                version = service_elem.attrib.get("version", "") if service_elem is not None else ""
                extrainfo = service_elem.attrib.get("extrainfo", "") if service_elem is not None else ""

                component_str = f"{product} {version}".strip() if product else service_name

                # Determine severity based on exposed service
                severity = FindingSeverity.INFO
                if portid in ["445", "139"]:  # SMB
                    severity = FindingSeverity.MEDIUM
                elif portid in ["3389", "5900"]:  # RDP / VNC
                    severity = FindingSeverity.MEDIUM
                elif portid in ["21", "23"]:  # FTP / Telnet
                    severity = FindingSeverity.HIGH
                elif portid in ["80", "8080", "443", "8443"]:  # Web
                    severity = FindingSeverity.LOW

                # Raw XML snippet for this port
                raw_port_xml = ET.tostring(port_elem, encoding="unicode")

                finding = Finding(
                    scan_id=scan_id,
                    title=f"Open Port {portid}/{proto.upper()} ({service_name}) on {host_ip}",
                    description=(
                        f"Port {portid} is open and responding on host {host_ip}.\n"
                        f"Detected Service: {service_name}\n"
                        f"Product: {product or 'N/A'}\n"
                        f"Version: {version or 'N/A'}\n"
                        f"Extra Info: {extrainfo or 'N/A'}"
                    ),
                    source_tool="Nmap",
                    tool_version=tool_ver,
                    target=f"{host_ip}:{portid}",
                    severity=severity,
                    severity_source="Nmap Port & Service State",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification=f"TCP handshake confirmed: {reason}",
                    status=FindingStatus.OBSERVED,
                    evidence_raw=raw_port_xml,
                    evidence_summary=f"Port {portid}/{proto} state='open' reason='{reason}' service='{service_name}'",
                    affected_component=component_str,
                    remediation=f"If service '{service_name}' on port {portid} is not required, disable or firewall it.",
                )
                findings.append(finding)

        return findings, None
