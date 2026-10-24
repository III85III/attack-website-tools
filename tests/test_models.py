"""
Unit tests for QOLAM SENTINEL core models.
"""
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)


def test_finding_creation_and_serialization():
    finding = Finding(
        title="Open Port 445 (Microsoft-DS)",
        description="Port 445 is exposed on host 127.0.0.1",
        source_tool="nmap",
        tool_version="7.99",
        target="127.0.0.1:445",
        severity=FindingSeverity.LOW,
        severity_source="Nmap Port State",
        confidence=FindingConfidence.CONFIRMED,
        confidence_justification="Verified syn-ack TCP handshake",
        status=FindingStatus.SCANNER_REPORTED,
        evidence_raw="<port protocol='tcp' portid='445'><state state='open'/></port>",
        remediation="Ensure SMB is disabled on untrusted interfaces.",
    )

    data = finding.to_dict()
    assert data["title"] == "Open Port 445 (Microsoft-DS)"
    assert data["severity"] == "LOW"
    assert data["confidence"] == "CONFIRMED"
    assert data["status"] == "SCANNER_REPORTED"

    reconstructed = Finding.from_dict(data)
    assert reconstructed.id == finding.id
    assert reconstructed.title == finding.title
    assert reconstructed.severity == FindingSeverity.LOW


def test_scan_run_serialization():
    scan = ScanRun(
        tool_name="nmap",
        target="127.0.0.1",
        raw_command="nmap -sT -p 135,445 127.0.0.1",
    )
    data = scan.to_dict()
    assert data["tool_name"] == "nmap"
    assert data["status"] == "RUNNING"
    assert data["findings_count"] == 0

    reconstructed = ScanRun.from_dict(data)
    assert reconstructed.id == scan.id
    assert reconstructed.tool_name == "nmap"


def test_tool_health_serialization():
    health = ToolHealthInfo(
        name="nmap",
        installed=True,
        version="7.99",
        path="C:\\Program Files\\Nmap\\nmap.exe",
        status_message="Ready",
    )
    data = health.to_dict()
    assert data["name"] == "nmap"
    assert data["installed"] is True
    assert data["version"] == "7.99"
    assert data["availability_status"] == "VERSION_CHECK_FAILED"
