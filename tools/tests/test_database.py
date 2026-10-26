"""
Unit tests for QOLAM SENTINEL SQLite database manager.
"""
import tempfile
from pathlib import Path

from src.core.database import DatabaseManager
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)


def test_database_crud_operations():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_sentinel.db"
        db = DatabaseManager(db_file)

        # 1. Test Scans
        scan = ScanRun(
            tool_name="nmap",
            target="127.0.0.1",
            raw_command="nmap -sT 127.0.0.1",
        )
        db.save_scan(scan)
        retrieved_scan = db.get_scan(scan.id)
        assert retrieved_scan is not None
        assert retrieved_scan.target == "127.0.0.1"
        assert retrieved_scan.status == "RUNNING"

        # 2. Test Findings
        finding = Finding(
            scan_id=scan.id,
            title="Exposed RPC Port 135",
            description="RPC service discovered",
            source_tool="nmap",
            target="127.0.0.1:135",
            severity=FindingSeverity.INFO,
            severity_source="Nmap",
            confidence=FindingConfidence.CONFIRMED,
            confidence_justification="syn-ack",
            evidence_raw="port 135 open",
        )
        db.save_finding(finding)

        findings = db.list_findings(scan_id=scan.id)
        assert len(findings) == 1
        assert findings[0].title == "Exposed RPC Port 135"

        # Verify scan findings_count was updated
        updated_scan = db.get_scan(scan.id)
        assert updated_scan.findings_count == 1

        # Test status update
        success = db.update_finding_status(finding.id, FindingStatus.VALIDATED)
        assert success is True
        updated_finding = db.get_finding(finding.id)
        assert updated_finding.status == FindingStatus.VALIDATED

        # 3. Test Tool Health
        health = ToolHealthInfo(
            name="defender",
            installed=True,
            version="4.18.26090.9",
            status_message="Active",
        )
        db.save_tool_health(health)
        tools = db.list_tool_health()
        assert len(tools) == 1
        assert tools[0].name == "defender"

        # 4. Test Summary
        summary = db.get_findings_summary()
        assert summary["TOTAL"] == 1
        assert summary["INFO"] == 1
        assert summary["VALIDATED"] == 1

        db.close()


def test_finalizing_scan_preserves_finding_association(tmp_path):
    db = DatabaseManager(tmp_path / "finalize.db")
    try:
        scan = ScanRun(tool_name="OBSIDIAN", target="http://127.0.0.1", raw_command="")
        db.save_scan(scan)
        finding = Finding(
            scan_id=scan.id, title="Evidence", description="Observed response", source_tool="OBSIDIAN",
            target=scan.target, severity=FindingSeverity.LOW, severity_source="HTTP",
            confidence=FindingConfidence.HIGH, confidence_justification="Response", evidence_raw="HTTP 200",
        )
        db.save_finding(finding)
        scan.status = "COMPLETED"
        scan.findings_count = 1
        db.save_scan(scan)
        assert db.get_finding(finding.id).scan_id == scan.id
        assert len(db.list_findings(scan_id=scan.id)) == 1
    finally:
        db.close()
