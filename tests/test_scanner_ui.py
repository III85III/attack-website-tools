"""Verify that scanner result rows, saved assessment, and async export agree."""
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

from src.core.database import DatabaseManager
from src.core.models import Finding, FindingConfidence, FindingSeverity, ScanRun
from src.reporting.export_service import export_assessment
from src.ui.tabs import ReportsTab, WebSecurityTab


def test_scanner_summary_and_async_report_use_same_assessment(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    db = DatabaseManager(tmp_path / "ui.db")
    monkeypatch.setattr(DatabaseManager, "get_instance", classmethod(lambda cls, *_a, **_kw: db))
    monkeypatch.setattr("src.ui.report_actions.export_assessment", lambda database, scan_id, fmt, **kwargs:
                        export_assessment(database, scan_id, fmt, tmp_path / "reports", **kwargs))
    scan = ScanRun(tool_name="Sentinel DAST", target="https://first.test", raw_command="",
                   status="COMPLETED", request_count=5, response_status=200, findings_count=1)
    db.save_scan(scan)
    item = Finding(scan_id=scan.id, title="Controlled high-severity finding", description="UI regression fixture",
                   source_tool="Sentinel", target=scan.target, severity=FindingSeverity.HIGH,
                   severity_source="Fixture", confidence=FindingConfidence.HIGH,
                   confidence_justification="Fixture", evidence_raw="Fixture")
    db.save_finding(item)
    widget = WebSecurityTab()
    try:
        widget._on_scan_finished(scan, [item])
        assert widget.findings_table.item(0, 0).text() == item.title
        assert widget.severity_labels["HIGH"].text() == "1  HIGH"
        assert widget.report_actions.word_btn.isEnabled()
        widget.report_actions.export("json")
        loop = QEventLoop()
        widget.report_actions.worker.finished.connect(loop.quit)
        QTimer.singleShot(5000, loop.quit)
        loop.exec()
        assert widget.report_actions.worker.wait(1000)
        app.processEvents()
        payload = json.loads(widget.report_actions.last_path.read_text(encoding="utf-8"))
        assert payload["scan"]["id"] == scan.id
        assert [f["id"] for f in payload["findings"]] == [item.id]
        assert widget.report_actions.open_btn.isEnabled()
        history = ReportsTab()
        assert history.scan_combo.currentData() == scan.id
        assert history.report_actions.scan_id == scan.id
        history.close()
    finally:
        widget.close()
        db.close()


def test_database_open_failure_is_reported_by_workers(tmp_path, monkeypatch):
    from src.ui.tabs import WebAuditWorker
    from src.ui.report_actions import ReportExportWorker

    def fail_open(*_args, **_kwargs):
        raise OSError("Database directory is not writable")

    monkeypatch.setattr(DatabaseManager, "get_instance", classmethod(fail_open))
    monkeypatch.setattr("src.ui.tabs.write_execution_log", lambda scan: tmp_path / "failed.json")
    scan_results, export_results = [], []
    scanner = WebAuditWorker("http://127.0.0.1")
    scanner.finished_signal.connect(lambda scan, findings: scan_results.append(scan))
    scanner.run()
    assert scan_results[0].status == "FAILED"
    assert "OSError" in scan_results[0].error_message
    exporter = ReportExportWorker("missing", "json")
    exporter.result.connect(lambda path, error: export_results.append((path, error)))
    exporter.run()
    assert export_results[0][0] == ""
    assert "not writable" in export_results[0][1]


def test_scan_landing_is_uncluttered_and_animation_is_idle(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    database = DatabaseManager(tmp_path / "landing.db")
    monkeypatch.setattr(DatabaseManager, "get_instance", classmethod(lambda cls: database))
    widget = WebSecurityTab()
    widget.show()
    app.processEvents()
    assert widget.findings_table.isHidden()
    assert widget.empty_results.isVisible()
    assert not widget.scan_visual._timer.isActive()
    assert widget.session_plan is None
    widget.close()
    database.close()
