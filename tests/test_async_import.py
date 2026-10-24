import json
import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import pytest
from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication
from src.core.database import DatabaseManager
from src.core.models import ScanRun, Finding, FindingSeverity, FindingConfidence
from src.ui.report_import_actions import ReportImportActions, ReportImportWorker


def fixture_scan():
    scan = ScanRun(tool_name="Fixture", target="local fixture", raw_command="", status="COMPLETED")
    finding = Finding(scan_id=scan.id, title="Fixture", description="Fixture", source_tool="Fixture",
                      target="local fixture", severity=FindingSeverity.INFO, severity_source="Fixture",
                      confidence=FindingConfidence.LOW, confidence_justification="Fixture", evidence_raw="Fixture")
    return scan, finding


def test_atomic_import_rolls_back_scan_and_prior_rows(tmp_path, monkeypatch):
    db = DatabaseManager(tmp_path / "atomic.db")
    scan, finding = fixture_scan()
    original = db._store_finding
    calls = []
    def fail_after_first(conn, item):
        calls.append(item)
        if len(calls) == 2:
            raise OSError("Controlled write failure")
        original(conn, item)
    monkeypatch.setattr(db, "_store_finding", fail_after_first)
    with pytest.raises(OSError):
        db.save_import(scan, [finding, finding])
    assert db.get_scan(scan.id) is None
    assert not db.list_findings(limit=None)
    db.close()


def test_atomic_import_rejects_cross_assessment_rows(tmp_path):
    db = DatabaseManager(tmp_path / "mismatch.db")
    scan, finding = fixture_scan()
    finding.scan_id = "different"
    with pytest.raises(ValueError):
        db.save_import(scan, [finding])
    assert db.get_scan(scan.id) is None
    db.close()


def test_import_keeps_event_loop_running_and_prevents_duplicate_start(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    db = DatabaseManager(tmp_path / "ui.db")
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps({"findings": [{"title": "Controlled import"}]}), encoding="utf-8")
    from src.adapters.report_import_adapter import ReportImportAdapter
    original = ReportImportAdapter.import_file
    release = threading.Event()
    worker_thread_ids = []
    def bounded_wait(self, file):
        worker_thread_ids.append(threading.get_ident())
        assert release.wait(3), "GUI timer never released background parser"
        return original(self, file)
    monkeypatch.setattr(ReportImportAdapter, "import_file", bounded_wait)
    widget = ReportImportActions(db.db_path)
    results = []
    widget.imported.connect(results.append)
    widget.start_import(str(path))
    worker = widget.worker
    widget.start_import(str(path))
    assert widget.worker is worker and not widget.button.isEnabled()
    loop = QEventLoop()
    worker.finished.connect(loop.quit)
    QTimer.singleShot(50, release.set)
    QTimer.singleShot(5000, loop.quit)
    try:
        loop.exec()
        assert worker.wait(1000)
        app.processEvents()
        assert len(worker_thread_ids) == 1
        assert worker_thread_ids[0] != threading.get_ident()
        assert len(results) == 1 and widget.button.isEnabled()
        assert len(db.list_scans()) == 1 and len(db.list_findings()) == 1
        assert results[0].findings_count == 1
    finally:
        release.set()
        worker.wait(5000)
        widget.close()
        db.close()


def test_parse_failure_signals_error_and_saves_nothing(tmp_path):
    app = QApplication.instance() or QApplication([])
    db = DatabaseManager(tmp_path / "fail.db")
    path = tmp_path / "broken.json"
    path.write_text("{broken", encoding="utf-8")
    results = []
    worker = ReportImportWorker(str(path), db.db_path)
    worker.result.connect(lambda scan, error: results.append((scan, error)))
    worker.run()
    assert results[0][0] is None and results[0][1]
    assert not db.list_scans()
    db.close()


def test_database_open_failure_is_reported(tmp_path, monkeypatch):
    path = tmp_path / "valid.json"
    path.write_text('{"findings": []}', encoding="utf-8")
    def fail_open(*args, **kwargs):
        raise OSError("Controlled database open failure")
    monkeypatch.setattr("src.ui.report_import_actions.DatabaseManager", fail_open)
    worker = ReportImportWorker(str(path), tmp_path / "unwritable.db")
    results = []
    worker.result.connect(lambda scan, error: results.append((scan, error)))
    worker.run()
    assert results == [(None, "OSError: Controlled database open failure")]
