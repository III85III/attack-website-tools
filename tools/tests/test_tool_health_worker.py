import os
import threading
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication
from src.core.database import DatabaseManager
from src.core.models import ToolHealthInfo
from src.ui import tool_health_worker as module
from src.ui.tabs import ToolHealthTab


def healthy():
    return ToolHealthInfo(name="Fixture", installed=True, version="fixture", availability_status="INSTALLED_AND_VERIFIED")


def test_health_probe_runs_off_ui_thread_and_repeated_refresh_is_ignored(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    database = DatabaseManager(tmp_path / "ui.db")
    monkeypatch.setattr(DatabaseManager, "get_instance", classmethod(lambda cls: database))
    release = threading.Event()
    threads = []
    def wait_probe():
        threads.append(threading.get_ident())
        assert release.wait(3)
        return healthy()
    monkeypatch.setattr(module, "health_checks", lambda: [("Fixture", wait_probe)])
    widget = ToolHealthTab()
    worker = widget.health_worker
    widget.refresh_tools()
    assert worker is widget.health_worker and not widget.refresh_btn.isEnabled()
    loop = QEventLoop()
    worker.finished.connect(loop.quit)
    QTimer.singleShot(50, release.set)
    QTimer.singleShot(5000, loop.quit)
    try:
        loop.exec()
        assert worker.wait(1000)
        app.processEvents()
        assert len(threads) == 1 and threads[0] != threading.get_ident()
        assert widget.refresh_btn.isEnabled() and widget.table.rowCount() == 3
        assert "0 detector failure(s)" in widget.health_status.text()
        records = database.list_tool_health()
        assert len(records) == 3
        assert all(item.availability_status != "INSTALLED_AND_VERIFIED" for item in records if item.name != "Fixture")
    finally:
        release.set()
        worker.wait(5000)
        widget.close()
        database.close()


def test_detector_failure_is_redacted_and_other_checks_continue(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    def fail():
        raise OSError("password=FIXTURE_PRIVATE")
    monkeypatch.setattr(module, "health_checks", lambda: [("Failing", fail), ("Working", healthy)])
    worker = module.ToolHealthWorker(tmp_path / "detector.db")
    results = []
    worker.result.connect(lambda items, error: results.append((items, error)))
    worker.run()
    items, error = results[0]
    assert not error
    assert items[0].availability_status == "EXECUTION_FAILED"
    assert "FIXTURE_PRIVATE" not in items[0].status_message
    assert items[1].availability_status == "INSTALLED_AND_VERIFIED"


def test_health_batch_rolls_back_and_preserves_prior_records(tmp_path, monkeypatch):
    database = DatabaseManager(tmp_path / "atomic.db")
    previous = ToolHealthInfo(name="Previous", installed=False)
    database.save_tool_health(previous)
    original = database._store_tool_health
    calls = []
    def failing(conn, health):
        calls.append(health)
        if len(calls) == 2:
            raise OSError("Controlled storage failure")
        original(conn, health)
    monkeypatch.setattr(database, "_store_tool_health", failing)
    with pytest.raises(OSError):
        database.save_tool_health_batch([healthy(), ToolHealthInfo(name="Second", installed=False)])
    assert [item.name for item in database.list_tool_health()] == ["Previous"]
    database.close()


def test_health_storage_failure_reports_unsaved_results(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(module, "health_checks", lambda: [("Fixture", healthy)])
    def fail(*args, **kwargs):
        raise OSError("Controlled database failure")
    monkeypatch.setattr(module, "DatabaseManager", fail)
    results = []
    worker = module.ToolHealthWorker(tmp_path / "fail.db")
    worker.result.connect(lambda items, error: results.append((items, error)))
    worker.run()
    assert len(results[0][0]) == 3
    assert "not saved" in results[0][1]


def test_invalid_detector_output_does_not_claim_empty_success(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(module, "health_checks", lambda: [("Invalid", lambda: None)])
    results = []
    worker = module.ToolHealthWorker(tmp_path / "invalid.db")
    worker.result.connect(lambda items, error: results.append(items))
    worker.run()
    assert results[0][0].availability_status == "EXECUTION_FAILED"
