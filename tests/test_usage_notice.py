import json
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QDialog
from src.core import usage_notice as core
from src.ui import usage_notice_dialog as ui


def test_saved_acknowledgement_is_versioned_and_contains_no_identity(tmp_path):
    path = tmp_path / "notice.json"
    assert not core.notice_accepted(path)
    core.save_acknowledgement(path, "fixture")
    assert core.notice_accepted(path)
    value = json.loads(path.read_text())
    assert set(value) == {"notice_version", "notice_sha256", "acknowledged", "accepted_at_utc", "application_version"}
    value["notice_sha256"] = "outdated"
    path.write_text(json.dumps(value))
    assert not core.notice_accepted(path)


def test_corrupt_or_oversized_acknowledgement_is_not_accepted(tmp_path):
    path = tmp_path / "notice.json"
    for value in ("{broken", "[]", '"string"', "x" * 16_385):
        path.write_text(value)
        assert not core.notice_accepted(path)


def test_continue_requires_unchecked_by_default_acknowledgement():
    app = QApplication.instance() or QApplication([])
    dialog = ui.UsageNoticeDialog()
    assert not dialog.acknowledge.isChecked() and not dialog.continue_btn.isEnabled()
    dialog.accept()
    assert dialog.result() != QDialog.DialogCode.Accepted
    dialog.acknowledge.setChecked(True)
    assert dialog.continue_btn.isEnabled()
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.close()


def test_decline_writes_nothing(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    path = tmp_path / "notice.json"
    monkeypatch.setattr(ui.UsageNoticeDialog, "exec", lambda self: QDialog.DialogCode.Rejected)
    assert not ui.ensure_usage_notice(path=path)
    assert not path.exists()


def test_accept_is_saved_and_second_launch_skips_notice(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    path = tmp_path / "notice.json"
    calls = []
    monkeypatch.setattr(ui.UsageNoticeDialog, "exec", lambda self: calls.append(True) or QDialog.DialogCode.Accepted)
    assert ui.ensure_usage_notice(path=path)
    assert ui.ensure_usage_notice(path=path)
    assert calls == [True] and core.notice_accepted(path)


def test_write_failure_allows_acknowledged_session_with_warning(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ui.UsageNoticeDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    def fail(*args):
        raise OSError("Fixture storage failure")
    warnings = []
    monkeypatch.setattr(ui, "save_acknowledgement", fail)
    monkeypatch.setattr(ui.QMessageBox, "warning", lambda *args: warnings.append(args))
    assert ui.ensure_usage_notice(path=tmp_path / "notice.json")
    assert warnings and "next time" in warnings[0][-1]


def test_main_exits_before_workspace_when_notice_declined(monkeypatch):
    import main
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(main, "QApplication", lambda *args: app)
    monkeypatch.setattr(main.sys, "argv", ["sentinel"])
    monkeypatch.setattr(ui, "ensure_usage_notice", lambda: False)
    monkeypatch.setattr(main.DatabaseManager, "get_instance", classmethod(lambda cls: (_ for _ in ()).throw(AssertionError("Workspace must not start"))))
    assert main.main() == 0


def test_main_starts_workspace_only_after_acknowledgement(monkeypatch):
    import main
    from types import SimpleNamespace
    calls = []
    application = SimpleNamespace(setApplicationName=lambda value: None,
                                  setOrganizationName=lambda value: None,
                                  setApplicationVersion=lambda value: None,
                                  exec=lambda: calls.append("event_loop") or 0)
    monkeypatch.setattr(main, "QApplication", lambda *args: application)
    monkeypatch.setattr(main.sys, "argv", ["sentinel"])
    monkeypatch.setattr(ui, "ensure_usage_notice", lambda: calls.append("notice") or True)
    monkeypatch.setattr(main.DatabaseManager, "get_instance", classmethod(lambda cls: calls.append("database")))
    monkeypatch.setattr(main, "MainWindow", lambda: SimpleNamespace(show=lambda: calls.append("workspace")))
    assert main.main() == 0
    assert calls == ["notice", "database", "workspace", "event_loop"]


def test_review_is_read_only_without_acknowledgement_controls():
    app = QApplication.instance() or QApplication([])
    dialog = ui.UsageNoticeDialog(review_only=True)
    assert dialog.acknowledge.isHidden() and dialog.continue_btn.isHidden()
    assert dialog.notice.isReadOnly()
    dialog.close()
