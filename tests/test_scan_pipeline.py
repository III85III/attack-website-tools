"""Local end-to-end coverage for observable live HTTP scan behavior."""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.adapters.web_auditor import WebAuditorAdapter
from src.core.database import DatabaseManager
from src.core.models import ScanRun, ToolHealthInfo
from src.reporting.docx_report import JSONExporter
from src.adapters.nmap_adapter import NmapAdapter


class _TargetHandler(BaseHTTPRequestHandler):
    paths = []

    def do_GET(self):
        type(self).paths.append(self.path)
        body = b"<html><head><title>Local test target</title></head><body>hello</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture
def local_http_target():
    _TargetHandler.paths = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_live_local_http_pipeline_records_real_requests_and_responses(local_http_target):
    adapter = WebAuditorAdapter()
    scan = ScanRun(tool_name="Sentinel DAST", target=local_http_target, raw_command="")

    result, findings = adapter.run_scan(local_http_target, scan)

    assert result.status == "COMPLETED"
    assert result.request_count >= 2
    assert result.response_status == 200
    assert result.duration_ms >= 0
    assert len(_TargetHandler.paths) == result.request_count
    assert any("Missing Content-Security-Policy" in finding.title for finding in findings)
    assert result.findings_count == len(findings)
    assert result.execution_log[-1]["state"] == "COMPLETED"


def test_invalid_target_fails_before_network_activity(monkeypatch):
    adapter = WebAuditorAdapter()
    monkeypatch.setattr(adapter.session, "get", lambda *_a, **_kw: pytest.fail("network request must not run"))
    scan = ScanRun(tool_name="Sentinel DAST", target="file:///etc/passwd", raw_command="")

    result, _findings = adapter.run_scan("file:///etc/passwd", scan)

    assert result.status == "FAILED"
    assert result.request_count == 0
    assert result.response_status is None


def test_connection_failure_is_not_an_empty_success():
    adapter = WebAuditorAdapter()
    scan = ScanRun(tool_name="Sentinel DAST", target="http://127.0.0.1:1/", raw_command="")

    result, findings = adapter.run_scan(scan.target, scan)

    assert result.status == "FAILED"
    assert result.exit_code != 0
    assert result.request_count >= 1
    assert result.response_status is None
    assert findings
    assert "did not produce a response" in result.completion_reason


def test_database_and_json_export_preserve_the_same_findings(local_http_target, tmp_path):
    adapter = WebAuditorAdapter()
    scan = ScanRun(tool_name="Sentinel DAST", target=local_http_target, raw_command="")
    result, findings = adapter.run_scan(local_http_target, scan)
    db = DatabaseManager(tmp_path / "pipeline.db")
    try:
        db.save_scan(result)
        for finding in findings:
            db.save_finding(finding)
        restored = db.get_scan(result.id)
        assert restored is not None
        assert restored.request_count == result.request_count
        assert restored.response_status == 200
        assert restored.execution_log == result.execution_log

        output = JSONExporter(tmp_path / "reports").export_json(
            restored, db.list_findings(scan_id=result.id), [
                ToolHealthInfo(name="OWASP ZAP", installed=False, availability_status="MISSING")
            ]
        )
        payload = json.loads(output.read_text(encoding="utf-8"))
        assert payload["scan"]["status"] == "COMPLETED"
        assert payload["scan"]["request_count"] == len(_TargetHandler.paths)
        assert {item["id"] for item in payload["findings"]} == {item.id for item in findings}
    finally:
        db.close()


def test_tool_archive_state_is_not_reported_as_installed():
    item = ToolHealthInfo(
        name="Example Source Bundle",
        installed=False,
        path="example.zip",
        status_message="Source archive only",
        availability_status="ARCHIVE_ONLY",
    )
    assert item.to_dict()["availability_status"] == "ARCHIVE_ONLY"
    assert item.to_dict()["installed"] is False


@pytest.mark.parametrize("code,stderr", [(-1, "Timeout of 1s expired"), (2, "permission denied")])
def test_nmap_timeout_and_process_errors_are_failed(code, stderr, monkeypatch):
    adapter = NmapAdapter(executable_path="nmap")
    monkeypatch.setattr(adapter, "_resolve_executable", lambda: "nmap")
    monkeypatch.setattr(adapter, "run_subprocess_safe", lambda *_a, **_kw: (code, "", stderr))
    scan = ScanRun(tool_name="Nmap", target="127.0.0.1", raw_command="")

    result, findings = adapter.run_scan("127.0.0.1", scan, {"ports": "80", "timeout_sec": 1})

    assert result.status == "FAILED"
    assert result.exit_code == code
    assert stderr in result.error_message
    assert findings == []
    assert result.execution_log[-1]["exit_code"] == code


def test_worker_does_not_block_qt_event_loop(local_http_target, tmp_path, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtCore import QEventLoop, QTimer
    from PyQt6.QtWidgets import QApplication
    from src.adapters.zap_adapter import ZapAdapter
    from src.ui.tabs import WebAuditWorker

    app = QApplication.instance() or QApplication([])
    db = DatabaseManager(tmp_path / "worker.db")
    monkeypatch.setattr(DatabaseManager, "get_instance", classmethod(lambda cls, *_a, **_kw: db))
    monkeypatch.setattr(ZapAdapter, "detect", lambda _self: ToolHealthInfo(name="OWASP ZAP", installed=False, availability_status="MISSING"))
    monkeypatch.setattr(NmapAdapter, "detect", lambda _self: ToolHealthInfo(name="Nmap", installed=False, availability_status="MISSING"))
    monkeypatch.setattr("src.ui.tabs.write_execution_log", lambda scan: tmp_path / f"{scan.id}.json")

    worker = WebAuditWorker(local_http_target, deep_scan=False)
    loop = QEventLoop()
    timer_fired = []
    results = []
    worker.finished_signal.connect(lambda scan, findings: (results.append((scan, findings)), loop.quit()))
    QTimer.singleShot(10, lambda: timer_fired.append(True))
    QTimer.singleShot(10000, loop.quit)
    worker.start()
    loop.exec()
    worker.wait(5000)

    assert timer_fired, "Qt event loop should process a timer during the live scan"
    assert results and results[0][0].status == "COMPLETED"
    assert results[0][0].request_count >= 2
    completed, findings = results[0]
    assert {f.id for f in db.list_findings(scan_id=completed.id, limit=None)} == {f.id for f in findings}
    assert app is not None


def test_packaged_scanner_verifier_is_loopback_only(tmp_path):
    from main import _verify_local_scanner

    output = tmp_path / "verification.json"
    assert _verify_local_scanner("https://example.com/", str(output)) == 1
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "FAILED"


def test_packaged_scanner_verifier_uses_live_pipeline(local_http_target, tmp_path):
    from main import _verify_local_scanner

    output = tmp_path / "verification.json"
    assert _verify_local_scanner(local_http_target, str(output)) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    from src.core.config import APP_VERSION
    assert payload["application_version"] == APP_VERSION
    assert payload["scan"]["status"] == "COMPLETED"
    assert payload["scan"]["request_count"] == len(_TargetHandler.paths)


def test_local_runtime_verification_artifact_redacts_response_evidence(local_http_target, tmp_path, monkeypatch):
    from main import _verify_local_scanner
    monkeypatch.setattr(_TargetHandler, "version_string", lambda self: "Fixture/1.2 token=RUNTIME_HEADER_SECRET")
    output = tmp_path / "runtime-privacy.json"
    assert _verify_local_scanner(local_http_target, str(output)) == 0
    text = output.read_text(encoding="utf-8")
    assert "RUNTIME_HEADER_SECRET" not in text
    assert json.loads(text)["scan"]["response_status"] == 200
