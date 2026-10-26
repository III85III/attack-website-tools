"""ZAP capability detection must distinguish absent service from bad verification."""
from unittest.mock import Mock, patch

import requests
import pytest

from src.adapters.zap_adapter import ZapAdapter
from src.core.models import ScanRun, ToolHealthInfo


def test_zap_valid_version_endpoint_is_verified():
    response = Mock(status_code=200)
    response.json.return_value = {"version": "2.16.1"}
    with patch("src.adapters.zap_adapter.requests.get", return_value=response):
        health = ZapAdapter().detect()
    assert health.availability_status == "INSTALLED_AND_VERIFIED"
    assert health.version == "2.16.1"


def test_zap_invalid_version_payload_is_not_reported_missing():
    response = Mock(status_code=200)
    response.json.return_value = []
    with patch("src.adapters.zap_adapter.requests.get", return_value=response):
        health = ZapAdapter().detect()
    assert health.availability_status == "VERSION_CHECK_FAILED"
    assert health.installed is False


def test_zap_unreachable_api_is_reported_missing():
    with patch("src.adapters.zap_adapter.requests.get", side_effect=requests.ConnectionError()):
        health = ZapAdapter().detect()
    assert health.availability_status == "MISSING"
    assert "connection failed" in health.status_message.lower()


@pytest.mark.parametrize("payload", [{"code": "bad_api_key"}, {}, [], {"alerts": [{}]}])
def test_invalid_zap_alert_response_is_not_a_clean_scan(payload):
    response = Mock(status_code=200)
    response.json.return_value = payload
    with patch("src.adapters.zap_adapter.requests.get", return_value=response):
        with pytest.raises(RuntimeError):
            ZapAdapter().fetch_alerts(baseurl="https://owned.test")


def test_explicit_empty_zap_alerts_are_a_valid_result():
    response = Mock(status_code=200)
    response.json.return_value = {"alerts": []}
    with patch("src.adapters.zap_adapter.requests.get", return_value=response):
        assert ZapAdapter().fetch_alerts(baseurl="https://owned.test") == []


@pytest.mark.parametrize("payload,expected", [({"code": "bad_api_key"}, "FAILED"), ({"alerts": []}, "COMPLETED")])
def test_zap_pipeline_does_not_complete_on_api_error(payload, expected, monkeypatch):
    adapter = ZapAdapter()
    monkeypatch.setattr(adapter, "detect", lambda: ToolHealthInfo(name="ZAP", installed=True, availability_status="INSTALLED_AND_VERIFIED"))
    calls = []
    def api(component, kind, operation, params=None, timeout=15):
        calls.append((component, kind, operation))
        if component == "context" and operation == "context":
            return {"context": {"id": "42"}}
        if operation == "scan":
            return {"scan": "1"}
        if operation == "status":
            return {"status": "100"}
        return {}
    monkeypatch.setattr(adapter, "_api", api)
    response = Mock(status_code=200)
    response.json.return_value = payload
    with patch("src.adapters.zap_adapter.requests.get", return_value=response):
        scan, findings = adapter.run_scan("https://owned.test", ScanRun(tool_name="ZAP", target="https://owned.test", raw_command=""))
    assert scan.status == expected
    assert findings == []
    assert ("context", "action", "removeContext") in calls


def test_zap_evidence_is_redacted_before_becoming_a_finding():
    response = Mock(status_code=200)
    response.json.return_value = {"alerts": [{"alert": "Disclosure", "url": "https://owned.test/?token=ZAP_QUERY_SECRET", "risk": "High",
                                             "evidence": "Authorization: Basic ZAP_BASIC_SECRET",
                                             "requestHeader": "Cookie: first=ZAP_COOKIE_ONE; other=ZAP_COOKIE_TWO"}]}
    with patch("src.adapters.zap_adapter.requests.get", return_value=response):
        findings = ZapAdapter().fetch_alerts(baseurl="https://owned.test")
    assert len(findings) == 1
    text = str(findings[0].to_dict())
    for secret in ("ZAP_QUERY_SECRET", "ZAP_BASIC_SECRET", "ZAP_COOKIE_ONE", "ZAP_COOKIE_TWO"):
        assert secret not in text
