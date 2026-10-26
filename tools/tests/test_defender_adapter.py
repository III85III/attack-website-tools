"""
Unit tests for Microsoft Defender adapter.
"""
import json

from src.adapters.defender_adapter import DefenderAdapter


def test_defender_detection(monkeypatch):
    adapter = DefenderAdapter()
    monkeypatch.setattr(adapter, "run_subprocess_safe", lambda *args, **kwargs: (
        0,
        json.dumps({
            "AMProductVersion": "4.18.0.0",
            "RealTimeProtectionEnabled": True,
        }),
        "",
    ))
    health = adapter.detect()
    assert health.name == "Microsoft Defender"
    assert health.installed is True
    assert "Active" in health.status_message


def test_defender_status_fields(monkeypatch):
    adapter = DefenderAdapter()
    expected = {
        "AntivirusEnabled": True,
        "RealTimeProtectionEnabled": True,
        "AMServiceEnabled": True,
    }
    monkeypatch.setattr(adapter, "run_subprocess_safe", lambda *args, **kwargs: (
        0,
        json.dumps(expected),
        "",
    ))
    status = adapter.get_status()
    assert status.get("available") is True
    assert "AntivirusEnabled" in status
    assert "RealTimeProtectionEnabled" in status
    assert status["AMServiceEnabled"] is True


def test_defender_unavailable_is_reported(monkeypatch):
    adapter = DefenderAdapter()
    monkeypatch.setattr(adapter, "run_subprocess_safe", lambda *args, **kwargs: (
        -3, "", "PowerShell provider unavailable"
    ))
    health = adapter.detect()
    assert health.installed is False
    assert "PowerShell provider unavailable" in health.status_message
