from types import SimpleNamespace

from src.core.models import ScanRun
from src.voice.voice_assistant import PersianVoiceAssistant


def test_failed_scan_summary_does_not_claim_no_findings():
    assistant = PersianVoiceAssistant()
    scan = ScanRun(tool_name="Web Security Auditor", target="example.test", raw_command="")
    scan.status = "FAILED"

    summary = assistant.build_scan_summary_text(scan, [], {})

    assert "کامل نیست" in summary
    assert "امن‌بودن هدف نیست" in summary
    assert "گزارش‌ها را باز کنید" not in summary


def test_no_scan_summary_does_not_claim_tools_ran():
    assistant = PersianVoiceAssistant()
    scan = ScanRun(tool_name="System", target="Localhost", raw_command="")

    summary = assistant.build_scan_summary_text(scan, [], {})

    assert "هنوز اسکن تکمیل‌شده‌ای" in summary
    assert "با موفقیت اجرا شدند" not in summary


def test_sapi_text_is_passed_as_data_not_powershell_source(monkeypatch):
    assistant = PersianVoiceAssistant()
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("src.voice.voice_assistant.subprocess.run", fake_run)
    payload = "test'; Start-Process calc; #"

    ok, _ = assistant._speak_windows_sapi(payload)

    assert ok is True
    assert seen["env"]["SENTINEL_SPEECH_TEXT"] == payload
    assert payload not in " ".join(seen["command"])
