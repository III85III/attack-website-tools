"""
III85III QOLAM SENTINEL — Persian Voice Assistant
Generates authentic spoken Persian summaries using edge-tts or Windows speech engine.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.models import Finding, ScanRun

logger = logging.getLogger("qolam.voice")


class PersianVoiceAssistant:
    """Natural Persian voice communicator for scan summaries and alerts."""

    def __init__(self, voice_name: str = "fa-IR-DilaraNeural"):
        self.voice_name = voice_name
        self._speech_available: Optional[bool] = None

    def build_scan_summary_text(
        self,
        scan: ScanRun,
        findings: List[Finding],
        tools_status: Dict[str, bool],
    ) -> str:
        """Create a truthful Persian summary based solely on collected findings."""
        target = scan.target
        total_findings = len(findings)

        # Count severities
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev_val in sev_counts:
                sev_counts[sev_val] += 1

        tools_succeeded = [name for name, ok in tools_status.items() if ok]
        tools_failed = [name for name, ok in tools_status.items() if not ok]

        if scan.status == "COMPLETED":
            parts = [f"ارزیابی {target} تکمیل شد."]
        elif scan.status in {"FAILED", "CANCELLED", "PARTIAL"}:
            parts = [f"ارزیابی {target} با وضعیت {scan.status} پایان یافت؛ نتیجه کامل نیست."]
        else:
            parts = [f"هنوز اسکن تکمیل‌شده‌ای برای {target} ثبت نشده است."]
        if tools_succeeded:
            parts.append(f"ابزارهای {', '.join(tools_succeeded)} با موفقیت اجرا شدند.")
        if tools_failed:
            parts.append(f"ابزارهای {', '.join(tools_failed)} در دسترس نبودند یا با خطا مواجه شدند.")

        if scan.status == "COMPLETED" and total_findings == 0:
            parts.append("یافته‌ای ثبت نشد؛ این نتیجه به‌تنهایی امنیت کامل هدف را ثابت نمی‌کند.")
        elif scan.status != "COMPLETED":
            parts.append("به‌دلیل ناقص‌بودن یا نبود نتیجهٔ تکمیل‌شده، نبود یافته به‌معنی امن‌بودن هدف نیست.")
        elif total_findings == 0:
            parts.append("یافته‌ای در داده‌های انتخاب‌شده ثبت نشده است.")
        else:
            parts.append(
                f"در مجموع تعداد {total_findings} یافته ثبت شد: "
                f"{sev_counts['CRITICAL']} مورد بحرانی، {sev_counts['HIGH']} مورد بالا، "
                f"و {sev_counts['MEDIUM']} مورد با شدت متوسط."
            )

        if scan.status == "COMPLETED":
            parts.append("برای ساخت فایل Word یا JSON، بخش گزارش‌ها را باز کنید.")
        return " ".join(parts)

    def speak(self, text: str, allow_online: bool = False) -> Tuple[bool, str]:
        """
        Synthesize and play Persian speech using edge-tts or Windows SAPI.
        Never pretends to speak if audio cannot be produced.
        """
        if not text or not text.strip():
            return False, "متن جهت تبدیل به گفتار خالی است."

        if os.name != "nt":
            return False, "Voice playback is currently Windows-only; reports and scanning remain available."

        if allow_online:
            tmp_path = ""
            try:
                import edge_tts

                async def _synthesize(audio_file: str):
                    communicate = edge_tts.Communicate(text, self.voice_name)
                    await communicate.save(audio_file)

                with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as tmp:
                    tmp_path = tmp.name

                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(_synthesize(tmp_path))
                finally:
                    loop.close()

                env = os.environ.copy()
                env["SENTINEL_AUDIO_PATH"] = tmp_path
                result = subprocess.run(
                    [
                        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                        "$wm = New-Object -ComObject WMPlayer.OCX; "
                        "$wm.URL = $env:SENTINEL_AUDIO_PATH; $wm.controls.play(); "
                        "Start-Sleep -Seconds 3; if ($wm.playState -eq 1) { exit 1 }",
                    ],
                    capture_output=True,
                    timeout=10,
                    env=env,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode == 0:
                    return True, "خلاصه با سرویس گفتار آنلاین ساخته و پخش شد."
            except Exception:
                logger.exception("Online Persian speech failed; trying local Windows SAPI")
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        logger.warning("Could not remove temporary speech file")

        return self._speak_windows_sapi(text)

    def _speak_windows_sapi(self, text: str) -> Tuple[bool, str]:
        """Offline fallback using Windows SAPI TTS."""
        try:
            env = os.environ.copy()
            env["SENTINEL_SPEECH_TEXT"] = text
            code = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "$voice = New-Object -ComObject SAPI.SpVoice; "
                    "[void]$voice.Speak($env:SENTINEL_SPEECH_TEXT)",
                ],
                capture_output=True,
                timeout=8,
                env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).returncode
            if code == 0:
                return True, "صوت از طریق موتور آفلاین ویندوز پخش گردید."
            return False, "موتور صوتی ویندوز در دسترس نیست."
        except Exception as exc:
            return False, f"عدم امکان پخش صوت: {str(exc)}"
