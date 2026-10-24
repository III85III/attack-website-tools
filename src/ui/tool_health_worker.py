"""Bounded existing health probes run away from the GUI thread."""
from PyQt6.QtCore import QThread, pyqtSignal

from src.adapters.web_auditor import WebAuditorAdapter
from src.adapters.browser_xss import BrowserXSSVerifier
from src.adapters.nmap_adapter import NmapAdapter
from src.adapters.defender_adapter import DefenderAdapter
from src.adapters.zap_adapter import ZapAdapter
from src.adapters.pcap_adapter import PcapAdapter
from src.adapters.external_tool_catalog import external_tool_health
from src.core.database import DatabaseManager
from src.core.models import ToolHealthInfo
from src.core.privacy import sanitize_text


def health_checks():
    return [(name, lambda factory=factory: factory().detect()) for name, factory in (
        ("Web Security Auditor", WebAuditorAdapter), ("Nmap", NmapAdapter),
        ("Browser XSS verification", BrowserXSSVerifier),
        ("Windows Defender", DefenderAdapter), ("OWASP ZAP", ZapAdapter), ("PCAP", PcapAdapter),
    )] + [("Optional tool inventory", external_tool_health)]


class ToolHealthWorker(QThread):
    progress = pyqtSignal(str)
    result = pyqtSignal(object, str)

    def __init__(self, db_path, parent=None):
        super().__init__(parent)
        self.db_path = db_path

    def run(self):
        database = None
        records = []
        try:
            for name, check in health_checks():
                self.progress.emit(f"Checking {name}…")
                try:
                    value = check()
                    items = value if isinstance(value, list) else [value]
                    if not items or any(not isinstance(item, ToolHealthInfo) for item in items):
                        raise ValueError("Detector returned no valid health records")
                    records.extend(items)
                except Exception as exc:
                    records.append(ToolHealthInfo(
                        name=name, installed=False, availability_status="EXECUTION_FAILED",
                        status_message=sanitize_text(f"Availability unknown: {type(exc).__name__}: {exc}"),
                    ))
            records.extend([
                ToolHealthInfo(name="Persian Voice Assistant", installed=True,
                               version="Not checked", availability_status="VERSION_CHECK_FAILED",
                               status_message="Optional speech feature; synthesis has not been checked."),
                ToolHealthInfo(name="CISA KEV Intelligence", installed=True,
                               version="Not checked", availability_status="VERSION_CHECK_FAILED",
                               status_message="Optional cached intelligence; cache freshness has not been checked."),
            ])
            database = DatabaseManager(self.db_path)
            database.save_tool_health_batch(records)
            self.result.emit(records, "")
        except Exception as exc:
            self.result.emit(records, sanitize_text(f"Health results were not saved: {type(exc).__name__}: {exc}"))
        finally:
            if database:
                database.close()
