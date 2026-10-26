"""Parse supplied traffic off the UI thread; no network requests."""
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal
from src.core.traffic_inventory import import_har


class TrafficImportWorker(QThread):
    result = pyqtSignal(object, str)

    def __init__(self, filename, target, parent=None):
        super().__init__(parent); self.filename = filename; self.target = target

    def run(self):
        try:
            self.result.emit(import_har(Path(self.filename), self.target), "")
        except ValueError as exc:
            self.result.emit(None, str(exc))
        except Exception as exc:
            self.result.emit(None, f"Unable to read HAR ({type(exc).__name__}). No traffic was sent.")
