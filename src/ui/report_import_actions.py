"""File parsing and atomic database persistence run outside the GUI thread."""
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QFileDialog, QLabel, QPushButton, QVBoxLayout, QWidget

from src.adapters.report_import_adapter import ReportImportAdapter
from src.core.database import DatabaseManager
from src.core.privacy import sanitize_text


class ReportImportWorker(QThread):
    result = pyqtSignal(object, str)

    def __init__(self, path, db_path, parent=None):
        super().__init__(parent)
        self.path, self.db_path = path, db_path

    def run(self):
        database = None
        try:
            scan, findings = ReportImportAdapter().import_file(self.path)
            database = DatabaseManager(self.db_path)
            database.save_import(scan, findings)
            self.result.emit(scan, "")
        except Exception as exc:
            self.result.emit(None, sanitize_text(f"{type(exc).__name__}: {exc}"))
        finally:
            if database:
                database.close()


class ReportImportActions(QWidget):
    imported = pyqtSignal(object)

    def __init__(self, db_path, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self.worker = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.button = QPushButton("Import scanner report")
        self.button.clicked.connect(self.choose_file)
        layout.addWidget(self.button)
        self.message = QLabel("SARIF, Nuclei JSON/JSONL, JSON or Nmap XML. Files are never executed.")
        self.message.setWordWrap(True)
        layout.addWidget(self.message)

    def choose_file(self):
        if self.worker and self.worker.isRunning():
            return
        path, _ = QFileDialog.getOpenFileName(self, "Import Security Scanner Report", "",
                                            "Reports (*.sarif *.json *.jsonl *.xml);;All Files (*.*)")
        if path:
            self.start_import(path)

    def start_import(self, path):
        if self.worker and self.worker.isRunning():
            return
        self.message.setText("Reading report and saving assessment…")
        self.button.setEnabled(False)
        self.worker = ReportImportWorker(path, self.db_path, self)
        self.worker.result.connect(self._on_result)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def _on_result(self, scan, error):
        if error:
            self.message.setText(f"Import failed. No assessment was saved. {error}")
            return
        self.message.setText(
            f"Imported {scan.findings_count} finding(s) from {scan.tool_name}. Status: {scan.status}. "
            "Source scan coverage is unverified. " + (scan.error_message or "")
        )
        self.imported.emit(scan)

    def _on_finished(self):
        self.button.setEnabled(True)
