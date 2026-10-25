"""Non-blocking exports attached to one explicit assessment."""
from pathlib import Path

from PyQt6.QtCore import QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from src.core.database import DatabaseManager
from src.reporting.export_service import export_assessment


class ReportExportWorker(QThread):
    result = pyqtSignal(str, str)

    def __init__(self, scan_id, report_format, target_name="", title="", parent=None):
        super().__init__(parent)
        self.scan_id = scan_id
        self.report_format = report_format
        self.target_name = target_name
        self.title = title

    def run(self):
        db = None
        try:
            db = DatabaseManager.get_instance()
            path = export_assessment(db, self.scan_id, self.report_format,
                                     target_name=self.target_name, title=self.title)
            self.result.emit(str(path), "")
        except Exception as exc:
            self.result.emit("", f"Report export failed: {exc}")
        finally:
            if db is not None:
                db.close()


class AssessmentReportActions(QWidget):
    """The same export controls serve the scanner and assessment history."""
    busy_changed = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_id = None
        self.worker = None
        self.last_path = None
        self.target_name = ""
        self.title = "Security Assessment Report"
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.word_btn = QPushButton("Export Word report")
        self.word_btn.setProperty("class", "ActionBtn")
        self.html_btn = QPushButton("Export HTML")
        self.md_btn = QPushButton("Export Markdown")
        self.json_btn = QPushButton("Export JSON")
        self.open_btn = QPushButton("Open report")
        self.folder_btn = QPushButton("Show in folder")
        for button in (self.word_btn, self.html_btn, self.md_btn, self.json_btn, self.open_btn, self.folder_btn):
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)
        self.message = QLabel("Complete a scan to export its report.")
        self.message.setWordWrap(True)
        self.message.setStyleSheet("color:#8ea9c0; font-size:11px;")
        layout.addWidget(self.message)
        self.word_btn.clicked.connect(lambda: self.export("docx"))
        self.html_btn.clicked.connect(lambda: self.export("html"))
        self.md_btn.clicked.connect(lambda: self.export("markdown"))
        self.json_btn.clicked.connect(lambda: self.export("json"))
        self.open_btn.clicked.connect(self.open_report)
        self.folder_btn.clicked.connect(self.open_folder)
        self._refresh_buttons()

    def set_assessment(self, scan):
        self.scan_id = scan.id if scan and scan.status not in {"RUNNING", "QUEUED"} else None
        self.last_path = None
        if not self.worker or not self.worker.isRunning():
            self.message.setText("Export every finding from this assessment, including its optional engines."
                                 if self.scan_id else "Complete a scan to export its report.")
        self._refresh_buttons()

    def _refresh_buttons(self):
        busy = bool(self.worker and self.worker.isRunning())
        enabled = bool(self.scan_id) and not busy
        self.word_btn.setEnabled(enabled)
        self.html_btn.setEnabled(enabled)
        self.md_btn.setEnabled(enabled)
        self.json_btn.setEnabled(enabled)
        self.open_btn.setEnabled(bool(self.last_path) and not busy)
        self.folder_btn.setEnabled(bool(self.last_path) and not busy)

    def export(self, report_format):
        if not self.scan_id or (self.worker and self.worker.isRunning()):
            return
        self.message.setText("Building report from the selected assessment…")
        self.worker = ReportExportWorker(self.scan_id, report_format, self.target_name, self.title, self)
        self.worker.result.connect(self._on_result)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()
        self.busy_changed.emit(True)
        self._refresh_buttons()

    def _on_finished(self):
        self._refresh_buttons()
        self.busy_changed.emit(False)

    def _on_result(self, path, error):
        self.last_path = Path(path) if path else None
        self.message.setText(error or f"Report saved: {path}")

    def open_report(self):
        if self.last_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_path)))

    def open_folder(self):
        if self.last_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_path.parent)))
