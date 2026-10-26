"""Data-backed route, research and evidence inspection for stored assessments."""
from __future__ import annotations
import json

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QPushButton,
    QSplitter, QTabWidget, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from src.core.database import DatabaseManager
from src.core.privacy import sanitize_data
from src.ui.surface_graph import SurfaceGraph


class IntelligenceWorkspace(QWidget):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager.get_instance()
        layout = QVBoxLayout(self)
        title = QLabel("Assessment intelligence")
        title.setStyleSheet("font-size:24px; font-weight:700;")
        layout.addWidget(title)
        description = QLabel("Recorded routes, bounded research and evidence. Observation is distinct from verification; no inferred attack chain is presented as proven.")
        description.setWordWrap(True); layout.addWidget(description)
        controls = QHBoxLayout()
        self.scans = QComboBox(); controls.addWidget(self.scans, 1)
        refresh = QPushButton("Refresh assessments"); refresh.clicked.connect(self.refresh_scans); controls.addWidget(refresh)
        layout.addLayout(controls)
        self.summary = QLabel("No assessment selected."); self.summary.setWordWrap(True); layout.addWidget(self.summary)
        split = QSplitter(Qt.Orientation.Vertical)
        self.tabs = QTabWidget()
        self.surface = SurfaceGraph()
        self.surface.inspected.connect(self._inspect_record)
        self.tabs.addTab(self.surface, "Surface relationships")
        self.routes = self._tree(["Method", "Route", "Identity context", "Collected", "Security check", "Validated records"])
        self.research = self._tree(["Hypothesis", "Parameter", "Outcome", "Requests"])
        self.timeline = self._tree(["Recorded time", "Operation", "Outcome"])
        self.findings = self._tree(["Finding", "Severity", "Confidence", "Verification state"])
        for title, tree in [("Routes", self.routes), ("Research", self.research), ("Evidence timeline", self.timeline), ("Finding confidence", self.findings)]:
            self.tabs.addTab(tree, title)
        split.addWidget(self.tabs)
        self.details = QTextBrowser(); self.details.setOpenExternalLinks(False)
        self.details.setPlaceholderText("Select a route, hypothesis, event or finding to inspect its recorded evidence.")
        split.addWidget(self.details); split.setSizes([470, 220]); layout.addWidget(split, 1)
        self.scans.currentIndexChanged.connect(self.load_assessment)
        self.refresh_scans()

    def _tree(self, headers):
        tree = QTreeWidget(); tree.setHeaderLabels(headers); tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True); tree.setUniformRowHeights(True)
        tree.currentItemChanged.connect(lambda current, _old: self._inspect(current))
        return tree

    def _inspect(self, item):
        if item is None:
            return
        self._inspect_record(item.data(0, Qt.ItemDataRole.UserRole))

    def _inspect_record(self, record):
        raw = json.dumps(sanitize_data(record), ensure_ascii=False, indent=2)
        self.details.setPlainText(raw[:24000] + ("\n[Display truncated; export assessment JSON for the complete record.]" if len(raw) > 24000 else ""))

    @staticmethod
    def _add(tree, columns, record):
        item = QTreeWidgetItem([str(value) for value in columns])
        item.setData(0, Qt.ItemDataRole.UserRole, sanitize_data(record)); tree.addTopLevelItem(item)

    def refresh_scans(self):
        selected = self.scans.currentData()
        self.scans.blockSignals(True); self.scans.clear()
        try:
            for scan in self.db.list_scans(limit=50, root_only=True):
                self.scans.addItem(f"{scan.start_time[:19]} · {scan.target} · {scan.status}", scan.id)
        except Exception as exc:
            self.summary.setText(f"Assessment history unavailable ({type(exc).__name__}).")
        index = self.scans.findData(selected)
        if index >= 0:self.scans.setCurrentIndex(index)
        self.scans.blockSignals(False); self.load_assessment()

    def load_assessment(self, *_args):
        for tree in [self.routes, self.research, self.timeline, self.findings]:tree.clear()
        self.details.clear()
        scan_id = self.scans.currentData()
        if not scan_id:
            self.surface.load_graph({})
            self.summary.setText("No assessment available. Run a scan to collect real evidence."); return
        scan = self.db.get_scan(scan_id)
        if scan is None:
            self.summary.setText("The assessment no longer exists."); return
        self.surface.load_graph(next((e for e in scan.execution_log if e.get("operation") == "Application relationships"), {}))
        coverage = next((e for e in scan.execution_log if e.get("operation") == "Route verification coverage"), {})
        total, tested = coverage.get("discovered_routes"), coverage.get("security_checked_discovered_routes")
        self.summary.setText(f"{scan.status} · {scan.request_count} recorded native/assessment HTTP requests · " +
            (f"{tested}/{total} discovered routes had a recorded completed security check. Collection is not a safety verdict." if total is not None else "This older assessment has no route-coverage record; coverage is unknown."))
        for row in coverage.get("routes", []):
            self._add(self.routes, [row["method"], row["url"], row.get("identity_context", "anonymous"),
                "yes" if row["requested"] else "not collected", "completed bounded check" if row["security_checked"] else "not established", row["verified_findings"]], row)
        for event in scan.execution_log:
            self._add(self.timeline, [event.get("timestamp", "not recorded"), event.get("operation", "Recorded engine event"), event.get("state", "see evidence")], event)
            if event.get("operation") == "Research hypotheses":
                for row in event.get("hypotheses", []):
                    self._add(self.research, [row["class"], row["parameter"], row["state"], f"{row['requests_collected']}/{row['request_budget']}"], row)
            if event.get("operation") == "Native request provenance":
                for request in event.get("requests", []):
                    self._add(self.timeline, [request.get("collected_at_utc", "not recorded"), request["method"] + " " + request["url"], request["status"]], request)
        for finding in self.db.list_findings(scan_id=scan_id, limit=250):
            self._add(self.findings, [finding.title, finding.severity.value, finding.confidence.value, finding.status.value], finding.to_dict())
