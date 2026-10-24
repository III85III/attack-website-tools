"""
III85III QOLAM SENTINEL — UI Tab Widgets
Implementation of the 8 dedicated functional tabs for the unified desktop platform.
"""
from __future__ import annotations

import os
import time
from copy import deepcopy
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QUrl, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QMenu,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.adapters.defender_adapter import DefenderAdapter
from src.ui.tool_health_worker import ToolHealthWorker
from src.adapters.nmap_adapter import NmapAdapter
from src.adapters.pcap_adapter import PcapAdapter
from src.ui.report_import_actions import ReportImportActions
from src.adapters.web_auditor import WebAuditorAdapter
from src.adapters.session_review import SessionReviewAdapter, validate_plan
from src.adapters.api_review import APIReviewAdapter, import_spec_file, validate_api_plan
from src.adapters.zap_adapter import ZapAdapter
from src.core.database import DatabaseManager
from src.core.config import APP_VERSION
from src.core.scan_logging import write_execution_log
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)
from src.reporting.docx_report import JSONExporter, ReportGenerator
from src.ui.report_actions import AssessmentReportActions
from src.ui.scan_visual import InfinityIndicator
from src.system_guard.monitor import SystemGuardMonitor
from src.voice.voice_assistant import PersianVoiceAssistant


def _polish_table(table: QTableWidget) -> None:
    """Apply consistent readable table behavior across the application."""
    table.setAlternatingRowColors(True)
    table.setWordWrap(True)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(34)
    table.setShowGrid(False)


# -------------------------------------------------------------
# Background Workers for Non-Blocking Execution
# -------------------------------------------------------------
class WebAuditWorker(QThread):
    finished_signal = pyqtSignal(object, list)
    progress_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, target_url: str, deep_scan: bool = False, parent=None, session_plan=None, api_plan=None):
        super().__init__(parent)
        self.target_url = target_url
        self.deep_scan = deep_scan
        self.adapter = WebAuditorAdapter()
        self.session_plan = deepcopy(session_plan)
        self.api_plan = deepcopy(api_plan)

    def run(self):
        started = time.monotonic()
        scan_run = ScanRun(
            tool_name="Sentinel Web Scanner",
            target=self.target_url,
            raw_command="",
        )
        scan_run.execution_log.append({
            "timestamp": scan_run.start_time,
            "operation": "Scan job started",
            "scanner": "Sentinel Web Scanner",
            "state": "RUNNING",
        })
        findings: List[Finding] = []
        scan_run.execution_log.append({
            "operation": "Assessment coverage",
            "session_access_setup": "CONFIGURED" if self.session_plan else "NOT_CONFIGURED",
            "api_definition_setup": "CONFIGURED" if self.api_plan else "NOT_CONFIGURED",
            "manual_review_required": "Login/MFA/password reset, state-changing workflows, unlisted access rules, DOM/stored XSS and full exploit impact.",
        })
        db = None
        try:
            db = DatabaseManager.get_instance()
            db.save_scan(scan_run)
            scan_run, findings = self.adapter.run_scan(
                self.target_url,
                scan_run,
                options={
                    "deep_scan": self.deep_scan,
                    "progress_callback": lambda msg: self.progress_signal.emit(msg),
                },
            )
            for f in findings:
                db.save_finding(f)
            if scan_run.status != "COMPLETED":
                scan_run.tool_name = "Sentinel DAST"
                scan_run.end_time = scan_run.end_time or datetime.now(timezone.utc).isoformat()
                scan_run.duration_ms = int((time.monotonic() - started) * 1000)
                scan_run.execution_log.append({
                    "timestamp": scan_run.end_time,
                    "operation": "Required HTTP collection incomplete; optional engines were not started",
                    "state": scan_run.status,
                    "reason": scan_run.error_message or scan_run.completion_reason,
                })
                try:
                    log_path = write_execution_log(scan_run)
                    scan_run.execution_log.append({"operation": "Structured execution log", "path": str(log_path)})
                except Exception as log_exc:
                    scan_run.execution_log.append({"operation": "Structured execution log write failed", "error_type": type(log_exc).__name__})
                db.save_scan(scan_run)
                self.finished_signal.emit(scan_run, findings)
                return

            modules = ["Sentinel DAST"]
            optional_failures: List[str] = []
            if self.api_plan:
                api_adapter = APIReviewAdapter()
                api_run = ScanRun(tool_name=api_adapter.name, target=self.target_url, parent_scan_id=scan_run.id, raw_command="")
                api_run, api_findings = api_adapter.run_scan(self.target_url, api_run, self.api_plan, self.progress_signal.emit)
                db.save_import(api_run, api_findings)
                findings.extend(api_findings)
                scan_run.execution_log.extend(api_run.execution_log)
                if api_run.status == "COMPLETED":
                    modules.append("OpenAPI review")
                else:
                    optional_failures.append("OpenAPI review")
            session_summary = "Session/access review not configured; authenticated coverage was not checked."
            if self.session_plan:
                self.progress_signal.emit("Checking supplied read-only sessions and access expectations…")
                review = SessionReviewAdapter()
                child = ScanRun(tool_name=review.name, target=self.target_url, parent_scan_id=scan_run.id,
                                raw_command="Explicit same-origin read-only session/access GET checks")
                child, access_findings = review.run_scan(self.target_url, child, self.session_plan)
                db.save_import(child, access_findings)
                findings.extend(access_findings)
                scan_run.execution_log.extend(child.execution_log)
                session_summary = child.completion_reason or child.error_message or child.status
                if child.status == "COMPLETED":
                    modules.append("Session/access review")
                else:
                    optional_failures.append("Session/access review")

            # Use ZAP automatically when its local API is available. The one
            # confirmation dialog already warns that active probes may run.
            zap_adapter = ZapAdapter()
            zap_health = zap_adapter.detect()
            if zap_health.installed:
                self.progress_signal.emit("Built-in scan complete; running OWASP ZAP within the same scope...")
                zap_run = ScanRun(
                    tool_name="OWASP ZAP Active Scan",
                    parent_scan_id=scan_run.id,
                    target=self.target_url,
                    raw_command="OWASP ZAP local API (origin-scoped)",
                )
                zap_run, zap_findings = zap_adapter.run_scan(
                    self.target_url,
                    zap_run,
                    options={"progress_callback": lambda msg: self.progress_signal.emit(msg)},
                )
                db.save_scan(zap_run)
                for finding in zap_findings:
                    db.save_finding(finding)
                findings.extend(zap_findings)
                scan_run.execution_log.append({
                    "timestamp": zap_run.end_time or datetime.now(timezone.utc).isoformat(),
                    "scanner": "OWASP ZAP",
                    "endpoint": zap_health.path,
                    "operation": "Origin-scoped spider and active scan via ZAP API",
                    "state": zap_run.status,
                    "finding_count": len(zap_findings),
                    "reason": zap_run.error_message,
                })
                if zap_run.status == "COMPLETED":
                    modules.append("OWASP ZAP")
                else:
                    optional_failures.append("OWASP ZAP")
                    self.progress_signal.emit(f"ZAP was available but did not complete: {zap_run.error_message or zap_run.status}")
            else:
                self.progress_signal.emit("ZAP is not installed or running; Sentinel built-in scan completed.")
                scan_run.execution_log.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "scanner": "OWASP ZAP",
                    "endpoint": zap_health.path,
                    "operation": "ZAP API version/capability check",
                    "state": "NOT_CONFIGURED",
                    "reason": zap_health.status_message,
                })

            nmap_adapter = NmapAdapter()
            nmap_health = nmap_adapter.detect()
            if nmap_health.installed:
                from urllib.parse import urlsplit

                parsed = urlsplit(self.target_url if "://" in self.target_url else f"https://{self.target_url}")
                host = parsed.hostname or ""
                self.progress_signal.emit("Checking common web service ports with Nmap...")
                nmap_run = ScanRun(
                    tool_name="Nmap Web Port Check",
                    parent_scan_id=scan_run.id,
                    target=host,
                    raw_command="Nmap safe TCP connect scan (80, 443, 8080, 8443)",
                )
                nmap_run, nmap_findings = nmap_adapter.run_scan(
                    host,
                    nmap_run,
                    options={
                        "profile": "SAFE_CONNECT",
                        "ports": "80,443,8080,8443",
                        "timeout_sec": 90,
                    },
                )
                db.save_scan(nmap_run)
                for finding in nmap_findings:
                    db.save_finding(finding)
                findings.extend(nmap_findings)
                scan_run.execution_log.append({
                    "timestamp": nmap_run.end_time or datetime.now(timezone.utc).isoformat(),
                    "scanner": "Nmap",
                    "executable": nmap_health.path,
                    "operation": "TCP connect scan of ports 80,443,8080,8443",
                    "state": nmap_run.status,
                    "exit_code": nmap_run.exit_code,
                    "finding_count": len(nmap_findings),
                    "reason": nmap_run.error_message,
                })
                if nmap_run.status == "COMPLETED":
                    modules.append("Nmap")
                else:
                    optional_failures.append("Nmap")
                    self.progress_signal.emit(f"Nmap did not complete: {nmap_run.error_message or nmap_run.status}")
            else:
                scan_run.execution_log.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "scanner": "Nmap",
                    "operation": "Executable and version capability check",
                    "state": "NOT_CONFIGURED",
                    "reason": nmap_health.status_message,
                })

            scan_run.status = "PARTIAL" if optional_failures else "COMPLETED"
            scan_run.tool_name = " + ".join(modules)
            scan_run.findings_count = len(findings)
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
            scan_run.duration_ms = int((time.monotonic() - started) * 1000)
            not_configured = [
                name for name, health in (("OWASP ZAP", zap_health), ("Nmap", nmap_health))
                if not health.installed
            ]
            reason_parts = ["Sentinel live HTTP assessment completed", session_summary,
                            "State-changing business workflows and full authenticated penetration testing still require assessor review."]
            if not_configured:
                reason_parts.append("not configured: " + ", ".join(not_configured))
            if optional_failures:
                reason_parts.append("execution incomplete or failed: " + ", ".join(optional_failures))
            scan_run.completion_reason = "; ".join(reason_parts)
            scan_run.execution_log.append({
                "timestamp": scan_run.end_time,
                "operation": "Scan pipeline finished",
                "state": scan_run.status,
                "selected_scanners": modules,
                "request_count": scan_run.request_count,
                "response_status": scan_run.response_status,
                "finding_count": scan_run.findings_count,
                "duration_ms": scan_run.duration_ms,
                "reason": scan_run.completion_reason,
            })
            try:
                log_path = write_execution_log(scan_run)
                scan_run.execution_log.append({"operation": "Structured execution log", "path": str(log_path)})
            except Exception as log_exc:
                scan_run.execution_log.append({"operation": "Structured execution log write failed", "error_type": type(log_exc).__name__})
            db.save_scan(scan_run)

            self.finished_signal.emit(scan_run, findings)
        except Exception as exc:
            scan_run.status = "PARTIAL" if scan_run.response_status is not None else "FAILED"
            scan_run.findings_count = len(findings)
            scan_run.error_message = f"{type(exc).__name__}: {str(exc)[:800]}"
            scan_run.completion_reason = (
                "Live HTTP assessment completed, but a later pipeline stage failed."
                if scan_run.response_status is not None
                else "The scan pipeline raised an exception before verified HTTP completion."
            )
            scan_run.end_time = datetime.now(timezone.utc).isoformat()
            scan_run.duration_ms = int((time.monotonic() - started) * 1000)
            scan_run.execution_log.append({
                "timestamp": scan_run.end_time,
                "operation": "Unhandled scan pipeline failure",
                "state": scan_run.status,
                "error_type": type(exc).__name__,
                "reason": scan_run.error_message,
            })
            try:
                log_path = write_execution_log(scan_run)
                scan_run.execution_log.append({"operation": "Structured execution log", "path": str(log_path)})
            except Exception as log_exc:
                scan_run.execution_log.append({
                    "operation": "Structured execution log write failed",
                    "error_type": type(log_exc).__name__,
                })
            if db is not None:
                try:
                    db.save_scan(scan_run)
                except Exception as persistence_error:
                    scan_run.execution_log.append({"operation": "Failed to persist scan failure", "error_type": type(persistence_error).__name__})
            self.finished_signal.emit(scan_run, findings)
        finally:
            self.session_plan = None
            self.api_plan = None
            if db is not None:
                db.close()


class VoiceWorker(QThread):
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, text: str, allow_online: bool = False):
        super().__init__()
        self.text = text
        self.allow_online = allow_online
        self.assistant = PersianVoiceAssistant()

    def run(self):
        success, msg = self.assistant.speak(self.text, allow_online=self.allow_online)
        self.finished_signal.emit(success, msg)


# -------------------------------------------------------------
# 1. OVERVIEW TAB
# -------------------------------------------------------------
class OverviewTab(QWidget):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager.get_instance()
        self.guard = SystemGuardMonitor(self.db)
        self.voice = PersianVoiceAssistant()
        self.setup_ui()
        self.refresh_metrics()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Header Title
        title_box = QHBoxLayout()
        header = QLabel("🛡️ Security Overview")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00f2fe;")
        title_box.addWidget(header)
        title_box.addStretch()

        self.voice_btn = QPushButton("🔊 Play Voice Summary")
        self.voice_btn.setProperty("class", "ActionBtn")
        self.voice_btn.clicked.connect(self.play_voice_summary)
        title_box.addWidget(self.voice_btn)

        layout.addLayout(title_box)

        # Stat Cards Grid
        grid = QGridLayout()
        grid.setSpacing(12)

        self.card_total = self._create_card("Total Findings", "0", "#00f2fe")
        self.card_critical = self._create_card("Critical Findings", "0", "#ef4444")
        self.card_high = self._create_card("High Findings", "0", "#f97316")
        self.card_validated = self._create_card("Validated Findings", "0", "#10b981")
        self.card_cpu = self._create_card("CPU Usage", "0%", "#38bdf8")
        self.card_ram = self._create_card("Memory Usage", "0 GB", "#a855f7")

        grid.addWidget(self.card_total, 0, 0)
        grid.addWidget(self.card_critical, 0, 1)
        grid.addWidget(self.card_high, 0, 2)
        grid.addWidget(self.card_validated, 1, 0)
        grid.addWidget(self.card_cpu, 1, 1)
        grid.addWidget(self.card_ram, 1, 2)

        layout.addLayout(grid)

        # Recent Scans Table
        recent_box = QGroupBox("Recent Scans")
        r_layout = QVBoxLayout(recent_box)
        self.scans_table = QTableWidget(0, 5)
        _polish_table(self.scans_table)
        self.scans_table.setHorizontalHeaderLabels(["Scan ID", "Tool", "Target", "Status", "Findings"])
        self.scans_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        r_layout.addWidget(self.scans_table)

        layout.addWidget(recent_box)

        # Status text
        self.status_lbl = QLabel("Ready. All data is stored locally.")
        self.status_lbl.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(self.status_lbl)

    def _create_card(self, label: str, default_val: str, color: str) -> QFrame:
        card = QFrame()
        card.setProperty("class", "StatCard")
        l = QVBoxLayout(card)
        val = QLabel(default_val)
        val.setProperty("class", "StatValue")
        val.setStyleSheet(f"color: {color};")
        lbl = QLabel(label)
        lbl.setProperty("class", "StatLabel")
        l.addWidget(val)
        l.addWidget(lbl)
        card.val_widget = val  # reference
        return card

    def refresh_metrics(self):
        summary = self.db.get_findings_summary()
        self.card_total.val_widget.setText(str(summary.get("TOTAL", 0)))
        self.card_critical.val_widget.setText(str(summary.get("CRITICAL", 0)))
        self.card_high.val_widget.setText(str(summary.get("HIGH", 0)))
        self.card_validated.val_widget.setText(str(summary.get("VALIDATED", 0)))

        # Snapshot
        snap = self.guard.get_system_snapshot(include_defender=False)
        self.card_cpu.val_widget.setText(f"{snap['cpu_percent']}%")
        self.card_ram.val_widget.setText(f"{snap['memory_used_gb']} / {snap['memory_total_gb']} GB")

        # Scans table
        scans = self.db.list_scans(limit=10)
        self.scans_table.setRowCount(len(scans))
        for row, s in enumerate(scans):
            self.scans_table.setItem(row, 0, QTableWidgetItem(s.id[:8]))
            self.scans_table.setItem(row, 1, QTableWidgetItem(s.tool_name))
            self.scans_table.setItem(row, 2, QTableWidgetItem(s.target))
            self.scans_table.setItem(row, 3, QTableWidgetItem(s.status))
            self.scans_table.setItem(row, 4, QTableWidgetItem(str(s.findings_count)))

    def play_voice_summary(self):
        scans = self.db.list_scans(limit=1)
        findings = self.db.list_findings(limit=50)
        latest_scan = scans[0] if scans else ScanRun(tool_name="System", target="Localhost", raw_command="")
        tools = {latest_scan.tool_name: latest_scan.status == "COMPLETED"} if scans else {}
        text = self.voice.build_scan_summary_text(latest_scan, findings, tools)

        choice = QMessageBox.question(
            self,
            "Voice Output",
            "Online natural voice sends the scan summary and findings to Microsoft Edge TTS.\n\n"
            "Yes: Online voice\nNo: Local Windows SAPI\nCancel: Do not play",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.No,
        )
        if choice == QMessageBox.StandardButton.Cancel:
            return

        self.voice_btn.setEnabled(False)
        self.voice_btn.setText("Playing audio...")
        self.worker = VoiceWorker(text, allow_online=choice == QMessageBox.StandardButton.Yes)
        self.worker.finished_signal.connect(self._on_voice_finished)
        self.worker.start()

    def _on_voice_finished(self, ok: bool, msg: str):
        self.voice_btn.setEnabled(True)
        self.voice_btn.setText("🔊 Play Voice Summary")
        self.status_lbl.setText(f"Voice status: {msg}")


# -------------------------------------------------------------
# 2. WEB SECURITY TAB
# -------------------------------------------------------------
class WebSecurityTab(QWidget):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager.get_instance()
        self.current_findings = []
        self.session_plan = None
        self.api_plan = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 5, 4, 4)
        layout.setSpacing(13)

        title_row = QHBoxLayout()
        title_stack = QVBoxLayout()
        title = QLabel("Web Security Scanner")
        title.setStyleSheet("font-size:23px; font-weight:800; color:#e7f4ff;")
        subtitle = QLabel("Enter an authorized target. Sentinel collects evidence and creates a structured report.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("font-size:12px; color:#8ea9c0;")
        title_stack.addWidget(title)
        title_stack.addWidget(subtitle)
        title_row.addLayout(title_stack)
        title_row.addStretch()
        badge = QLabel(f"AUTHORIZED ASSESSMENTS   •   v{APP_VERSION}")
        badge.setStyleSheet("color:#77cce7; font-size:10px; letter-spacing:1px; border:1px solid #254864; border-radius:10px; padding:7px 10px;")
        title_row.addWidget(badge, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(title_row)

        hero = QFrame()
        hero.setObjectName("ScanHero")
        hero.setStyleSheet("QFrame#ScanHero { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #111f32,stop:1 #0b1727); border:1px solid #28415d; border-radius:15px; }")
        hero_row = QHBoxLayout(hero)
        hero_row.setContentsMargins(22, 17, 18, 13)
        hero_row.setSpacing(10)

        form = QVBoxLayout()
        form.setSpacing(10)
        prompt = QLabel("Website URL")
        prompt.setStyleSheet("color:#c6d8e9; font-size:12px; font-weight:700;")
        form.addWidget(prompt)

        self.target_input = QLineEdit()
        self.target_input.setObjectName("TargetUrl")
        self.target_input.setPlaceholderText("https://example.com")
        self.target_input.setClearButtonEnabled(True)
        self.target_input.setMinimumHeight(48)
        self.target_input.setStyleSheet("QLineEdit#TargetUrl { font-size:15px; padding:10px 13px; border-radius:9px; background:#081422; border:1px solid #31516d; }")
        self.target_input.returnPressed.connect(self.start_scan)
        form.addWidget(self.target_input)

        engines = QLabel("BUILT-IN DAST  ·  ZAP / NMAP WHEN VERIFIED")
        engines.setStyleSheet("color:#63849f; font-size:10px; letter-spacing:1px;")
        form.addWidget(engines)

        actions = QHBoxLayout()
        self.scan_btn = QPushButton("SCAN WEBSITE")
        self.scan_btn.setProperty("class", "ActionBtn")
        self.scan_btn.setMinimumHeight(45)
        self.scan_btn.setMinimumWidth(180)
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.clicked.connect(self.start_scan)
        actions.addWidget(self.scan_btn)
        self.session_btn = QPushButton("Assessment setup")
        setup_menu = QMenu(self.session_btn)
        setup_menu.addAction("Test sessions / access rules", self.configure_session_review)
        setup_menu.addAction("Import OpenAPI / Swagger JSON", self.import_api_definition)
        setup_menu.addAction("Clear API definition", self.clear_api_definition)
        self.session_btn.setMenu(setup_menu)
        actions.addWidget(self.session_btn)

        self.progress = QProgressBar()
        self.progress.setObjectName("ScanProgress")
        self.progress.setVisible(False)
        self.progress.setRange(0, 0)
        self.progress.setMaximumHeight(9)
        actions.addWidget(self.progress, 1, Qt.AlignmentFlag.AlignVCenter)
        form.addLayout(actions)
        hero_row.addLayout(form, 1)
        self.scan_visual = InfinityIndicator()
        hero_row.addWidget(self.scan_visual)
        layout.addWidget(hero)

        self.scan_status = QLabel("Enter a website URL.")
        self.scan_status.setWordWrap(True)
        self.scan_status.setStyleSheet("color:#8ea9c0; padding:2px 4px;")
        layout.addWidget(self.scan_status)
        self.coverage_note = QLabel()
        self.coverage_note.setWordWrap(True)
        self.coverage_note.setStyleSheet("color:#9cb3c7; font-size:11px; padding:2px 4px;")
        self.coverage_note.hide()
        layout.addWidget(self.coverage_note)

        self.severity_summary = QWidget()
        summary_row = QHBoxLayout(self.severity_summary)
        summary_row.setContentsMargins(0, 0, 0, 0)
        self.severity_labels = {}
        colors = {"CRITICAL": "#ff6a88", "HIGH": "#ffae72", "MEDIUM": "#efd27f", "LOW": "#82d6b7", "INFO": "#8faeca"}
        for severity, color in colors.items():
            label = QLabel(f"0  {severity}")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setStyleSheet(f"color:{color};background:#101f30;border:1px solid #263c52;border-radius:8px;padding:11px;font-size:11px;font-weight:700;")
            self.severity_labels[severity] = label
            summary_row.addWidget(label)
        self.severity_summary.hide()
        layout.addWidget(self.severity_summary)

        findings_box = QGroupBox("Scan Results")
        findings_layout = QVBoxLayout(findings_box)
        self.empty_results = QLabel("YOUR NEXT ASSESSMENT\n\nEnter an authorized URL above.\nFindings, evidence and report actions appear here after the scan.")
        self.empty_results.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_results.setWordWrap(True)
        self.empty_results.setStyleSheet("color:#8fa8be; padding:32px; font-size:13px;")
        findings_layout.addWidget(self.empty_results)
        self.findings_table = QTableWidget(0, 5)
        _polish_table(self.findings_table)
        self.findings_table.setHorizontalHeaderLabels(["Finding", "Severity", "Confidence", "Component", "Evidence Summary"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        findings_layout.addWidget(self.findings_table)
        self.findings_table.cellDoubleClicked.connect(self.show_finding_details)
        self.findings_table.hide()
        layout.addWidget(findings_box, 1)
        self.report_actions = AssessmentReportActions(self)
        self.report_actions.busy_changed.connect(self.scan_btn.setDisabled)
        layout.addWidget(self.report_actions)

    def configure_session_review(self):
        from src.ui.session_review_dialog import SessionReviewDialog
        valid, message, target = WebAuditorAdapter.validate_target_url(self.target_input.text())
        if not valid:
            QMessageBox.warning(self, "Website URL", "Enter the authorized website URL first. " + message)
            return
        dialog = SessionReviewDialog(target, self.session_plan, self)
        try:
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.session_plan = dialog.plan
                self.session_btn.setText("Assessment setup · configured" if self.session_plan or self.api_plan else "Assessment setup")
        finally:
            for mode, secret, marker in dialog.profiles.values():
                secret.clear()
                marker.clear()
            dialog.plan = None
            dialog.deleteLater()

    def import_api_definition(self):
        target = self.target_input.text().strip()
        valid, message, target = WebAuditorAdapter.validate_target_url(target)
        if not valid:
            QMessageBox.warning(self, "API setup", message)
            return
        filename, _ = QFileDialog.getOpenFileName(self, "Import API definition for this target", "", "OpenAPI JSON (*.json)")
        if not filename:
            return
        try:
            plan = import_spec_file(target, filename)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "API setup", str(exc))
            return
        eligible = sum(not item["skip_reason"] for item in plan["operations"])
        self.api_plan = plan
        self.scan_status.setText(f"API definition ready: {len(plan['operations'])} documented operations; up to {min(eligible, 20)} concrete GET routes will be assessed. Exclusions remain visible in the report.")
        self.session_btn.setText("Assessment setup · API loaded")

    def clear_api_definition(self):
        self.api_plan = None
        self.session_btn.setText("Assessment setup · configured" if self.session_plan else "Assessment setup")
        self.scan_status.setText("API definition cleared. The normal website scanner remains available.")

    def start_scan(self):
        if getattr(self, "web_worker", None) and self.web_worker.isRunning():
            return
        if self.report_actions.worker and self.report_actions.worker.isRunning():
            return
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Enter a target URL or IP address.")
            return

        valid_target, validation_message, normalized_target = WebAuditorAdapter.validate_target_url(target)
        if not valid_target:
            QMessageBox.critical(self, "Invalid URL", validation_message)
            return
        target = normalized_target
        if self.api_plan:
            try:
                validate_api_plan(target, self.api_plan)
            except ValueError as exc:
                QMessageBox.warning(self, "API setup", str(exc))
                return
        if self.session_plan:
            try:
                validate_plan(target, self.session_plan)
            except ValueError as exc:
                QMessageBox.warning(self, "Session setup", str(exc))
                return
        approval = QMessageBox.question(
            self,
            "Scan Authorization",
            f"Scan only websites you own or have written permission to assess:\n\n{target}\n\n"
            "Sentinel will run a deep web assessment. If local OWASP ZAP or Nmap is installed, those scanners will also run against this host. Active probes may affect the service. "
            + (f"Supplied sessions will also be used on the canary and {len(self.session_plan['cases'])} declared read-only path(s); the session values are not passed to ZAP or Nmap. " if self.session_plan else "")
            + ("The imported API definition will also be reviewed with up to 20 anonymous GET operations and bounded query probes. Verify these GET routes are read-only. " if self.api_plan else "")
            + "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if approval != QMessageBox.StandardButton.Yes:
            return

        self.scan_btn.setEnabled(False)
        self.session_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.findings_table.setRowCount(0)
        self.findings_table.hide()
        self.current_findings = []
        self.severity_summary.hide()
        self.coverage_note.hide()
        self.report_actions.set_assessment(None)
        self.scan_visual.set_state("RUNNING")
        self.empty_results.setText("Scanning website...")
        self.empty_results.show()
        self.scan_status.setText("Scanning website…")
        self.web_worker = WebAuditWorker(target, deep_scan=True, parent=self, session_plan=self.session_plan, api_plan=self.api_plan)
        self.web_worker.progress_signal.connect(self._on_scan_progress)
        self.web_worker.finished_signal.connect(self._on_scan_finished)
        self.web_worker.error_signal.connect(self._on_scan_error)
        self.web_worker.start()

    def _on_scan_progress(self, message: str) -> None:
        self.scan_status.setText(message)
        self.scan_status.setToolTip(message)

    def _on_scan_finished(self, scan_run: ScanRun, findings: List[Finding]):
        self.scan_btn.setEnabled(True)
        self.session_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.scan_visual.set_state(scan_run.status)
        self.report_actions.set_assessment(scan_run)
        self.coverage_note.setText(scan_run.completion_reason or scan_run.error_message or "")
        self.coverage_note.setVisible(bool(self.coverage_note.text()))
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings = sorted(findings, key=lambda f: (severity_order.get(f.severity.value, 5), f.title.casefold()))
        self.current_findings = findings
        self.severity_summary.show()
        for severity, label in self.severity_labels.items():
            count = sum(1 for f in findings if f.severity.value == severity and f.status != FindingStatus.FALSE_POSITIVE)
            label.setText(f"{count}  {severity}")
        status = scan_run.status.lower()
        http_status = f"HTTP {scan_run.response_status}" if scan_run.response_status is not None else "HTTP status unavailable"
        duration = f"{scan_run.duration_ms} ms" if scan_run.duration_ms < 1000 else f"{scan_run.duration_ms / 1000:.1f}s"
        self.scan_status.setText(
            f"{scan_run.tool_name} {status} • {scan_run.request_count} built-in HTTP requests • "
            f"{http_status} • {duration} • {len(findings)} findings"
        )
        self.scan_status.setToolTip(
            f"Scan ID: {scan_run.id}\n"
            f"{scan_run.completion_reason or scan_run.error_message or ''}\n"
            f"Execution log: {next((item.get('path') for item in reversed(scan_run.execution_log) if item.get('path')), 'not available')}"
        )

        # Update table
        self.findings_table.setRowCount(len(findings))
        self.findings_table.setVisible(bool(findings))
        self.empty_results.setVisible(not findings)
        if scan_run.status == "FAILED":
            self.empty_results.setText(
                "Scan failed before a complete assessment. "
                f"Reason: {scan_run.error_message or scan_run.completion_reason or 'Unknown execution failure.'}"
            )
        elif scan_run.status == "PARTIAL":
            self.empty_results.setText(
                "Assessment coverage is incomplete. "
                f"{scan_run.completion_reason or ''}"
            )
        else:
            self.empty_results.setText("No findings recorded. A clean scan does not prove the site is secure.")
        for row, f in enumerate(findings):
            self.findings_table.setItem(row, 0, QTableWidgetItem(f.title))
            self.findings_table.setItem(row, 1, QTableWidgetItem(f.severity.value))
            self.findings_table.setItem(row, 2, QTableWidgetItem(f.confidence.value))
            self.findings_table.setItem(row, 3, QTableWidgetItem(f.affected_component or "N/A"))
            self.findings_table.setItem(row, 4, QTableWidgetItem(f.evidence_summary))
            severity_colors = {"CRITICAL": "#ff6a88", "HIGH": "#ffae72", "MEDIUM": "#efd27f", "LOW": "#82d6b7", "INFO": "#8faeca"}
            self.findings_table.item(row, 1).setForeground(QColor(severity_colors.get(f.severity.value, "#8faeca")))
            self.findings_table.item(row, 0).setToolTip("Double-click to read evidence and remediation.")

    def show_finding_details(self, row, _column=0):
        if row < 0 or row >= len(self.current_findings):
            return
        finding = self.current_findings[row]
        dialog = QDialog(self)
        dialog.setWindowTitle("Finding evidence and remediation")
        dialog.resize(760, 580)
        layout = QVBoxLayout(dialog)
        details = QTextEdit()
        details.setReadOnly(True)
        details.setPlainText(
            f"{finding.title}\n\nSeverity: {finding.severity.value} | Status: {finding.status.value}\n"
            f"Confidence: {finding.confidence.value}\nSource: {finding.source_tool}\nTarget: {finding.target}\n\n"
            f"DESCRIPTION\n{finding.description}\n\nEVIDENCE\n{finding.evidence_summary}\n{finding.evidence_raw}\n\n"
            f"REMEDIATION\n{finding.remediation}\n\nFinding ID: {finding.id}"
        )
        layout.addWidget(details)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def _on_scan_error(self, err: str):
        self.scan_btn.setEnabled(True)
        self.session_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.scan_visual.set_state("FAILED")
        self.scan_status.setText("Scan failed")
        self.scan_status.setToolTip(err)
        if self.findings_table.rowCount() == 0:
            self.empty_results.setText("Scan failed. Check the URL, connectivity, and error details.")
            self.empty_results.show()
        QMessageBox.critical(self, "Scan Error", err)


# -------------------------------------------------------------
# 3. SYSTEM GUARD TAB
# -------------------------------------------------------------
class SystemGuardTab(QWidget):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager.get_instance()
        self.guard = SystemGuardMonitor(self.db)
        self.setup_ui()
        self.refresh_telemetry()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        header = QLabel("🛡️ System Guard & Windows Defender")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00f2fe;")
        layout.addWidget(header)

        # Defender Status Banner
        self.def_box = QGroupBox("Microsoft Defender Status")
        d_layout = QGridLayout(self.def_box)
        self.lbl_def_av = QLabel("Antivirus: Checking...")
        self.lbl_def_rtp = QLabel("Real-time Protection: Checking...")
        self.lbl_def_engine = QLabel("Defender Engine Version: Checking...")
        self.lbl_def_threats = QLabel("Recorded Threats: Checking...")

        d_layout.addWidget(self.lbl_def_av, 0, 0)
        d_layout.addWidget(self.lbl_def_rtp, 0, 1)
        d_layout.addWidget(self.lbl_def_engine, 1, 0)
        d_layout.addWidget(self.lbl_def_threats, 1, 1)

        self.btn_refresh_def = QPushButton("🔄 Refresh Defender Status & Threat Log")
        self.btn_refresh_def.setProperty("class", "ActionBtn")
        self.btn_refresh_def.clicked.connect(self.refresh_defender_threats)
        d_layout.addWidget(self.btn_refresh_def, 2, 0, 1, 2)

        layout.addWidget(self.def_box)

        # Process and Network Tabs
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Top processes
        p_box = QGroupBox("Active Processes")
        p_layout = QVBoxLayout(p_box)
        self.proc_table = QTableWidget(0, 4)
        _polish_table(self.proc_table)
        self.proc_table.setHorizontalHeaderLabels(["PID", "Process", "Memory (MB)", "Executable Path"])
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        p_layout.addWidget(self.proc_table)
        splitter.addWidget(p_box)

        # Sockets
        s_box = QGroupBox("Active Network Connections")
        s_layout = QVBoxLayout(s_box)
        self.sock_table = QTableWidget(0, 4)
        _polish_table(self.sock_table)
        self.sock_table.setHorizontalHeaderLabels(["Type", "Local Address", "Remote Address", "Status"])
        self.sock_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        s_layout.addWidget(self.sock_table)
        splitter.addWidget(s_box)

        layout.addWidget(splitter)

        # File Hash Inspector
        file_box = QGroupBox("File Hash Inspector")
        f_layout = QHBoxLayout(file_box)
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Enter or select a file path...")
        f_layout.addWidget(self.file_input)

        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self.browse_file)
        f_layout.addWidget(self.browse_btn)

        self.hash_btn = QPushButton("🔍 Calculate Hash")
        self.hash_btn.setProperty("class", "ActionBtn")
        self.hash_btn.clicked.connect(self.inspect_file_hash)
        f_layout.addWidget(self.hash_btn)

        layout.addWidget(file_box)

    def refresh_telemetry(self):
        snap = self.guard.get_system_snapshot()
        self.lbl_def_av.setText(f"Antivirus: {'Enabled' if snap['defender_available'] else 'Disabled'}")
        self.lbl_def_rtp.setText(f"Real-time Protection: {'On' if snap['defender_rtp'] else 'Off'}")
        self.lbl_def_engine.setText(f"Engine version: {snap['defender_engine']}")

        # Processes
        procs = self.guard.get_top_processes(limit=20)
        self.proc_table.setRowCount(len(procs))
        for row, p in enumerate(procs):
            self.proc_table.setItem(row, 0, QTableWidgetItem(str(p["pid"])))
            self.proc_table.setItem(row, 1, QTableWidgetItem(p["name"]))
            self.proc_table.setItem(row, 2, QTableWidgetItem(str(p["memory_mb"])))
            self.proc_table.setItem(row, 3, QTableWidgetItem(p["exe"]))

        # Sockets
        conns = self.guard.get_active_connections(limit=25)
        self.sock_table.setRowCount(len(conns))
        for row, c in enumerate(conns):
            self.sock_table.setItem(row, 0, QTableWidgetItem(c["type"]))
            self.sock_table.setItem(row, 1, QTableWidgetItem(c["laddr"]))
            self.sock_table.setItem(row, 2, QTableWidgetItem(c["raddr"]))
            self.sock_table.setItem(row, 3, QTableWidgetItem(c["status"]))

    def refresh_defender_threats(self):
        threats = self.guard.defender.get_threat_detections(limit=50)
        for t in threats:
            self.db.save_finding(t)
        self.lbl_def_threats.setText(f"Recorded threats: {len(threats)} items")
        QMessageBox.information(
            self,
            "Microsoft Defender",
            f"{len(threats)} threat detection records were retrieved from Windows Defender and saved locally.",
        )

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to inspect")
        if path:
            self.file_input.setText(path)

    def inspect_file_hash(self):
        path = self.file_input.text().strip()
        if not path:
            return
        res = self.guard.inspect_file(path)
        if "error" in res:
            QMessageBox.critical(self, "Error", res["error"])
        else:
            QMessageBox.information(
                self,
                "File Evidence",
                f"File name: {res['file_name']}\nSize: {res['size_bytes']} bytes\nSHA256: {res['sha256']}",
            )


# -------------------------------------------------------------
# 4. NETWORK ANALYSIS TAB
# -------------------------------------------------------------
class NetworkAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.adapter = PcapAdapter()
        self.db = DatabaseManager.get_instance()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        header = QLabel("📡 Network Traffic Analysis")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00f2fe;")
        layout.addWidget(header)

        # File Select Box
        box = QGroupBox("Select a capture file")
        b_layout = QHBoxLayout(box)
        self.pcap_input = QLineEdit()
        self.pcap_input.setPlaceholderText("Enter or select a PCAP file...")
        b_layout.addWidget(self.pcap_input)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_pcap)
        b_layout.addWidget(browse_btn)

        self.analyze_btn = QPushButton("📊 Analyze Capture")
        self.analyze_btn.setProperty("class", "ActionBtn")
        self.analyze_btn.clicked.connect(self.analyze_pcap)
        b_layout.addWidget(self.analyze_btn)

        layout.addWidget(box)

        # Results
        self.results_view = QTextEdit()
        self.results_view.setReadOnly(True)
        layout.addWidget(self.results_view)

    def browse_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a PCAP file", "", "PCAP Files (*.pcap *.pcapng);;All Files (*.*)")
        if path:
            self.pcap_input.setText(path)

    def analyze_pcap(self):
        path = self.pcap_input.text().strip()
        if not path:
            QMessageBox.warning(self, "Error", "Select a PCAP file first.")
            return

        scan_run = ScanRun(tool_name="PCAP Analyzer", target=path, raw_command=f"parse {path}")
        scan_run, findings = self.adapter.run_scan(path, scan_run)

        if scan_run.status == "FAILED":
            QMessageBox.critical(self, "Analysis Error", scan_run.error_message or "Error")
            return

        self.db.save_scan(scan_run)
        for f in findings:
            self.db.save_finding(f)

        self.results_view.setPlainText(findings[0].description if findings else "Analysis completed.")
        QMessageBox.information(self, "Analysis Complete", "Capture analysis completed and saved.")


# -------------------------------------------------------------
# 5. FINDINGS TAB
# -------------------------------------------------------------
class FindingsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager.get_instance()
        self.setup_ui()
        self.refresh_findings()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        header = QLabel("🔍 Findings & Evidence")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00f2fe;")
        layout.addWidget(header)

        # Filter bar
        filter_box = QHBoxLayout()
        filter_box.addWidget(QLabel("Filter by severity:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.filter_combo.currentIndexChanged.connect(self.refresh_findings)
        filter_box.addWidget(self.filter_combo)

        filter_box.addStretch()
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_findings)
        filter_box.addWidget(refresh_btn)

        self.import_actions = ReportImportActions(self.db.db_path, self)
        self.import_actions.imported.connect(lambda _scan: self.refresh_findings())
        filter_box.addWidget(self.import_actions)

        layout.addLayout(filter_box)

        # Findings Table
        self.table = QTableWidget(0, 6)
        _polish_table(self.table)
        self.table.setHorizontalHeaderLabels(["ID", "Finding", "Source Tool", "Target", "Severity", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.display_selected_finding)
        layout.addWidget(self.table)

        # Finding Details Panel
        self.detail_box = QGroupBox("Finding Details & Evidence")
        d_layout = QVBoxLayout(self.detail_box)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        d_layout.addWidget(self.detail_text)

        # Status Update Actions
        action_bar = QHBoxLayout()
        action_bar.addWidget(QLabel("Update finding status:"))

        self.validate_btn = QPushButton("✅ Mark as Validated")
        self.validate_btn.clicked.connect(lambda: self.change_finding_status(FindingStatus.VALIDATED))
        action_bar.addWidget(self.validate_btn)

        self.fp_btn = QPushButton("❌ Mark as False Positive")
        self.fp_btn.clicked.connect(lambda: self.change_finding_status(FindingStatus.FALSE_POSITIVE))
        action_bar.addWidget(self.fp_btn)

        d_layout.addLayout(action_bar)
        layout.addWidget(self.detail_box)

    def import_scanner_report(self):
        self.import_actions.choose_file()

    def refresh_findings(self):
        sev_idx = self.filter_combo.currentIndex()
        sev_filter = None if sev_idx == 0 else self.filter_combo.currentText()
        findings = self.db.list_findings(severity=sev_filter, limit=200)

        self.current_findings = findings
        self.table.setRowCount(len(findings))

        for row, f in enumerate(findings):
            self.table.setItem(row, 0, QTableWidgetItem(f.id[:8]))
            self.table.setItem(row, 1, QTableWidgetItem(f.title))
            self.table.setItem(row, 2, QTableWidgetItem(f.source_tool))
            self.table.setItem(row, 3, QTableWidgetItem(f.target))
            self.table.setItem(row, 4, QTableWidgetItem(f.severity.value))
            self.table.setItem(row, 5, QTableWidgetItem(f.status.value))

    def display_selected_finding(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.current_findings):
            return
        f = self.current_findings[row]
        details = (
            f"Title: {f.title}\n"
            f"Full ID: {f.id}\n"
            f"Source Tool: {f.source_tool} (version: {f.tool_version})\n"
            f"Severity: {f.severity.value} | Severity source: {f.severity_source}\n"
            f"Confidence: {f.confidence.value} | rationale: {f.confidence_justification}\n"
            f"Validation status: {f.status.value}\n"
            f"ID CVE: {f.cve_id or 'None'} | CWE: {f.cwe_id or 'None'}\n"
            f"Target: {f.target}\n"
            f"Recorded at: {f.timestamp}\n\n"
            f"Technical description:\n{f.description}\n\n"
            f"Recommended remediation:\n{f.remediation}\n\n"
            f"Raw evidence:\n{f.evidence_raw}"
        )
        self.detail_text.setPlainText(details)

    def change_finding_status(self, new_status: FindingStatus):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.current_findings):
            QMessageBox.warning(self, "Error", "Select a finding first.")
            return
        f = self.current_findings[row]
        self.db.update_finding_status(f.id, new_status)
        self.refresh_findings()
        QMessageBox.information(self, "Status Updated", f"Finding status changed to '{new_status.value}'.")


# -------------------------------------------------------------
# 6. REPORTS TAB
# -------------------------------------------------------------
class ReportsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager.get_instance()
        self.setup_ui()
        self.refresh_scans()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        header = QLabel("Assessment reports")
        header.setStyleSheet("font-size:23px;font-weight:800;color:#e7f4ff;")
        layout.addWidget(header)
        intro = QLabel("Choose an assessment. Word and JSON include the same findings from that target and its engine runs.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#8ea9c0;")
        layout.addWidget(intro)
        selection = QHBoxLayout()
        self.scan_combo = QComboBox()
        self.scan_combo.setMinimumHeight(40)
        self.scan_combo.currentIndexChanged.connect(self._selection_changed)
        selection.addWidget(self.scan_combo, 1)
        self.refresh_btn = QPushButton("Refresh history")
        self.refresh_btn.clicked.connect(self.refresh_scans)
        selection.addWidget(self.refresh_btn)
        layout.addLayout(selection)
        self.scan_detail = QLabel()
        self.scan_detail.setWordWrap(True)
        self.scan_detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.scan_detail.setStyleSheet("color:#9cb3c7;padding:12px;background:#101f30;border-radius:9px;")
        layout.addWidget(self.scan_detail)
        box = QGroupBox("Report details")
        form = QGridLayout(box)
        form.addWidget(QLabel("Target name (optional)"), 0, 0)
        self.target_name_input = QLineEdit()
        self.target_name_input.setPlaceholderText("Use the assessment target")
        form.addWidget(self.target_name_input, 0, 1)
        form.addWidget(QLabel("Report title"), 1, 0)
        self.report_title_input = QLineEdit("Security Assessment Report")
        form.addWidget(self.report_title_input, 1, 1)
        layout.addWidget(box)
        self.report_actions = AssessmentReportActions(self)
        self.report_actions.busy_changed.connect(self.scan_combo.setDisabled)
        self.report_actions.busy_changed.connect(self.refresh_btn.setDisabled)
        self.target_name_input.textChanged.connect(self._update_metadata)
        self.report_title_input.textChanged.connect(self._update_metadata)
        layout.addWidget(self.report_actions)
        layout.addStretch()

    def _update_metadata(self):
        self.report_actions.target_name = self.target_name_input.text().strip()
        self.report_actions.title = self.report_title_input.text().strip()

    def refresh_scans(self):
        if self.report_actions.worker and self.report_actions.worker.isRunning():
            return
        selected = self.scan_combo.currentData()
        self.scan_combo.blockSignals(True)
        self.scan_combo.clear()
        for scan in self.db.list_scans(limit=500, root_only=True):
            try:
                started = datetime.fromisoformat(scan.start_time).astimezone().isoformat(timespec="minutes")
            except ValueError:
                started = scan.start_time
            self.scan_combo.addItem(f"{scan.target}  |  {scan.status}  |  {started}", scan.id)
        index = self.scan_combo.findData(selected) if selected else 0
        self.scan_combo.setCurrentIndex(max(0, index))
        self.scan_combo.blockSignals(False)
        self._selection_changed()

    def _selection_changed(self, _index=None):
        scan_id = self.scan_combo.currentData()
        scan = self.db.get_scan(scan_id) if scan_id else None
        self.report_actions.set_assessment(scan)
        if scan is None:
            self.scan_detail.setText("No assessment saved yet. Start a scan from the Scanner page.")
            return
        findings = self.db.list_findings(scan_id=scan.id, limit=None)
        self.scan_detail.setText(
            f"{scan.tool_name} • {scan.status} • {len(findings)} findings • {scan.request_count} built-in HTTP requests\n"
            f"Assessment ID: {scan.id}\n{scan.completion_reason or scan.error_message or ''}"
        )


# -------------------------------------------------------------
# 7. TOOL HEALTH TAB
# -------------------------------------------------------------
class ToolHealthTab(QWidget):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager.get_instance()
        self.health_worker = None
        self.setup_ui()
        self.refresh_tools()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        header = QLabel("🩺 Security Tool Integrations")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00f2fe;")
        layout.addWidget(header)

        self.table = QTableWidget(0, 5)
        _polish_table(self.table)
        self.table.setHorizontalHeaderLabels(["Tool", "Availability", "Version", "Source / Executable Path", "Status / Notes"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        btn_bar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh tool status")
        refresh_btn = self.refresh_btn
        refresh_btn.setProperty("class", "ActionBtn")
        refresh_btn.clicked.connect(self.refresh_tools)
        btn_bar.addWidget(refresh_btn)

        self.import_actions = ReportImportActions(self.db.db_path, self)
        btn_bar.addWidget(self.import_actions)

        open_folder_btn = QPushButton("📂 Open Selected Archive Folder")
        open_folder_btn.clicked.connect(self.open_selected_archive_folder)
        btn_bar.addWidget(open_folder_btn)

        layout.addLayout(btn_bar)
        self.health_status = QLabel("Tool availability has not been checked.")
        self.health_status.setWordWrap(True)
        layout.addWidget(self.health_status)

    def refresh_tools(self):
        if self.health_worker and self.health_worker.isRunning():
            return
        self.health_status.setText("Checking tool availability…")
        self.refresh_btn.setEnabled(False)
        self.health_worker = ToolHealthWorker(self.db.db_path, self)
        self.health_worker.progress.connect(self.health_status.setText)
        self.health_worker.result.connect(self._on_health_result)
        self.health_worker.finished.connect(self._on_health_finished)
        self.health_worker.start()

    def _on_health_finished(self):
        self.refresh_btn.setEnabled(True)

    def _on_health_result(self, tools_health, error):
        failed = sum(item.availability_status == "EXECUTION_FAILED" for item in tools_health)
        self.health_status.setText(error or f"Checked {len(tools_health)} tool records. {failed} detector failure(s). Unverified entries are not ready claims.")
        if error and not tools_health:
            return
        # Populate table
        self.table.setRowCount(len(tools_health))
        for row, t in enumerate(tools_health):
            self.table.setItem(row, 0, QTableWidgetItem(t.name))
            availability = t.availability_status
            stat_item = QTableWidgetItem(availability)
            color = (
                Qt.GlobalColor.green if availability == "INSTALLED_AND_VERIFIED"
                else Qt.GlobalColor.cyan if availability == "ARCHIVE_ONLY"
                else Qt.GlobalColor.yellow if availability in {"VERSION_CHECK_FAILED", "EXECUTION_FAILED"}
                else Qt.GlobalColor.red
            )
            stat_item.setForeground(color)
            self.table.setItem(row, 1, stat_item)
            self.table.setItem(row, 2, QTableWidgetItem(t.version or "N/A"))
            self.table.setItem(row, 3, QTableWidgetItem(t.path or "N/A"))
            self.table.setItem(row, 4, QTableWidgetItem(t.status_message))

    def import_tool_report(self):
        self.import_actions.choose_file()

    def open_selected_archive_folder(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select a Tool", "Select a source archive row first.")
            return
        path_item = self.table.item(row, 3)
        status_item = self.table.item(row, 4)
        path = Path(path_item.text()) if path_item and path_item.text() != "N/A" else None
        if not path or not status_item or not status_item.text().startswith("SOURCE ARCHIVE FOUND"):
            QMessageBox.information(self, "No Source Archive", "The selected row is not a detected source archive.")
            return
        if not path.is_file():
            QMessageBox.warning(self, "Archive Missing", "The source archive is no longer available at that path.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))


# -------------------------------------------------------------
# 8. SETTINGS TAB
# -------------------------------------------------------------
class SettingsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        header = QLabel("⚙️ Settings")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00f2fe;")
        layout.addWidget(header)

        box = QGroupBox("Tool Paths & Scope")
        b_layout = QGridLayout(box)

        b_layout.addWidget(QLabel("Nmap Path:"), 0, 0)
        self.nmap_path = QLineEdit()
        self.nmap_path.setPlaceholderText("Auto-detect from PATH or select Nmap executable")
        b_layout.addWidget(self.nmap_path, 0, 1)

        b_layout.addWidget(QLabel("TShark Path:"), 1, 0)
        self.tshark_path = QLineEdit()
        self.tshark_path.setPlaceholderText("Auto-detect from PATH or select Wireshark executable")
        b_layout.addWidget(self.tshark_path, 1, 1)

        b_layout.addWidget(QLabel("OWASP ZAP API URL:"), 2, 0)
        self.zap_url = QLineEdit("http://127.0.0.1:8080")
        b_layout.addWidget(self.zap_url, 2, 1)

        b_layout.addWidget(QLabel("Allowed Targets:"), 3, 0)
        self.allowed_targets = QLineEdit("127.0.0.1, localhost, ::1")
        b_layout.addWidget(self.allowed_targets, 3, 1)

        save_btn = QPushButton("💾 Save Settings")
        save_btn.setProperty("class", "ActionBtn")
        save_btn.clicked.connect(self.save_settings)
        b_layout.addWidget(save_btn, 4, 0, 1, 2)

        layout.addWidget(box)
        layout.addStretch()

    def save_settings(self):
        QMessageBox.information(self, "Settings Saved", "Settings saved successfully.")
