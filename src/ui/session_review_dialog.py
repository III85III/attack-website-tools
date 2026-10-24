"""Optional per-assessment session setup; values are never written to settings."""
from copy import deepcopy

from PyQt6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                            QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton,
                            QTableWidget, QTableWidgetItem, QVBoxLayout)
from src.adapters.session_review import MAX_CASES, validate_plan


class SessionReviewDialog(QDialog):
    def __init__(self, target, plan=None, parent=None):
        super().__init__(parent)
        self.target = target
        self.plan = deepcopy(plan)
        self.setWindowTitle("Session and access review")
        self.resize(1040, 760)
        layout = QVBoxLayout(self)
        help_text = QLabel(
            "Use your authorized test sessions. Paste a Cookie header value or Bearer token, not a password. "
            "These values stay in memory until you clear setup or exit. Remote sessions require HTTPS.\n"
            "Choose an account page and distinct non-secret text identifying each signed-in account. "
            "Only the exact read-only paths below will be requested; no forms or login attempts are submitted."
        )
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
        form = QFormLayout()
        self.canary = QLineEdit()
        self.canary.setPlaceholderText("/account — a read-only page identifying the signed-in account")
        form.addRow("Session verification path", self.canary)
        self.profiles = {}
        for key, label in (("primary", "Primary test account"), ("secondary", "Second test account (optional)")):
            row = QHBoxLayout()
            mode = QComboBox()
            mode.addItems(["Cookie", "Bearer token"])
            secret = QLineEdit()
            secret.setEchoMode(QLineEdit.EchoMode.Password)
            secret.setPlaceholderText("Cookie header value or token only")
            marker = QLineEdit()
            marker.setPlaceholderText("Distinct account text, 6–200 characters")
            row.addWidget(mode)
            row.addWidget(secret, 2)
            row.addWidget(marker, 2)
            self.profiles[key] = (mode, secret, marker)
            form.addRow(label, row)
        layout.addLayout(form)
        label = QLabel(
            "For each path, give unique non-secret text that proves the expected protected content is present. "
            "Tick an identity only when it SHOULD have access. Forbidden text is an optional read-only business-rule assertion."
        )
        label.setWordWrap(True)
        layout.addWidget(label)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Read-only path / API URL", "Protected content marker", "Allow anonymous", "Allow second", "Forbidden text (primary)"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 245)
        self.table.setColumnWidth(1, 225)
        self.table.setColumnWidth(2, 125)
        self.table.setColumnWidth(3, 145)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        add = QPushButton("Add path")
        add.clicked.connect(lambda: self.add_case())
        remove = QPushButton("Remove selected path")
        remove.clicked.connect(lambda: self.table.removeRow(self.table.currentRow()) if self.table.currentRow() >= 0 else None)
        clear = QPushButton("Clear session setup")
        clear.clicked.connect(self.clear_setup)
        row.addWidget(add)
        row.addWidget(remove)
        row.addStretch()
        row.addWidget(clear)
        layout.addLayout(row)
        self.read_only = QCheckBox("I confirm these paths and accounts are authorized and all listed GET requests are read-only.")
        layout.addWidget(self.read_only)
        note = QLabel("This checks supplied sessions, declared access rules and content assertions. Payment flows, MFA, password reset and unlisted business workflows require separate scenarios and manual review.")
        note.setWordWrap(True)
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Use for this app session")
        buttons.accepted.connect(self.apply_setup)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        if plan:
            self.canary.setText(plan.get("canary_path", ""))
            self.read_only.setChecked(plan.get("read_only_confirmed") is True)
            for key, controls in self.profiles.items():
                profile = plan.get(key) or {}
                controls[0].setCurrentIndex(1 if profile.get("mode") == "bearer" else 0)
                controls[1].setText(profile.get("secret", ""))
                controls[2].setText(profile.get("marker", ""))
            for case in plan.get("cases", []):
                self.add_case(case)
        else:
            self.add_case()

    def add_case(self, case=None):
        if self.table.rowCount() >= MAX_CASES:
            return
        case = case or {}
        row = self.table.rowCount()
        self.table.insertRow(row)
        for column, key in ((0, "path"), (1, "marker"), (4, "forbidden")):
            self.table.setItem(row, column, QTableWidgetItem(case.get(key, "")))
        for column, key in ((2, "anonymous_allowed"), (3, "secondary_allowed")):
            check = QCheckBox()
            check.setChecked(case.get(key, False))
            self.table.setCellWidget(row, column, check)

    def clear_setup(self):
        self.plan = None
        for mode, secret, marker in self.profiles.values():
            secret.clear()
            marker.clear()
        self.accept()

    def apply_setup(self):
        profiles = {}
        for key, (mode, secret, marker) in self.profiles.items():
            profiles[key] = {"mode": "bearer" if mode.currentIndex() else "cookie", "secret": secret.text(), "marker": marker.text()}
        cases = []
        for row in range(self.table.rowCount()):
            case = {key: self.table.item(row, column).text() if self.table.item(row, column) else ""
                    for column, key in ((0, "path"), (1, "marker"), (4, "forbidden"))}
            for column, key in ((2, "anonymous_allowed"), (3, "secondary_allowed")):
                case[key] = self.table.cellWidget(row, column).isChecked()
            cases.append(case)
        plan = {"primary": profiles["primary"], "secondary": profiles["secondary"] if profiles["secondary"]["secret"] else None,
                "canary_path": self.canary.text(), "cases": cases, "read_only_confirmed": self.read_only.isChecked()}
        try:
            validate_plan(self.target, plan)
        except ValueError as exc:
            QMessageBox.warning(self, "Session setup", str(exc))
            return
        self.plan = plan
        self.accept()
