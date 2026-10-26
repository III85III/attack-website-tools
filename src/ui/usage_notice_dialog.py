from PyQt6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QMessageBox, QTextEdit, QVBoxLayout
from src.core.config import APP_VERSION, DATA_DIR
from src.core.usage_notice import NOTICE_TEXT, notice_accepted, save_acknowledgement
from src.ui.theme import DARK_TACTICAL_THEME
from src.ui.hud import create_obsidian_icon


class UsageNoticeDialog(QDialog):
    def __init__(self, parent=None, review_only=False):
        super().__init__(parent)
        self.setWindowTitle("OBSIDIAN — Responsible Use")
        self.setWindowIcon(create_obsidian_icon())
        self.setStyleSheet(DARK_TACTICAL_THEME)
        self.resize(730, 650)
        layout = QVBoxLayout(self)
        title = QLabel("Authorized use and responsibility")
        title.setStyleSheet("font-size:20px; font-weight:700; color:#63d8f2;")
        layout.addWidget(title)
        self.notice = QTextEdit()
        self.notice.setReadOnly(True)
        self.notice.setPlainText(NOTICE_TEXT)
        layout.addWidget(self.notice)
        self.acknowledge = QCheckBox("I have read this notice and understand my responsibility for authorized use.")
        layout.addWidget(self.acknowledge)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.continue_btn = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.continue_btn.setText("Acknowledge and continue")
        self.continue_btn.setEnabled(False)
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Exit")
        self.acknowledge.toggled.connect(self.continue_btn.setEnabled)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        if review_only:
            self.acknowledge.hide()
            self.continue_btn.hide()
            self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Close")

    def accept(self):
        if self.acknowledge.isChecked():
            super().accept()


def ensure_usage_notice(parent=None, path=None) -> bool:
    path = path if path is not None else DATA_DIR / "usage_notice_acknowledgement.json"
    if notice_accepted(path):
        return True
    dialog = UsageNoticeDialog(parent)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return False
    try:
        save_acknowledgement(path, APP_VERSION)
    except OSError:
        QMessageBox.warning(parent, "Acknowledgement not saved",
                            "You can continue this session. The notice will appear again next time because its local acknowledgement could not be saved.")
    return True
