"""Main window with a scan-first landing page and lazy-loaded workspace tabs."""
from __future__ import annotations

from PyQt6.QtCore import QThread, Qt
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from src.ui.hud import create_sentinel_icon
from src.ui.theme import DARK_TACTICAL_THEME
from src.core.config import APP_VERSION


class MainWindow(QMainWindow):
    """Desktop entry point; expensive tools initialize only when requested."""

    TAB_LABELS = (
        ("Scanner", 0),
        ("Overview", 1),
        ("Findings", 2),
        ("Reports", 3),
        ("System Guard", 4),
        ("PCAP Analysis", 5),
        ("Tool Integrations", 6),
        ("Settings", 7),
    )

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Qolam Sentinel {APP_VERSION} | Security Workbench")
        self.setWindowIcon(create_sentinel_icon())
        self.resize(1360, 900)
        self.setMinimumSize(1080, 760)
        self.setStyleSheet(DARK_TACTICAL_THEME)
        self._tabs: dict[int, QWidget] = {}
        self._setup_ui()
        self._open_tab(0)

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(218)
        sidebar.setStyleSheet(
            "QFrame#Sidebar { background:#09111d; border-right:1px solid #1b3047; }"
        )
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(14, 22, 14, 16)
        side.setSpacing(7)

        mark = QLabel()
        mark.setPixmap(create_sentinel_icon().pixmap(46, 46))
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setStyleSheet("font-size:35px; color:#63d8f2; font-weight:700;")
        name = QLabel("QOLAM")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name.setStyleSheet("font-size:20px; color:#e9f5ff; font-weight:800; letter-spacing:3px;")
        sub = QLabel("S E N T I N E L")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("font-size:9px; color:#6d8da8; letter-spacing:2px;")
        side.addWidget(mark)
        side.addWidget(name)
        side.addWidget(sub)
        side.addSpacing(25)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for text, index in self.TAB_LABELS:
            button = QPushButton(text)
            button.setCheckable(True)
            button.setProperty("class", "NavButton")
            button.setMinimumHeight(42)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            self.nav_group.addButton(button, index)
            side.addWidget(button)
        self.nav_group.idClicked.connect(self._open_tab)
        side.addStretch(1)

        notice_btn = QPushButton("Responsible use notice")
        notice_btn.clicked.connect(self._show_usage_notice)
        side.addWidget(notice_btn)

        local = QLabel("AUTHORIZED ASSESSMENTS\nYour websites and permitted scope")
        local.setAlignment(Qt.AlignmentFlag.AlignCenter)
        local.setStyleSheet(
            "color:#6f879f; font-size:10px; padding:10px; border:1px solid #1c3045; border-radius:8px;"
        )
        side.addWidget(local)
        layout.addWidget(sidebar)

        content = QWidget()
        content.setObjectName("MainContent")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(18, 15, 18, 10)
        content_layout.setSpacing(0)
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("QStackedWidget#TabStack { background:transparent; }")
        self.stack.setObjectName("TabStack")
        content_layout.addWidget(self.stack, 1)
        layout.addWidget(content, 1)

        self.status_bar = QStatusBar()
        self.status_bar.showMessage("Ready — scans start only after authorization confirmation")
        self.setStatusBar(self.status_bar)

    def _open_tab(self, index: int) -> None:
        was_loaded = index in self._tabs
        if index not in self._tabs:
            tab = self._create_tab(index)
            self._tabs[index] = tab
            self.stack.addWidget(tab)
        tab = self._tabs[index]
        self.stack.setCurrentWidget(tab)
        button = self.nav_group.button(index)
        if button:
            button.setChecked(True)

        # Refresh data-backed pages on entry, but never poll them in the
        # background while the user is working in another section.
        if was_loaded and index == 1 and hasattr(tab, "refresh_metrics"):
            tab.refresh_metrics()
        elif was_loaded and index == 2 and hasattr(tab, "refresh_findings"):
            tab.refresh_findings()
        elif was_loaded and index == 3 and hasattr(tab, "refresh_scans"):
            tab.refresh_scans()
        elif was_loaded and index == 4 and hasattr(tab, "refresh_telemetry"):
            tab.refresh_telemetry()
        elif was_loaded and index == 6 and hasattr(tab, "refresh_tools"):
            tab.refresh_tools()

    def _show_usage_notice(self):
        from src.ui.usage_notice_dialog import UsageNoticeDialog
        UsageNoticeDialog(self, review_only=True).exec()

    def closeEvent(self, event):
        workers = self.findChildren(QThread)
        # Some older workspace tools keep a worker as an attribute without a
        # QObject parent. Include those before Qt destroys the window.
        for tab in self._tabs.values():
            workers.extend(value for value in vars(tab).values() if isinstance(value, QThread))
        if any(worker.isRunning() for worker in workers):
            QMessageBox.information(self, "Work in progress", "A background operation is still running. Wait for it to finish before closing Sentinel.")
            event.ignore()
            return
        event.accept()

    @staticmethod
    def _create_tab(index: int) -> QWidget:
        from src.ui.tabs import (
            FindingsTab,
            NetworkAnalysisTab,
            OverviewTab,
            ReportsTab,
            SettingsTab,
            SystemGuardTab,
            ToolHealthTab,
            WebSecurityTab,
        )

        factories = {
            0: WebSecurityTab,
            1: OverviewTab,
            2: FindingsTab,
            3: ReportsTab,
            4: SystemGuardTab,
            5: NetworkAnalysisTab,
            6: ToolHealthTab,
            7: SettingsTab,
        }
        return factories[index]()
