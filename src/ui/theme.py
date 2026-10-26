"""
III85III OBSIDIAN — Dark Tactical Theme Stylesheet
High-contrast, professional cybersecurity theme with dark slate and cyan accents.
"""

DARK_TACTICAL_THEME = """
QWidget {
    background-color: #0c0d12;
    color: #e9e7ee;
    /* A single Windows family keeps Qt's Persian/Arabic glyph fallback reliable. */
    font-family: 'Segoe UI';
    font-size: 13px;
}

/* Main Window & Header */
QMainWindow {
    background-color: #08090d;
}

QLabel { background: transparent; }

QPushButton {
    background-color: #1c1d29;
    color: #dfdce8;
    border: 1px solid #393245;
    border-radius: 7px;
    padding: 8px 12px;
    min-height: 20px;
}
QPushButton:hover { background-color: #2b263b; border-color: #b49bd9; }

QGroupBox {
    background-color: #12131b;
    border: 1px solid #302b3b;
    border-radius: 10px;
    margin-top: 13px;
    padding: 16px 10px 10px 10px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 7px;
    color: #b6c8df;
}

QStatusBar {
    background-color: #0d1726;
    color: #a7b7ca;
    border-top: 1px solid #302b3b;
    padding: 4px 10px;
}

QToolTip {
    background-color: #17263a;
    color: #f1f5f9;
    border: 1px solid #3b536f;
    padding: 6px 8px;
}

QHeaderView::section {
    background-color: #162032;
    color: #38bdf8;
    padding: 6px;
    font-weight: bold;
    border: 1px solid #1e293b;
}

/* Sidebar Navigation Buttons */
QPushButton.NavButton {
    background-color: transparent;
    color: #9aacbf;
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 12px 14px;
    text-align: left;
    font-size: 13px;
    font-weight: 600;
}

QPushButton.NavButton:hover {
    background-color: #201927;
    color: #dac3f1;
    border: 1px solid #574165;
}

QPushButton.NavButton:checked {
    background-color: #2e2238;
    color: #e4cbfa;
    border: 1px solid #75538c;
}

/* Action Buttons */
QPushButton.ActionBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #70528e, stop:1 #58446f);
    color: #ffffff;
    font-weight: bold;
    border: none;
    border-radius: 8px;
    padding: 10px 18px;
}

QPushButton.ActionBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8462a3, stop:1 #70528e);
}

QPushButton:disabled {
    background-color: #24212b;
    color: #81758d;
    border-color: #24212b;
}

QPushButton.DangerBtn {
    background-color: #991b1b;
    color: #ffffff;
    font-weight: bold;
    border: none;
    border-radius: 6px;
    padding: 8px 18px;
}

QPushButton.DangerBtn:hover {
    background-color: #dc2626;
}

/* Metric / Stat Cards */
QFrame.StatCard {
    background-color: #111c2c;
    border: 1px solid #38303f;
    border-radius: 10px;
    padding: 14px;
}

QLabel.StatValue {
    font-size: 26px;
    font-weight: bold;
    color: #69d8f5;
}

QLabel.StatLabel {
    font-size: 11px;
    color: #9ca3af;
    text-transform: uppercase;
}

/* Tables & Lists */
QTableWidget, QListWidget, QTextEdit {
    background-color: #111117;
    alternate-background-color: #191620;
    border: 1px solid #38303f;
    border-radius: 8px;
    color: #f1f5f9;
    gridline-color: #302935;
    selection-background-color: #493253;
    selection-color: #ffffff;
    padding: 3px;
}

QTableWidget::item, QListWidget::item {
    padding: 6px 5px;
    border-bottom: 1px solid #302935;
}

QTableWidget::item:selected, QListWidget::item:selected {
    background-color: #493253;
    color: #ffffff;
}

/* Input Fields */
QLineEdit, QComboBox {
    background-color: #15121b;
    border: 1px solid #44374e;
    border-radius: 7px;
    padding: 8px 10px;
    color: #f8fafc;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid #bc99dd;
}

QComboBox QAbstractItemView {
    background-color: #15121b;
    color: #e9e7ee;
    selection-background-color: #493253;
    border: 1px solid #44374e;
}

QCheckBox {
    spacing: 9px;
}
QCheckBox::indicator {
    width: 17px;
    height: 17px;
}
QCheckBox::indicator:unchecked {
    background-color: #15121b;
    border: 1px solid #536982;
    border-radius: 4px;
}
QCheckBox::indicator:checked {
    background-color: #806194;
    border: 1px solid #ccb1e3;
    border-radius: 4px;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #0d0c12;
    width: 8px;
}
QScrollBar::handle:vertical {
    background: #334155;
    min-height: 20px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #bc99dd;
}
QScrollBar:horizontal {
    border: none;
    background: #0c0d12;
    height: 8px;
}
QScrollBar::handle:horizontal {
    background: #44374e;
    min-width: 20px;
    border-radius: 4px;
}
QProgressBar {
    background-color: #201927;
    border: 1px solid #29415c;
    border-radius: 5px;
    min-height: 10px;
}
QProgressBar::chunk {
    background-color: #1c91b6;
    border-radius: 4px;
}
"""

DARK_TACTICAL_THEME += """
QTreeWidget, QTextBrowser { background:#111117; color:#e5ddea; border:1px solid #38303f; alternate-background-color:#191620; selection-background-color:#493253; }
QHeaderView::section { background:#211b29; color:#d8c7e7; border:0; padding:8px; }
QTabBar::tab { background:#18141f; color:#bfb1cb; padding:10px 15px; border-bottom:2px solid transparent; }
QTabBar::tab:selected { color:#f2eafb; border-bottom:2px solid #bc99dd; }
QSplitter::handle { background:#302637; }
"""
