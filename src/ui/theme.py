"""
III85III QOLAM SENTINEL — Dark Tactical Theme Stylesheet
High-contrast, professional cybersecurity theme with dark slate and cyan accents.
"""

DARK_TACTICAL_THEME = """
QWidget {
    background-color: #0b1220;
    color: #e6edf7;
    /* A single Windows family keeps Qt's Persian/Arabic glyph fallback reliable. */
    font-family: 'Segoe UI';
    font-size: 13px;
}

/* Main Window & Header */
QMainWindow {
    background-color: #080d17;
}

QLabel { background: transparent; }

QPushButton {
    background-color: #15293c;
    color: #d5e6f4;
    border: 1px solid #2b465d;
    border-radius: 7px;
    padding: 8px 12px;
    min-height: 20px;
}
QPushButton:hover { background-color: #1d3b52; border-color: #4387a5; }

QGroupBox {
    background-color: #101a2a;
    border: 1px solid #24344b;
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
    border-top: 1px solid #24344b;
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
    background-color: #142238;
    color: #67d8fa;
    border: 1px solid #294865;
}

QPushButton.NavButton:checked {
    background-color: #142b42;
    color: #7ddcff;
    border: 1px solid #245777;
}

/* Action Buttons */
QPushButton.ActionBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #087ca8, stop:1 #1762a0);
    color: #ffffff;
    font-weight: bold;
    border: none;
    border-radius: 8px;
    padding: 10px 18px;
}

QPushButton.ActionBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1296c3, stop:1 #247ac0);
}

QPushButton:disabled {
    background-color: #26364a;
    color: #73849a;
    border-color: #26364a;
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
    border: 1px solid #26374e;
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
    background-color: #0e1725;
    alternate-background-color: #122237;
    border: 1px solid #26374e;
    border-radius: 8px;
    color: #f1f5f9;
    gridline-color: #223249;
    selection-background-color: #1b4665;
    selection-color: #ffffff;
    padding: 3px;
}

QTableWidget::item, QListWidget::item {
    padding: 6px 5px;
    border-bottom: 1px solid #1c2a3d;
}

QTableWidget::item:selected, QListWidget::item:selected {
    background-color: #1b4665;
    color: #ffffff;
}

/* Input Fields */
QLineEdit, QComboBox {
    background-color: #111d2d;
    border: 1px solid #344961;
    border-radius: 7px;
    padding: 8px 10px;
    color: #f8fafc;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid #42b8de;
}

QComboBox QAbstractItemView {
    background-color: #111d2d;
    color: #e6edf7;
    selection-background-color: #1b4665;
    border: 1px solid #344961;
}

QCheckBox {
    spacing: 9px;
}
QCheckBox::indicator {
    width: 17px;
    height: 17px;
}
QCheckBox::indicator:unchecked {
    background-color: #111d2d;
    border: 1px solid #536982;
    border-radius: 4px;
}
QCheckBox::indicator:checked {
    background-color: #1383aa;
    border: 1px solid #52c6e8;
    border-radius: 4px;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #0b0f19;
    width: 8px;
}
QScrollBar::handle:vertical {
    background: #334155;
    min-height: 20px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #42b8de;
}
QScrollBar:horizontal {
    border: none;
    background: #0b1220;
    height: 8px;
}
QScrollBar::handle:horizontal {
    background: #344961;
    min-width: 20px;
    border-radius: 4px;
}
QProgressBar {
    background-color: #142238;
    border: 1px solid #29415c;
    border-radius: 5px;
    min-height: 10px;
}
QProgressBar::chunk {
    background-color: #1c91b6;
    border-radius: 4px;
}
"""
