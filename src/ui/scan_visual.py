"""Small code-drawn infinity mark; animation runs only during a visible scan."""
import math

from PyQt6.QtCore import QPointF, QTimer, Qt
from PyQt6.QtGui import QColor, QLinearGradient, QRadialGradient, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QWidget


class InfinityIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(160, 120)
        self._active = False
        self._phase = 0
        self._label = "READY"
        self._timer = QTimer(self)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._tick)
        self.setToolTip("Live activity indicator. Actual requests and results appear below.")

    def set_state(self, state):
        self._active = state == "RUNNING"
        self._label = {"RUNNING": "LIVE ASSESSMENT", "COMPLETED": "COMPLETE",
                       "PARTIAL": "PARTIAL RESULT", "FAILED": "CHECK FAILED"}.get(state, "READY")
        self._sync_timer()
        self.update()

    def _sync_timer(self):
        if self._active and self.isVisible():
            self._timer.start()
        else:
            self._timer.stop()

    def showEvent(self, event):
        self._sync_timer()
        super().showEvent(event)

    def hideEvent(self, event):
        self._timer.stop()
        super().hideEvent(event)

    def _tick(self):
        self._phase = (self._phase + 0.09) % (2 * math.pi)
        self.update()

    @staticmethod
    def _point(t):
        denominator = 1 + math.sin(t) ** 2
        return QPointF(80 + 65 * math.cos(t) / denominator,
                       48 + 65 * math.sin(t) * math.cos(t) / denominator)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        glow = QRadialGradient(80, 48, 78)
        glow.setColorAt(0, QColor(145, 108, 183, 30))
        glow.setColorAt(1, QColor(12, 24, 40, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawRoundedRect(0, 0, 160, 100, 18, 18)
        painter.setPen(QPen(QColor(102, 174, 204, 35), 1))
        for x in range(12, 160, 16):
            for y in range(8, 88, 16):
                painter.drawPoint(x, y)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        path = QPainterPath(self._point(0))
        for i in range(1, 161):
            path.lineTo(self._point(i * 2 * math.pi / 160))
        painter.setPen(QPen(QColor(166, 128, 196, 22), 14))
        painter.drawPath(path)
        gradient = QLinearGradient(10, 20, 150, 80)
        gradient.setColorAt(0, QColor("#a68acb"))
        gradient.setColorAt(0.5, QColor("#e3d7f5"))
        gradient.setColorAt(1, QColor("#b995dd"))
        painter.setPen(QPen(gradient, 3))
        painter.drawPath(path)
        if self._active:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#d7fcff"))
            painter.drawEllipse(self._point(self._phase), 4, 4)
        painter.setPen(QColor("#bcaace"))
        painter.drawText(0, 94, 160, 22, Qt.AlignmentFlag.AlignCenter, self._label)
