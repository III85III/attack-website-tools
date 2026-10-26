"""Lightweight animated OBSIDIAN scanner illustration drawn with QPainter."""
from __future__ import annotations

import math

from PyQt6.QtCore import QPointF, QRectF, QTimer, Qt
from PyQt6.QtGui import QColor, QConicalGradient, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap, QPolygonF, QRadialGradient
from PyQt6.QtWidgets import QWidget


def create_sentinel_icon(size: int = 128) -> QIcon:
    """Obsidian shield and luminous infinity mark, also used by the Windows EXE."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    margin = size * .05
    bounds = QRectF(margin, margin, size - 2*margin, size - 2*margin)
    gradient = QLinearGradient(bounds.topLeft(), bounds.bottomRight())
    gradient.setColorAt(0, QColor("#192741"))
    gradient.setColorAt(1, QColor("#050913"))
    painter.setPen(QPen(QColor("#354966"), size * .012))
    painter.setBrush(gradient)
    painter.drawRoundedRect(bounds, size*.2, size*.2)
    center = bounds.center()
    glow = QRadialGradient(center, size*.43)
    glow.setColorAt(0, QColor(17, 188, 213, 65))
    glow.setColorAt(1, QColor(17, 188, 213, 0))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(glow)
    painter.drawEllipse(bounds)
    shield = QPainterPath(QPointF(size*.5, size*.17))
    shield.lineTo(size*.79, size*.28)
    shield.lineTo(size*.76, size*.57)
    shield.cubicTo(size*.73, size*.72, size*.60, size*.80, size*.5, size*.85)
    shield.cubicTo(size*.40, size*.80, size*.27, size*.72, size*.24, size*.57)
    shield.lineTo(size*.21, size*.28)
    shield.closeSubpath()
    painter.setBrush(QColor(10, 24, 40, 180))
    edge = QLinearGradient(QPointF(size*.2, size*.2), QPointF(size*.8, size*.8))
    edge.setColorAt(0, QColor("#e8daf6"))
    edge.setColorAt(.6, QColor("#b68ad8"))
    edge.setColorAt(1, QColor("#a68abb"))
    painter.setPen(QPen(edge, size*.018))
    painter.drawPath(shield)
    infinity = QPainterPath()
    for i in range(181):
        angle = i * math.tau / 180
        point = QPointF(size*.5 + size*.20*math.cos(angle), size*.48 + size*.115*math.sin(2*angle))
        infinity.moveTo(point) if i == 0 else infinity.lineTo(point)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.setPen(QPen(QColor(34, 211, 238, 45), size*.105, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawPath(infinity)
    painter.setPen(QPen(edge, size*.047, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawPath(infinity)
    painter.setPen(QPen(QColor("#d0fffb"), size*.010, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawPath(infinity)
    painter.end()
    return QIcon(pixmap)


class SentinelHud(QWidget):
    """A small, custom-drawn holographic radar that animates during a scan."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(230, 230)
        self.setMaximumSize(300, 300)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._angle = 0
        self._active = False
        self._headline = "OBSIDIAN READY"
        self._detail = "Ready to scan"
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(110)

    def set_scanning(self, active: bool, detail: str = "") -> None:
        self._active = active
        self._headline = "LIVE SCAN" if active else "OBSIDIAN READY"
        self._detail = detail or ("Scanning target" if active else "Ready to scan")
        self._timer.setInterval(38 if active else 110)
        self.update()

    def set_result(self, headline: str, detail: str = "") -> None:
        self._active = False
        self._headline = headline[:24]
        self._detail = detail[:42] or "Scan complete"
        self._timer.setInterval(110)
        self.update()

    def _tick(self) -> None:
        self._angle = (self._angle + (7 if self._active else 2)) % 360
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height()) - 18
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        center = rect.center()
        radius = side / 2

        glow = QRadialGradient(center, radius)
        glow.setColorAt(0.0, QColor(16, 77, 111, 60 if self._active else 36))
        glow.setColorAt(0.72, QColor(8, 26, 48, 32))
        glow.setColorAt(1.0, QColor(4, 13, 27, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(rect)

        # Fine radial guides and range rings.
        for scale, alpha in ((0.91, 115), (0.72, 86), (0.52, 66), (0.31, 52)):
            r = radius * scale
            pen = QPen(QColor(62, 184, 225, alpha), 1)
            pen.setStyle(Qt.PenStyle.DotLine if scale in (0.72, 0.31) else Qt.PenStyle.SolidLine)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QRectF(center.x() - r, center.y() - r, 2*r, 2*r))

        painter.save()
        painter.translate(center)
        painter.rotate(self._angle)
        sweep = QConicalGradient(QPointF(0, 0), 0)
        sweep.setColorAt(0.00, QColor(75, 231, 255, 210 if self._active else 125))
        sweep.setColorAt(0.035, QColor(59, 190, 237, 70))
        sweep.setColorAt(0.14, QColor(47, 165, 220, 0))
        sweep.setColorAt(0.50, QColor(47, 165, 220, 0))
        sweep.setColorAt(1.00, QColor(75, 231, 255, 210 if self._active else 125))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(sweep)
        painter.drawPie(QRectF(-radius * .87, -radius * .87, radius * 1.74, radius * 1.74), 0, 360 * 16)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(86, 230, 255, 220), 2 if self._active else 1.2))
        painter.drawLine(QPointF(0, 0), QPointF(0, -radius * .87))
        painter.restore()

        # Three moving contacts on the outer track.
        for offset, distance in ((0, .73), (132, .56), (238, .86)):
            angle = math.radians(self._angle + offset)
            point = QPointF(center.x() + math.cos(angle) * radius * distance,
                            center.y() + math.sin(angle) * radius * distance)
            color = QColor(115, 244, 255, 230 if self._active else 145)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawEllipse(point, 3.1 if self._active else 2.2, 3.1 if self._active else 2.2)

        # Central OBSIDIAN mark.
        core_r = radius * .23
        points = [QPointF(center.x() + math.cos(math.radians(60*i - 30)) * core_r,
                          center.y() + math.sin(math.radians(60*i - 30)) * core_r) for i in range(6)]
        painter.setPen(QPen(QColor(88, 225, 255, 220), 1.5))
        painter.setBrush(QColor(7, 23, 42, 220))
        painter.drawPolygon(QPolygonF(points))
        painter.setPen(QPen(QColor(140, 244, 255, 235), 2))
        painter.drawLine(QPointF(center.x() - core_r*.48, center.y()), QPointF(center.x() + core_r*.48, center.y()))
        painter.drawLine(QPointF(center.x(), center.y() - core_r*.48), QPointF(center.x(), center.y() + core_r*.48))

        # Place labels in a small footer so they stay legible at all sizes.
        painter.setPen(QColor(157, 231, 248))
        title_rect = QRectF(rect.left(), rect.bottom() - 47, rect.width(), 19)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter, self._headline)
        painter.setPen(QColor(116, 153, 177))
        detail_rect = QRectF(rect.left() + 8, rect.bottom() - 27, rect.width() - 16, 17)
        painter.drawText(detail_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter, self._detail)
        painter.end()


# Compatibility aliases for existing UI extensions.
create_obsidian_icon = create_sentinel_icon
ObsidianHud = SentinelHud
