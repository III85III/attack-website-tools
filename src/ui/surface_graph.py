"""Interactive, bounded visualization of recorded discovery relationships."""
import json
import math
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QPen
from PyQt6.QtWidgets import QGraphicsItem, QGraphicsScene, QGraphicsView

from src.core.privacy import sanitize_data


class SurfaceGraph(QGraphicsView):
    inspected = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.graph_scene = QGraphicsScene(self); self.setScene(self.graph_scene)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.graph_scene.selectionChanged.connect(self._selection)
        self._zoom = 1.0
        self.setToolTip("Recorded discovery edges only. Select a node for evidence; scroll to zoom and drag to pan. This is not a verified exploit-chain graph.")

    def _selection(self):
        selected = self.graph_scene.selectedItems()
        if selected and selected[0].data(0) is not None:
            self.inspected.emit(selected[0].data(0))

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        if .3 < self._zoom * factor < 4:
            self.scale(factor, factor); self._zoom *= factor
        event.accept()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._zoom == 1.0 and not self.sceneRect().isEmpty():
            self.fitInView(self.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def load_graph(self, snapshot):
        self.graph_scene.clear(); self.resetTransform(); self._zoom = 1.0
        nodes = snapshot.get("nodes", [])[:60]
        if not nodes:
            self.graph_scene.addText("No recorded surface graph for this assessment.")
            return
        label = self.graph_scene.addText(f"Observed discovery relationships · showing {len(nodes)}/{len(snapshot.get('nodes', []))} nodes · not exploit-chain proof")
        label.setDefaultTextColor(QColor("#d8cbe8")); label.setPos(-480, -390)
        positions, by_url = {}, {}
        radius = max(150, min(330, len(nodes) * 12))
        for index, node in enumerate(nodes):
            angle = math.tau * index / len(nodes)
            point = (math.cos(angle) * radius, math.sin(angle) * radius)
            positions[node["id"]] = point; by_url.setdefault(node["url"], node["id"])
        for edge in snapshot.get("relationships", [])[:100]:
            source, target = by_url.get(edge.get("source_url")), edge.get("target_id")
            if source in positions and target in positions:
                x1, y1 = positions[source]; x2, y2 = positions[target]
                line = self.graph_scene.addLine(x1, y1, x2, y2, QPen(QColor("#594967"), 1.2))
                line.setToolTip("Observed: " + edge.get("relation", "reference"))
        for node in nodes:
            x, y = positions[node["id"]]
            item = self.graph_scene.addEllipse(x-9, y-9, 18, 18, QPen(QColor("#cfb2ee")), QBrush(QColor("#46324e")))
            item.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
            item.setData(0, sanitize_data({"relationship_status": "OBSERVED_DISCOVERY", **node}))
            item.setToolTip(node["url"] + "\n" + node["kind"])
            text = self.graph_scene.addText(node["kind"] + " " + (urlsplit(node["url"]).path or "/")[:30])
            text.setDefaultTextColor(QColor("#c5bdce")); text.setPos(x+12, y-12)
        self.setSceneRect(self.graph_scene.itemsBoundingRect().adjusted(-30, -30, 30, 30))
        self.fitInView(self.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
