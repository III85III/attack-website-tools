"""
III85III QOLAM SENTINEL — System Guard Monitor
Resource-conscious, genuine Windows process, network socket, and Defender telemetry service.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from src.adapters.defender_adapter import DefenderAdapter
from src.core.config import PROCESS_CPU_THRESHOLD, PROCESS_MEMORY_MB_THRESHOLD
from src.core.database import DatabaseManager
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
)

logger = logging.getLogger("qolam.system_guard")


class SystemGuardMonitor:
    """Live system telemetry and process guard for Windows 11."""

    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or DatabaseManager.get_instance()
        self.defender = DefenderAdapter()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def get_system_snapshot(self, include_defender: bool = True) -> Dict[str, Any]:
        """Collect current system metrics; Defender may involve a slow WMI query."""
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("C:\\")

        # Keep the overview fast; Defender status can require a slow PowerShell/WMI call.
        defender_stat = self.defender.get_status() if include_defender else {}

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used / (1024**3), 2),
            "memory_total_gb": round(mem.total / (1024**3), 2),
            "disk_free_gb": round(disk.free / (1024**3), 2),
            "defender_available": defender_stat.get("available", False),
            "defender_rtp": defender_stat.get("RealTimeProtectionEnabled", False),
            "defender_engine": defender_stat.get("EngineVersion", "N/A"),
        }

    def get_top_processes(self, limit: int = 25) -> List[Dict[str, Any]]:
        """Return list of active processes sorted by memory usage."""
        procs = []
        for p in psutil.process_iter(
            ["pid", "name", "username", "cpu_percent", "memory_info", "exe", "create_time"]
        ):
            try:
                info = p.info
                mem_mb = round((info["memory_info"].rss / (1024 * 1024)), 1) if info.get("memory_info") else 0
                procs.append({
                    "pid": info["pid"],
                    "name": info["name"] or "Unknown",
                    "username": info.get("username") or "N/A",
                    "cpu_percent": info.get("cpu_percent") or 0.0,
                    "memory_mb": mem_mb,
                    "exe": info.get("exe") or "N/A",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        procs.sort(key=lambda x: x["memory_mb"], reverse=True)
        return procs[:limit]

    def get_active_connections(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Collect active listening and established network sockets."""
        conns = []
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
                conns.append({
                    "fd": c.fd,
                    "family": "IPv4" if c.family == 2 else "IPv6",
                    "type": "TCP" if c.type == 1 else "UDP",
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": c.status,
                    "pid": c.pid,
                })
        except (psutil.AccessDenied, Exception):
            pass

        return conns[:limit]

    def inspect_file(self, file_path: str) -> Dict[str, Any]:
        """Compute SHA256 and gather metadata for a specific suspicious file."""
        p = Path(file_path)
        if not p.is_file():
            return {"error": "File does not exist"}

        try:
            sha256 = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)

            stat = p.stat()
            return {
                "file_name": p.name,
                "file_path": str(p.resolve()),
                "size_bytes": stat.st_size,
                "sha256": sha256.hexdigest(),
                "created_time": datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
                "modified_time": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {"error": f"Error inspecting file: {str(exc)}"}
