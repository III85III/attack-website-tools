"""
III85III QOLAM SENTINEL — Base Tool Adapter
Abstract base class for all external tool integrations.
"""
from __future__ import annotations

import abc
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from src.core.models import Finding, ScanRun, ToolHealthInfo


class BaseToolAdapter(abc.ABC):
    """Abstract base class for external cybersecurity tools."""

    name: str = "base_tool"

    def __init__(self, executable_path: Optional[str] = None):
        self.executable_path = executable_path

    @abc.abstractmethod
    def detect(self) -> ToolHealthInfo:
        """Detect whether the tool is installed, its version, and readiness."""
        pass

    @abc.abstractmethod
    def run_scan(
        self,
        target: str,
        scan_run: ScanRun,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ScanRun, List[Finding]]:
        """Execute the tool scan, record evidence, and return structured findings."""
        pass

    def run_subprocess_safe(
        self,
        cmd: List[str],
        timeout_sec: int = 60,
    ) -> Tuple[int, str, str]:
        """
        Execute command without shell=True to prevent command injection.
        Returns (exit_code, stdout, stderr).
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                shell=False,
                # GUI scans and tool health probes must not create a visible
                # console window for every child process on Windows.
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            return -1, exc.stdout or "", f"Timeout of {timeout_sec}s expired"
        except FileNotFoundError:
            return -2, "", f"Executable not found: {cmd[0]}"
        except Exception as exc:
            return -3, "", f"Execution error: {str(exc)}"
