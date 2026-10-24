"""Write redacted, structured scan execution records for auditability."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from src.core.config import LOGS_DIR
from src.core.models import ScanRun
from src.core.privacy import sanitize_data


def _redact(value: Any) -> Any:
    return _bound_strings(sanitize_data(value))


def _bound_strings(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _bound_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_bound_strings(item) for item in value]
    if isinstance(value, str):
        return value[:5000]
    return value


def write_execution_log(scan: ScanRun) -> Path:
    """Atomically persist one scan's structured log and return its path."""
    directory = Path(LOGS_DIR) / "scans"
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{scan.id}.json"
    payload = _redact({
        "schema": "qolam-sentinel-scan-log-v1",
        "log_path": str(destination),
        "scan": scan.to_dict(),
    })
    fd, temporary_name = tempfile.mkstemp(prefix=f".{scan.id}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return destination
