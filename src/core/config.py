"""
III85III QOLAM SENTINEL — Configuration
Central settings, directory paths, and safety boundaries.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Source runs keep their state beside the project. Frozen installs use a
# writable per-user location; preserve the existing portable Desktop data
# folder when upgrading that layout in place.
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if getattr(sys, "frozen", False):
    executable_dir = Path(sys.executable).resolve().parent
    legacy_project_dir = executable_dir.parent.parent
    legacy_data_dir = legacy_project_dir / "data"
    local_app_data = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    STATE_DIR = legacy_project_dir if (legacy_data_dir / "sentinel.db").is_file() else local_app_data / "III85III" / "Qolam Sentinel"
else:
    STATE_DIR = BASE_DIR

DATA_DIR = STATE_DIR / "data"
LOGS_DIR = STATE_DIR / "logs"
REPORTS_DIR = STATE_DIR / "reports"
CACHE_DIR = STATE_DIR / "cache"

for directory in [DATA_DIR, LOGS_DIR, REPORTS_DIR, CACHE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Database
DB_PATH = DATA_DIR / "sentinel.db"

# Default tool paths (Windows)
DEFAULT_NMAP_PATH = ""
DEFAULT_TSHARK_PATH = ""
DEFAULT_ZAP_API_URL = "http://127.0.0.1:8080"
DEFAULT_ZAP_API_KEY = ""

# Scope and security boundaries
ALLOWED_SCAN_PROTOCOLS = ["http", "https"]
DEFAULT_LOCAL_TARGETS = ["127.0.0.1", "localhost", "::1"]
APP_VERSION = "0.19.1"

# Telemetry & Monitoring
PROCESS_CPU_THRESHOLD = 80.0  # Alert if CPU exceeds this percentage
PROCESS_MEMORY_MB_THRESHOLD = 1500.0  # Alert if RAM exceeds 1.5 GB
TELEMETRY_REFRESH_INTERVAL_SEC = 3
