"""
III85III QOLAM SENTINEL — Configuration
Central settings, directory paths, and safety boundaries.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# User state stays outside source trees and signed/read-only application bundles.
BASE_DIR = Path(__file__).resolve().parent.parent.parent


def user_state_dir(platform_name=None, home=None, environ=None):
    platform_name = platform_name or sys.platform
    home = Path(home) if home is not None else Path.home()
    environ = os.environ if environ is None else environ
    if platform_name == "win32":
        return Path(environ.get("LOCALAPPDATA") or home / "AppData" / "Local") / "III85III" / "Qolam Sentinel"
    if platform_name == "darwin":
        return home / "Library" / "Application Support" / "III85III" / "Attack Website Tools"
    xdg = Path(environ.get("XDG_DATA_HOME") or home / ".local" / "share")
    if not xdg.is_absolute():
        xdg = home / ".local" / "share"
    return xdg / "iii85iii" / "attack-website-tools"


STATE_DIR = user_state_dir()
if sys.platform == "win32" and getattr(sys, "frozen", False):
    legacy = Path(sys.executable).resolve().parent.parent.parent
    if (legacy / "data" / "sentinel.db").is_file():
        STATE_DIR = legacy

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
APP_VERSION = "0.20.0"

# Telemetry & Monitoring
PROCESS_CPU_THRESHOLD = 80.0  # Alert if CPU exceeds this percentage
PROCESS_MEMORY_MB_THRESHOLD = 1500.0  # Alert if RAM exceeds 1.5 GB
TELEMETRY_REFRESH_INTERVAL_SEC = 3
