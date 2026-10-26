"""Honest availability and integration status for optional external tools."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import List, Optional, Tuple

from src.core.models import ToolHealthInfo


_OPTIONAL_TOOLS: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    (
        "Nuclei",
        ("nuclei",),
        "CLI availability only; OBSIDIAN does not execute templates automatically. Import native Nuclei JSON/JSONL or SARIF results.",
    ),
    (
        "Nikto",
        ("nikto", "nikto.pl"),
        "CLI availability only; not launched by OBSIDIAN. Import supported scanner reports.",
    ),
    (
        "SQLmap",
        ("sqlmap", "sqlmap.py"),
        "CLI availability only; automated injection and data-access actions are not launched by OBSIDIAN.",
    ),
    (
        "FFUF",
        ("ffuf",),
        "CLI availability only; content discovery is not launched by OBSIDIAN.",
    ),
    (
        "Gobuster",
        ("gobuster",),
        "CLI availability only; content and DNS enumeration are not launched by OBSIDIAN.",
    ),
    (
        "WhatWeb",
        ("whatweb",),
        "CLI availability only; not launched by OBSIDIAN. Import supported scanner reports.",
    ),
    (
        "WPScan",
        ("wpscan",),
        "CLI availability only; not launched by OBSIDIAN. Import supported scanner reports.",
    ),
    (
        "HTTPX",
        ("httpx",),
        "CLI availability only; not launched by OBSIDIAN. Use reports from authorized assessments.",
    ),
    (
        "Subfinder",
        ("subfinder",),
        "CLI availability only; subdomain enumeration is not launched by OBSIDIAN.",
    ),
    (
        "Amass",
        ("amass",),
        "CLI availability only; asset discovery is not launched by OBSIDIAN.",
    ),
    (
        "testssl.sh",
        ("testssl", "testssl.sh"),
        "CLI availability only; TLS checks are not launched by OBSIDIAN.",
    ),
    (
        "Shannon",
        ("shannon",),
        "Autonomous exploit-mode scans are not launched by OBSIDIAN; import SARIF 2.1 or supported JSON reports.",
    ),
    (
        "Sn1per",
        ("sniper", "sn1per"),
        "Full CLI is Linux/Kali-oriented; OBSIDIAN imports Nmap-compatible XML exports and does not launch mass scans.",
    ),
    (
        "Strix",
        ("strix",),
        "Autonomous agent scans are not launched by OBSIDIAN; import SARIF or supported JSON reports.",
    ),
    (
        "THC Hydra",
        ("hydra",),
        "Credential-attack execution is disabled; JSON reports can be imported with usernames and passwords discarded.",
    ),
)


_USER_SOURCE_BUNDLES: Tuple[Tuple[str, str, str], ...] = (
    ("Shannon", "shannon-*.zip", "Autonomous AI web pentester source; not launched by OBSIDIAN."),
    ("Sn1per", "Sn1per-*.zip", "Attack-surface toolkit source; Linux/Kali oriented and not launched by OBSIDIAN."),
    ("Strix", "strix-*.zip", "Autonomous AI pentester source; not launched by OBSIDIAN."),
    ("THC Hydra", "thc-hydra*.zip", "Credential-auditing source; credential-attack execution is disabled."),
    ("Wireshark", "wireshark*.zip", "Network protocol analyzer source; use a separately installed Wireshark/TShark build."),
)


def _desktop_tool_folder() -> Optional[Path]:
    """Find the user's Desktop tool archive folder without assuming a username."""
    candidates = [Path.home() / "Desktop" / "pen test", Path.home() / "OneDrive" / "Desktop" / "pen test"]
    return next((p for p in candidates if p.is_dir()), None)


def _source_bundle_health() -> List[ToolHealthInfo]:
    """Show user-owned source archives as archives, never as installed tools."""
    folder = _desktop_tool_folder()
    if folder is None:
        return []

    health: List[ToolHealthInfo] = []
    for name, pattern, note in _USER_SOURCE_BUNDLES:
        archives = sorted(folder.glob(pattern), key=lambda p: p.name.lower())
        if not archives:
            continue
        archive = archives[-1]
        health.append(
            ToolHealthInfo(
                name=f"{name} Source Bundle",
                installed=False,
                version="Source archive (not installed)",
                path=str(archive),
                status_message=f"SOURCE ARCHIVE FOUND — {note} Compatible reports may be imported; archive contents are not executed.",
                availability_status="ARCHIVE_ONLY",
            )
        )
    return health


def external_tool_health() -> List[ToolHealthInfo]:
    """Check PATH only; never execute external scanner binaries for detection."""
    health = [
        ToolHealthInfo(
            name="External Report Import",
            installed=True,
            version="SARIF 2.1 / Nuclei JSONL / Nmap XML / Hydra JSON / common findings JSON",
            path="Built in",
            status_message="Ready; imports are size-bounded, hashed, and stored as scanner-reported evidence.",
            availability_status="INSTALLED_AND_VERIFIED",
        )
    ]
    for name, candidates, integration in _OPTIONAL_TOOLS:
        executable: Optional[str] = next((shutil.which(candidate) for candidate in candidates if shutil.which(candidate)), None)
        if executable:
            status = f"Executable path found, but its version/capability was not verified. It will not be auto-executed. {integration}"
            availability = "VERSION_CHECK_FAILED"
        else:
            status = f"CLI not detected on PATH. Report import remains available. {integration}"
            availability = "MISSING"
        health.append(
            ToolHealthInfo(
                name=name,
                installed=bool(executable),
                path=executable,
                status_message=status,
                availability_status=availability,
            )
        )
    health.extend(_source_bundle_health())
    return health
