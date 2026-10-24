"""Local acknowledgement of a versioned responsible-use notice, without telemetry."""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

NOTICE_VERSION = "2026-10-22.1"
NOTICE_TEXT = """AUTHORIZED WEBSITE SECURITY ASSESSMENTS

Qolam Sentinel is intended for security assessments of websites you own or have explicit authorization to test. It runs from your computer against the target you choose, including authorized public websites.

YOUR RESPONSIBILITY
You are responsible for obtaining authorization, choosing the correct targets, staying within the agreed scope and test window, complying with applicable law, and the decisions and actions you initiate. Active tests may affect availability, generate alerts or expose sensitive information. Protect collected data and review findings before acting on them.

THE CREATORS' ROLE
Providing this software does not authorize access to anyone's systems. The creators do not select or approve your targets, supervise your assessments, or grant permission on behalf of a website owner.

WARRANTY AND LIABILITY
The software is provided without warranty to the extent permitted by applicable law. Warranty and liability are governed by the included GPL-3.0-only license and applicable law. This notice does not exclude liability that cannot legally be excluded or change your rights under that license. It does not make unauthorized activity lawful.

ASSESSMENT LIMITS
Automated results may be incomplete or incorrect. A completed scan does not prove a website is secure or replace a complete penetration test. The application cannot verify your authorization; confirm it for every target.

This acknowledgement is stored on this computer only. No name, signature, target or acceptance record is sent to the creators.
"""
NOTICE_SHA256 = hashlib.sha256(NOTICE_TEXT.encode("utf-8")).hexdigest()


def notice_accepted(path: Path) -> bool:
    try:
        with Path(path).open("rb") as source:
            raw = source.read(16_385)
        if len(raw) > 16_384:
            return False
        record = json.loads(raw)
        return (isinstance(record, dict) and record.get("notice_version") == NOTICE_VERSION
                and record.get("notice_sha256") == NOTICE_SHA256 and record.get("acknowledged") is True
                and isinstance(record.get("accepted_at_utc"), str) and bool(record["accepted_at_utc"]))
    except (OSError, ValueError, TypeError):
        return False


def save_acknowledgement(path: Path, application_version: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"notice_version": NOTICE_VERSION, "notice_sha256": NOTICE_SHA256,
              "acknowledged": True, "accepted_at_utc": datetime.now(timezone.utc).isoformat(),
              "application_version": application_version}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".usage-notice-", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            json.dump(record, output, indent=2)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
