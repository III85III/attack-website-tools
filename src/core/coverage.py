"""Execution coverage records, never inferred from finding counts."""
from __future__ import annotations

from src.core.privacy import sanitize_data


class CoverageLedger:
    STATES = {"COMPLETED", "SKIPPED", "BLOCKED", "INCONCLUSIVE", "FAILED"}

    def __init__(self):
        self.checks = []

    def record(self, check, state, reason, requests=0, **details):
        if state not in self.STATES:
            raise ValueError("Unknown coverage outcome")
        if len(self.checks) < 160:
            self.checks.append(sanitize_data({"check": check, "state": state,
                "reason": reason, "request_count": requests, **details}))

    def snapshot(self):
        return {"operation": "Verification coverage", "checks": list(self.checks),
            "counts": {state: sum(c["state"] == state for c in self.checks) for state in sorted(self.STATES)},
            "meaning": "COMPLETED means the named bounded operation ran, not that the vulnerability class is absent. Nested request counts are not additive."}
