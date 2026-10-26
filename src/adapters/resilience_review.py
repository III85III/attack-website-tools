"""Opt-in serial resilience sampling using the scanner's scoped HTTP transport.

This measures a small read-only endpoint sample, not server capacity or DDoS resistance.
"""
from __future__ import annotations
import math
import time
from datetime import datetime, timezone
import psutil
import requests
from src.adapters.web_auditor import WebAuditorAdapter
from src.core.application_map import origin, read_only_candidate


def validate_resilience(target, plan):
    valid, message, normalized = WebAuditorAdapter.validate_target_url(target)
    if not valid:
        raise ValueError(message)
    if not isinstance(plan, dict) or plan.get("owned_read_only_approved") is not True:
        raise ValueError("Explicit approval of an owned, read-only endpoint is required.")
    approved_origin = plan.get("approved_origin")
    if approved_origin != origin(normalized):
        # The UI keeps this in memory; JSON plans may use a list instead of tuple.
        if not isinstance(approved_origin, (list, tuple)) or tuple(approved_origin) != origin(normalized):
            raise ValueError("Resilience approval belongs to a different target origin.")
    values = {}
    for key, low, high, default in (("requests", 1, 20, 5), ("rate", .2, 2, 1),
        ("duration_seconds", 1, 30, 10), ("latency_stop_ms", 100, 5000, 2000),
        ("error_rate_stop", .1, 1, .3), ("client_memory_stop_percent", 50, 95, 90)):
        value = plan.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
            raise ValueError("Invalid resilience limit: " + key)
        values[key] = value
    if not isinstance(values["requests"], int) or plan.get("concurrency", 1) != 1:
        raise ValueError("Use an integer request budget and serial concurrency=1.")
    if not read_only_candidate(normalized):
        raise ValueError("Only a read-only target endpoint is eligible.")
    return normalized, values


def run_resilience(target, plan, cancel_check=None):
    target, limits = validate_resilience(target, plan)
    adapter = WebAuditorAdapter()
    adapter._scan_metrics = {"request_count": 0, "response_statuses": [], "initial_response_status": None,
        "errors": [], "body_limit_hits": 0, "body_read_errors": 0, "initial_body_failed": False}
    adapter._authorized_origin = origin(target)
    adapter._cancel_check = cancel_check
    records = []
    started = time.monotonic()
    stop = "Request budget completed."
    try:
        for index in range(limits["requests"]):
            due = started + index / limits["rate"]
            while time.monotonic() < due:
                if time.monotonic() - started >= limits["duration_seconds"]:
                    stop = "Duration admission limit reached."
                    break
                if cancel_check and cancel_check():
                    stop = "Emergency stop requested."
                    break
                time.sleep(max(0, min(.05, due - time.monotonic())))
            if stop == "Duration admission limit reached.":
                break
            if stop == "Emergency stop requested." or (cancel_check and cancel_check()):
                stop = "Emergency stop requested."
                break
            if time.monotonic() - started >= limits["duration_seconds"]:
                stop = "Duration admission limit reached."
                break
            if psutil.virtual_memory().percent >= limits["client_memory_stop_percent"]:
                stop = "Client memory threshold reached. Target memory is not observable."
                break
            before = time.monotonic()
            record = {"sequence": index + 1, "timestamp": datetime.now(timezone.utc).isoformat()}
            try:
                adapter.session.cookies.clear()
                response = adapter._bounded_get(target, timeout=2)
                record["status"] = response.status_code
                record["error"] = response.status_code >= 500 or response.status_code == 429
                record["response_bytes"] = len(response.content)
            except requests.RequestException as exc:
                record.update(status=None, error=True, error_type=type(exc).__name__)
            record["latency_ms"] = round((time.monotonic() - before) * 1000, 2)
            records.append(record)
            if record["status"] in {429, 503}:
                stop = "Target backpressure response."
                break
            if record["latency_ms"] >= limits["latency_stop_ms"]:
                stop = "Latency threshold reached."
                break
            if sum(row["error"] for row in records) / len(records) >= limits["error_rate_stop"]:
                stop = "Error-rate threshold reached."
                break
    finally:
        adapter.session.close()
    return {"operation": "Controlled resilience sample", "state": "COMPLETED" if len(records) == limits["requests"] and stop == "Request budget completed." else "INCONCLUSIVE",
        "target": target, "method": "GET", "request_count": adapter._scan_metrics["request_count"], "limits": limits, "concurrency": 1,
        "observations": records, "stop_reason": stop, "duration_ms": round((time.monotonic() - started) * 1000),
        "meaning": "Endpoint sample only, not a capacity/security verdict. Target CPU/RAM unavailable. No redirects or account sessions.",
        "duration_note": "Duration limits admission of new requests; an in-flight request finishes under transport timeouts/body cap."}
