"""Bounded HAR discovery; credentials, bodies and captured values never replayed."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.core.application_map import origin, read_only_candidate, safe_url

MAX_HAR_BYTES = 5_000_000
MAX_HAR_ENTRIES = 2000
MAX_TRAFFIC_ROUTES = 150


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("HAR contains duplicate JSON keys")
        result[key] = value
    return result


def _canonical_route(target, request, response, index):
    url, method = request.get("url"), request.get("method")
    if not isinstance(url, str) or len(url) > 4096 or origin(url) != origin(target):
        return None, "outside_scope_or_invalid"
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        return None, "unsupported_method"
    method = method.upper()
    names = sorted(set(n for n, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)))
    if len(names) > 20 or any(len(name) > 80 for name in names):
        return None, "parameter_limit"
    headers = request.get("headers", [])
    if not isinstance(headers, list) or len(headers) > 200:
        return None, "malformed_headers"
    authenticated = bool(request.get("cookies")) or any(isinstance(h, dict) and str(h.get("name", "")).lower() in {"authorization", "cookie", "x-api-key"} for h in headers)
    ownership = any(re.search(r"(?i)(?:^|_)(?:id|uid|tenant|account|user|order)(?:_|$)", name) for name in names)
    status = response.get("status")
    if not isinstance(status, int) or isinstance(status, bool) or not 0 <= status <= 599:
        return None, "invalid_response_status"
    reason = ("Recorded credentials are not replayed; use explicit synthetic-account setup." if authenticated else
              "Ownership-sensitive parameters require declared synthetic resources." if ownership else
              "Only read-only GET query inputs are eligible for synthetic probes." if method != "GET" or not read_only_candidate(url) else
              "No query input; retained for discovery only." if not names else "Eligible only after explicit approval of read-only synthetic probes.")
    return {"url": safe_url(url), "method": method, "parameter_names": names,
        "recorded_status": status, "capture_entry": index, "authentication_recorded": authenticated,
        "probe_eligible": method == "GET" and bool(names) and not authenticated and not ownership and read_only_candidate(url),
        "reason": reason}, None


def import_har(path: Path, target: str):
    """Parse only metadata from a supplied capture; never fetch URLs here."""
    if origin(target) is None:
        raise ValueError("Enter a valid HTTP/S target before importing traffic")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_HAR_BYTES + 1)
    if len(raw) > MAX_HAR_BYTES:
        raise ValueError("HAR exceeds the 5 MB limit; export a smaller capture")
    try:
        document = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid HAR JSON") from exc
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list) or len(entries) > MAX_HAR_ENTRIES:
        raise ValueError("Expected HAR log.entries with no more than 2000 entries")
    routes, excluded, seen = [], {}, set()
    for index, entry in enumerate(entries):
        request = entry.get("request") if isinstance(entry, dict) else None
        response = entry.get("response") if isinstance(entry, dict) else None
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise ValueError("Malformed HAR request/response entry")
        route, reason = _canonical_route(target, request, response, index)
        if reason:
            excluded[reason] = excluded.get(reason, 0) + 1
            continue
        key = (route["method"], route["url"], route["authentication_recorded"])
        if key in seen:
            continue
        seen.add(key)
        if len(routes) >= MAX_TRAFFIC_ROUTES:
            raise ValueError("HAR route limit exceeded; narrow the capture before importing")
        routes.append(route)
    return {"schema": "obsidian-har-inventory-v1", "target_origin": list(origin(target)),
        "source_sha256": hashlib.sha256(raw).hexdigest(), "entry_count": len(entries),
        "routes": routes, "excluded": excluded,
        "limits": "Captured bodies, headers, cookies and query values are discarded; observed traffic is not a live verification."}


def validate_traffic_plan(target, plan):
    if not isinstance(plan, dict) or plan.get("schema") != "obsidian-har-inventory-v1" or plan.get("target_origin") != list(origin(target) or ()):
        raise ValueError("Traffic capture scope does not match the current target")
    routes = plan.get("routes")
    if not isinstance(routes, list) or len(routes) > MAX_TRAFFIC_ROUTES:
        raise ValueError("Invalid traffic route inventory")
    if not re.fullmatch(r"[a-f0-9]{64}", str(plan.get("source_sha256", ""))):
        raise ValueError("Invalid traffic provenance hash")
    cleaned = []
    for route in routes:
        if not isinstance(route, dict) or origin(route.get("url", "")) != origin(target):
            raise ValueError("Traffic inventory contains an out-of-scope route")
        if route.get("url") != safe_url(route["url"]):
            raise ValueError("Traffic query values must already be redacted")
        request = {"url": route["url"], "method": route.get("method"), "headers": [],
                   "cookies": [{}] if route.get("authentication_recorded") else []}
        checked, error = _canonical_route(target, request, {"status": route.get("recorded_status")}, route.get("capture_entry"))
        if error or checked["parameter_names"] != route.get("parameter_names") or checked["probe_eligible"] != route.get("probe_eligible"):
            raise ValueError("Traffic route metadata is inconsistent")
        cleaned.append(checked)
    return {"schema": "obsidian-har-inventory-v1", "target_origin": list(origin(target)),
        "source_sha256": plan["source_sha256"], "routes": cleaned,
        "limits": "Imported metadata only; credentials, bodies and captured query values are never replayed."}


def synthetic_input_points(plan):
    """Only non-authenticated, non-ownership GET inputs; all values synthetic."""
    points = []
    for route in plan["routes"]:
        if not route["probe_eligible"]:
            continue
        parts = urlsplit(route["url"])
        query = urlencode([(name, "obsidian-traffic-control") for name in route["parameter_names"]])
        points.append({"url": urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")), "names": route["parameter_names"]})
    return points
