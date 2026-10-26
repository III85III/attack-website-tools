"""Observed route coverage and research records built from real engine evidence."""
from __future__ import annotations
import hashlib
from urllib.parse import parse_qsl, urlsplit

from src.core.application_map import safe_url
from src.core.privacy import sanitize_data


def finding_key(finding):
    """Stable identity across serialization; no merging based on title alone."""
    import json
    try:
        data = json.loads(finding.evidence_raw)
        data = data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        data = {}
    try:
        target = safe_url(finding.target) or str(finding.target)
    except ValueError:
        target = str(finding.target)
    signature = [finding.source_tool, finding.cwe_id or "", finding.title, target,
                 data.get("method", "UNKNOWN"), data.get("parameter", ""), data.get("identity", "")]
    return hashlib.sha256(json.dumps(sanitize_data(signature), sort_keys=True).encode()).hexdigest()


def _route(url, method="GET", context="anonymous"):
    try:
        parts = urlsplit(url)
        return method, parts.path or "/", tuple(sorted(set(n for n, _ in parse_qsl(parts.query)))), context
    except ValueError:
        return method, "[invalid]", (), context


def route_coverage(graph, requests, checks, findings, traffic=None):
    routes = {}
    for node in graph.get("nodes", []):
        if node.get("kind") not in {"page", "form", "api_route", "imported_route", "input_route"}:
            continue
        key = _route(node["url"], node.get("method", "GET"), node.get("identity_context", "anonymous"))
        routes[key] = {"url": node["url"], "method": key[0], "parameters": list(key[2]),
            "identity_context": key[3], "discovered": True, "requested": False, "security_checked": False, "verified_findings": 0, "checks": [], "tested_parameters": []}
    for record in requests:
        key = _route(record["url"], record["method"])
        item = routes.setdefault(key, {"url": record["url"], "method": key[0], "parameters": list(key[2]),
            "identity_context": key[3], "discovered": False, "requested": False, "security_checked": False, "verified_findings": 0, "checks": [], "tested_parameters": []})
        item["requested"] = True
    for check in checks:
        check_url = check.get("route") or check.get("target")
        if not check_url:
            continue
        key = _route(check_url, check.get("method", "GET"))
        item = routes.get(key)
        if item:
            item["checks"].append({"check": check["check"], "state": check["state"]})
            completed = check["state"] == "COMPLETED" and check.get("request_count", 0) > 0
            item["security_checked"] |= completed
            parameter = check.get("parameter")
            if completed and parameter in item["parameters"] and parameter not in item["tested_parameters"]:
                item["tested_parameters"].append(parameter)
    for finding in findings:
        import json
        try:
            evidence = json.loads(finding.evidence_raw)
            evidence = evidence if isinstance(evidence, dict) else {}
        except (ValueError, TypeError):
            evidence = {}
        if getattr(finding.status, "value", finding.status) == "VALIDATED":
            for key, item in routes.items():
                if key[0] == "GET" and key[3] == "anonymous" and key[1] == urlsplit(finding.target).path and (not evidence.get("parameter") or evidence["parameter"] in key[2]):
                    item["verified_findings"] += 1
    for route in (traffic or {}).get("routes", []):
        item = routes.get(_route(route["url"], route["method"], "captured-authenticated-not-replayed" if route["authentication_recorded"] else "anonymous"))
        if item:
            item["capture_provenance"] = {"source_sha256": traffic["source_sha256"], "entry": route["capture_entry"]}
            if not route["probe_eligible"]:
                item["probe_limitation"] = route["reason"]
    discovered = [r for r in routes.values() if r["discovered"]]
    tested = sum(r["security_checked"] for r in discovered)
    return sanitize_data({"operation": "Route verification coverage", "routes": list(routes.values())[:350],
        "discovered_routes": len(discovered), "security_checked_discovered_routes": tested,
        "discovered_inputs": sum(len(row["parameters"]) for row in discovered),
        "security_checked_inputs": sum(len(row["tested_parameters"]) for row in discovered),
        "checked_fraction": tested / len(discovered) if discovered else None,
        "meaning": "Requested means HTTP collection only. Security checked means a recorded bounded check completed; neither means the route is safe. Verified findings are not verified attack chains."})


def sql_hypothesis(target, parameter, observations, engines, finding_ids):
    identity = hashlib.sha256((target + "|GET|" + parameter + "|SQL-error").encode()).hexdigest()[:24]
    control = [o for o in observations if o["role"] in {"baseline", "control"}]
    probes = [o for o in observations if o["role"] in {"quote", "repeat_quote"}]
    supporting = [o["response_sha256"] for o in probes if set(o["engines"]) & set(engines)]
    contradicting = [o["response_sha256"] for o in control if o["engines"]]
    return {"id": identity, "target": target, "method": "GET", "parameter": parameter,
        "class": "Input-dependent database error disclosure", "preconditions": "Authorized read-only query input; original and benign controls available.",
        "test": "Original input, benign control, quote and repeat quote; stop on collection failure or target backpressure.",
        "expected_observation": "Same new database signature in both quote responses and neither control.",
        "state": "SUPPORTED_CANDIDATE" if engines else "NOT_REPRODUCED" if len(observations) == 4 else "INCONCLUSIVE",
        "supporting_observations": supporting, "contradicting_observations": contradicting,
        "observations": observations, "finding_ids": finding_ids, "request_budget": 4, "requests_collected": len(observations),
        "retry_count": 1 if len(probes) == 2 else 0,
        "limitations": "This is an error-disclosure hypothesis, not verified SQL injection, data extraction or an exploitable chain."}
