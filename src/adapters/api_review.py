"""Read-only OpenAPI discovery and live evidence, with no reference fetching."""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import requests

from src.adapters.web_auditor import WebAuditorAdapter
from src.core.models import Finding, FindingSeverity, FindingConfidence, FindingStatus

MAX_SPEC_BYTES = 2_000_000
MAX_OPERATIONS = 500
MAX_API_GETS = 20
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
SECRET_PARAMETER = re.compile(r"password|passwd|token|secret|authorization|cookie|api.?key|session", re.I)


class _AnonymousAuditor(WebAuditorAdapter):
    def _bounded_get(self, *args, **kwargs):
        self.session.cookies.clear()
        return super()._bounded_get(*args, **kwargs)


def _path(value):
    if (not isinstance(value, str) or len(value) > 1024 or not value.startswith("/") or value.startswith("//")
            or not re.fullmatch(r"/[A-Za-z0-9/_\-.~!$&'()*+,;=:@{}]*", value)
            or any(part in {".", ".."} for part in value.split("/"))):
        raise ValueError("API paths must be plain same-origin paths without encoding, query, traversal or fragments.")
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON fields are not accepted.")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("Non-finite JSON constants are not accepted.")


def import_spec_file(target, path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_SPEC_BYTES + 1)
    if len(raw) > MAX_SPEC_BYTES:
        raise ValueError("OpenAPI JSON exceeds the 2 MB limit.")
    try:
        document = json.loads(raw, object_pairs_hook=_unique, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Choose valid UTF-8 OpenAPI JSON with unique fields; YAML is not supported.") from exc
    return build_plan(target, document, hashlib.sha256(raw).hexdigest())


def build_plan(target, document, source_sha256):
    valid, _, normalized = WebAuditorAdapter.validate_target_url(target)
    if not valid or not isinstance(document, dict):
        raise ValueError("Enter a valid target URL and an OpenAPI object.")
    version = document.get("openapi", document.get("swagger", ""))
    if not isinstance(version, str) or not (re.fullmatch(r"3\.(0|1)\.\d{1,4}", version) or version == "2.0"):
        raise ValueError("Supported JSON definitions: OpenAPI 3.0 / 3.1 and Swagger 2.0.")
    base = urlsplit(normalized)
    selected_server = ""
    if version == "2.0":
        selected_server = document.get("basePath", "/")
        host = document.get("host", "")
        if not isinstance(host, str):
            raise ValueError("Swagger host must be a string.")
        if host and host.lower() != base.netloc.lower():
            raise ValueError("Swagger host must match the authorized target exactly.")
        schemes = document.get("schemes", [base.scheme])
        if not isinstance(schemes, list) or base.scheme not in schemes:
            raise ValueError("Swagger schemes do not include the selected target scheme.")
    elif "servers" in document:
        servers = document["servers"]
        if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict):
            raise ValueError("OpenAPI servers must contain a valid first server.")
        selected_server = servers[0].get("url", "")
    else:
        selected_server = "/"
    if not isinstance(selected_server, str) or "{" in selected_server or "}" in selected_server:
        raise ValueError("Choose a concrete API server without template variables.")
    _path(urlsplit(selected_server).path or "/")
    server = urlsplit(urljoin(normalized, selected_server))
    if (WebAuditorAdapter._web_origin(server) != WebAuditorAdapter._web_origin(base)
            or server.username or server.password or server.query or server.fragment):
        raise ValueError("The first API server must use the exact authorized origin without credentials or query values.")
    prefix = _path(server.path or "/").rstrip("/")
    paths = document.get("paths")
    if not isinstance(paths, dict) or len(paths) > 250:
        raise ValueError("OpenAPI must contain a paths object with at most 250 paths.")
    operations = []
    for route, item in paths.items():
        if route.startswith("x-"):
            continue
        if not isinstance(item, dict):
            raise ValueError("Every API path must be an object.")
        if "$ref" in item and not any(method in METHODS for method in item):
            try:
                endpoint = _path(prefix + _path(route))
            except ValueError:
                endpoint = "[invalid path]"
            operations.append({"method": "REFERENCE", "path": endpoint, "query_names": [],
                               "skip_reason": "Path reference is not resolved; its operations are unknown",
                               "security_declared": False, "authentication_required_by_spec": False})
            if len(operations) > MAX_OPERATIONS:
                raise ValueError("OpenAPI exceeds the 500-operation limit; nothing was imported.")
        for method, operation in item.items():
            if method not in METHODS:
                continue
            if not isinstance(operation, dict):
                raise ValueError("Every API operation must be an object.")
            try:
                endpoint = _path(prefix + _path(route))
                reason = ""
            except ValueError:
                endpoint, reason = "[invalid path]", "Unsafe or unsupported path"
            parameters = item.get("parameters", []) + operation.get("parameters", []) if isinstance(item.get("parameters", []), list) and isinstance(operation.get("parameters", []), list) else None
            if parameters is None or len(parameters) > 50:
                raise ValueError("API parameter lists must contain at most 50 entries.")
            names = []
            for parameter in parameters:
                if not isinstance(parameter, dict):
                    raise ValueError("API parameters must be objects.")
                if "$ref" in parameter:
                    reason = reason or "Parameter references are not resolved"
                elif parameter.get("in") == "query":
                    name = parameter.get("name")
                    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", name):
                        reason = reason or "Unsupported query parameter name"
                    elif SECRET_PARAMETER.search(name):
                        reason = reason or "Credential-like query parameter requires explicit manual review"
                    elif name not in names:
                        names.append(name)
                elif parameter.get("required") and parameter.get("in") in {"header", "cookie"}:
                    reason = reason or "Required header or cookie is not supplied"
            if method != "get":
                reason = reason or "Method is outside this GET-only review"
            if any(key in item or key in operation for key in ("servers", "$ref")):
                reason = reason or "Operation/path server overrides and references require explicit review"
            if "{" in endpoint or "}" in endpoint:
                reason = reason or "Path template needs an assessor-supplied resource"
            if re.search(r"/(logout|signout|delete|destroy|remove|reset|unsubscribe)(/|$)", endpoint, re.I):
                reason = reason or "Potential state-changing GET route excluded"
            if len(names) > 10:
                reason = reason or "More than ten query parameters require a smaller explicit operation definition"
            security = operation.get("security", document.get("security", []))
            if (not isinstance(security, list) or any(not isinstance(entry, dict) or any(not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes) for scopes in entry.values()) for entry in security)):
                raise ValueError("API security requirements must be arrays of valid requirement objects.")
            operations.append({"method": method.upper(), "path": endpoint, "query_names": names,
                               "skip_reason": reason, "security_declared": bool(security),
                               "authentication_required_by_spec": bool(security) and all(bool(entry) for entry in security)})
            if len(operations) > MAX_OPERATIONS:
                raise ValueError("OpenAPI exceeds the 500-operation limit; nothing was imported.")
    plan = {"format": 1, "origin": list(WebAuditorAdapter._web_origin(base)), "source_sha256": source_sha256,
            "spec_version": version, "operations": operations}
    validate_api_plan(normalized, plan)
    return plan


def validate_api_plan(target, plan):
    valid, _, normalized = WebAuditorAdapter.validate_target_url(target)
    if not valid or not isinstance(plan, dict) or plan.get("format") != 1:
        raise ValueError("API assessment setup is invalid.")
    parsed = urlsplit(normalized)
    if plan.get("origin") != list(WebAuditorAdapter._web_origin(parsed)):
        raise ValueError("The target origin changed; import the API definition again for this target.")
    if not re.fullmatch(r"[a-f0-9]{64}", str(plan.get("source_sha256", ""))):
        raise ValueError("API source fingerprint is invalid.")
    operations = plan.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_OPERATIONS:
        raise ValueError("API setup must contain 1 to 500 operations.")
    for item in operations:
        if not isinstance(item, dict) or not isinstance(item.get("method"), str) or item["method"].lower() not in METHODS | {"reference"}:
            raise ValueError("Invalid API operation.")
        if item.get("skip_reason"):
            continue
        path = _path(item.get("path"))
        if item["method"] != "GET" or "{" in path or "}" in path or re.search(r"/(logout|signout|delete|destroy|remove|reset|unsubscribe)(/|$)", path, re.I):
            raise ValueError("Only concrete read-only GET operations can be selected.")
        names = item.get("query_names")
        if (not isinstance(names, list) or len(names) > 10 or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", name) or SECRET_PARAMETER.search(name) for name in names)):
            raise ValueError("Invalid API query parameter setup.")
    return parsed


class APIReviewAdapter:
    name = "OpenAPI Web Assessment"

    def run_scan(self, target, scan, plan, progress_callback=None):
        started = time.monotonic()
        checks, findings = [], []
        scan.raw_command = "Explicit OpenAPI GET review; no external reference fetching or supplied-session forwarding"
        try:
            base = validate_api_plan(target, plan)
        except (ValueError, TypeError, AttributeError):
            scan.status, scan.exit_code = "FAILED", 1
            scan.error_message = "API setup failed validation before any traffic."
            scan.end_time = datetime.now(timezone.utc).isoformat()
            scan.execution_log.append({"operation": "API coverage", "state": "FAILED", "checks": [], "request_count": 0,
                                       "reason": scan.error_message})
            return scan, findings
        native = _AnonymousAuditor()
        native._scan_metrics = {"request_count": 0, "response_statuses": [], "initial_response_status": None,
                                "errors": [], "body_limit_hits": 0, "body_read_errors": 0, "initial_body_failed": False}
        points = []
        selected = 0
        try:
            for item in plan["operations"]:
                check = {"method": item["method"], "path": item["path"], "outcome": "NOT_TESTED", "reason": item["skip_reason"],
                         "authentication_required_by_spec": item.get("authentication_required_by_spec", False)}
                checks.append(check)
                if item["skip_reason"]:
                    continue
                if selected >= MAX_API_GETS:
                    check["reason"] = "Per-review 20-operation limit reached"
                    continue
                selected += 1
                query = urlencode([(name, "sentinel") for name in item["query_names"]])
                url = urlunsplit((base.scheme, base.netloc, item["path"], query, ""))
                if progress_callback:
                    progress_callback(f"Assessing documented API GET {selected}/{MAX_API_GETS}: {item['path']}")
                time.sleep(.15)
                try:
                    before_caps = native._scan_metrics["body_limit_hits"]
                    response = native._bounded_get(url, timeout=8)
                    check.update({"http_status": response.status_code, "response_sha256": hashlib.sha256(response.content).hexdigest()})
                    if 200 <= response.status_code < 300 and native._scan_metrics["body_limit_hits"] == before_caps:
                        check.update({"outcome": "COLLECTED", "reason": "Successful anonymous response; authorization policy and business impact are not inferred"})
                        if item.get("authentication_required_by_spec") and response.content:
                            findings.append(Finding(
                                scan_id=scan.id, title="API authentication declaration differs from anonymous response",
                                description="The API definition requires authentication for this operation, but a fresh cookie-free GET received a successful non-empty response. This is a potential policy mismatch, not proof of sensitive-data access; the definition may be stale or the content intentionally public.",
                                source_tool=self.name, tool_version="1.0.0", target=urlunsplit((base.scheme, base.netloc, item["path"], "", "")),
                                severity=FindingSeverity.MEDIUM, severity_source="Declared authentication requirement versus successful anonymous content response",
                                confidence=FindingConfidence.MEDIUM, confidence_justification="No supplied credentials or previous response cookies were sent; protected-content meaning and actual policy require assessor validation.",
                                status=FindingStatus.POTENTIAL, cwe_id="CWE-306",
                                evidence_raw=json.dumps({"source_sha256": plan["source_sha256"], "http_status": response.status_code,
                                                         "response_sha256": check["response_sha256"], "authentication_required_by_spec": True,
                                                         "supplied_credentials": False, "previous_response_cookies_sent": False}),
                                evidence_summary="Declared authentication and observed anonymous response differ; no response body or credentials retained.",
                                remediation="Verify the documented policy with the owner and known protected-content markers. Enforce authentication before returning protected data, or correct the definition if this operation is intentionally public."))
                        if item["query_names"]:
                            points.append({"url": url, "names": item["query_names"]})
                    else:
                        check.update({"outcome": "INCONCLUSIVE", "reason": "Non-success response or body limit; application coverage was not established"})
                except requests.RequestException as exc:
                    check.update({"outcome": "INCONCLUSIVE", "reason": type(exc).__name__})
            findings.extend(native._probe_query_parameters(points, scan.id, progress_callback))
        except Exception as exc:
            native._scan_metrics["errors"].append(type(exc).__name__)
            checks.append({"method": "", "path": "", "outcome": "INCONCLUSIVE", "reason": "API collection interrupted: " + type(exc).__name__})
        finally:
            native.session.close()
        incomplete = any(check["outcome"] != "COLLECTED" for check in checks) or bool(native._scan_metrics["errors"] or native._scan_metrics["body_limit_hits"])
        scan.status = "PARTIAL" if incomplete else "COMPLETED"
        scan.exit_code = 0
        scan.request_count = native._scan_metrics["request_count"]
        scan.response_status = native._scan_metrics["initial_response_status"]
        scan.findings_count = len(findings)
        scan.completion_reason = f"Documented API review: {selected} GET operation(s) attempted; {sum(c['outcome'] == 'COLLECTED' for c in checks)} collected; untested/inconclusive operations remain visible."
        scan.end_time = datetime.now(timezone.utc).isoformat()
        scan.duration_ms = int((time.monotonic() - started) * 1000)
        scan.execution_log.append({"operation": "API coverage", "source_sha256": plan["source_sha256"], "spec_version": plan["spec_version"],
                                   "declared_operations": len(checks), "request_count": scan.request_count, "checks": checks,
                                   "browser_request_count": sum(item["request_count"] for item in native._browser_checks),
                                   "browser_checks": native._browser_checks, "state": scan.status,
                                   "query_probe_parameters": [{"path": urlsplit(point["url"]).path, "parameter": name}
                                                              for point in points for name in point["names"]][:10],
                                   "collection_error_types": native._scan_metrics["errors"],
                                   "limits": "20 GET operations, 10 query probes, 3 browser candidates; no authentication assertions, resource enumeration or POST/JSON submission"})
        return scan, findings
