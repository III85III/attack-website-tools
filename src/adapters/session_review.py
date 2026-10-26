"""Read-only, user-declared session and access checks; no login attempts or ID guessing."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

from src.adapters.web_auditor import WebAuditorAdapter
from src.core.models import Finding, FindingConfidence, FindingSeverity, FindingStatus, ScanRun
from src.core.privacy import sanitize_text

MAX_CASES = 12
MAX_BODY_BYTES = 250_000


def _marker(value, required=True):
    if not isinstance(value, str) or len(value) > 200 or (required and len(value.strip()) < 6):
        raise ValueError("Use a unique content marker of 6 to 200 characters.")
    return value


def _profile(value):
    if not isinstance(value, dict) or value.get("mode") not in {"cookie", "bearer"}:
        raise ValueError("Choose Cookie or Bearer token for each account.")
    secret = value.get("secret", "")
    if not isinstance(secret, str) or not secret or not secret.isascii() or len(secret) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in secret):
        raise ValueError("A session value is missing, too long or contains a line break.")
    return {"mode": value["mode"], "secret": secret, "marker": _marker(value.get("marker", ""))}


def validate_plan(target, plan):
    valid, message, base = WebAuditorAdapter.validate_target_url(target)
    if not valid:
        raise ValueError(message)
    parsed = urlparse(base)
    try:
        local = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = parsed.hostname.lower() == "localhost"
    if parsed.scheme != "https" and not local:
        raise ValueError("Remote session checks require HTTPS to protect account credentials.")
    if not isinstance(plan, dict) or plan.get("read_only_confirmed") is not True:
        raise ValueError("Confirm that all supplied paths are authorized and read-only.")
    origin = WebAuditorAdapter._web_origin(parsed)

    def resolve(path):
        if not isinstance(path, str) or not path or len(path) > 2000 or any(c.isspace() or c == "\\" for c in path):
            raise ValueError("Supply a valid same-origin path or URL.")
        if not path.startswith(("/", "https://", "http://")):
            raise ValueError("Paths must begin with / or use a complete same-origin URL.")
        url = urljoin(base, path)
        value = urlparse(url)
        if value.username is not None or value.password is not None or value.fragment or WebAuditorAdapter._web_origin(value) != origin:
            raise ValueError("Every session check must stay on the exact selected origin without URL credentials or fragments.")
        return url

    primary = _profile(plan.get("primary"))
    secondary = _profile(plan["secondary"]) if plan.get("secondary") else None
    if secondary and (primary["mode"], primary["secret"]) == (secondary["mode"], secondary["secret"]):
        raise ValueError("Use separate sessions for the two test accounts.")
    if secondary and primary["marker"] == secondary["marker"]:
        raise ValueError("Use distinct account-specific session markers for the two accounts.")
    cases = plan.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError(f"Configure 1 to {MAX_CASES} explicit read-only paths.")
    normalized = []
    for row in cases:
        if not isinstance(row, dict) or not isinstance(row.get("anonymous_allowed", False), bool) or not isinstance(row.get("secondary_allowed", False), bool):
            raise ValueError("Every path needs explicit access expectations.")
        normalized.append({"url": resolve(row.get("path")), "marker": _marker(row.get("marker", "")),
                           "forbidden": _marker(row.get("forbidden", ""), required=False),
                           "anonymous_allowed": row.get("anonymous_allowed", False),
                           "secondary_allowed": row.get("secondary_allowed", False)})
    return {"primary": primary, "secondary": secondary, "canary": resolve(plan.get("canary_path")), "cases": normalized}


class SessionReviewAdapter:
    name = "Read-only Session and Access Review"

    def __init__(self):
        self.request_count = 0

    def _get(self, session, url, markers):
        time.sleep(0.15)
        self.request_count += 1
        session.cookies.clear()  # A response cookie must not promote/change a test identity.
        try:
            with session.get(url, allow_redirects=False, verify=True, stream=True, timeout=(3, 8)) as response:
                content = bytearray()
                limited = False
                for chunk in response.iter_content(chunk_size=16384):
                    content.extend(chunk[:MAX_BODY_BYTES - len(content)])
                    if len(content) >= MAX_BODY_BYTES:
                        limited = True
                        break
                body = bytes(content)
                text = body.decode(response.encoding or "utf-8", errors="replace")
                return {"http_status": response.status_code, "body_sha256": hashlib.sha256(body).hexdigest(),
                        "body_limit_reached": limited, "matches": {name: bool(value and value in text) for name, value in markers.items()}}
        except (requests.RequestException, LookupError, UnicodeError) as exc:
            return {"http_status": None, "error_type": type(exc).__name__, "matches": {}, "body_limit_reached": False}

    def run_scan(self, target: str, scan: ScanRun, plan):
        started = time.monotonic()
        self.request_count = 0
        sessions = {}
        findings, checks = [], []
        try:
            config = validate_plan(target, plan)  # Validate the entire plan before any credentials are sent.
            for identity, profile in (("primary", config["primary"]), ("anonymous", None), ("secondary", config["secondary"])):
                if identity == "secondary" and profile is None:
                    continue
                session = requests.Session()
                session.trust_env = False
                session.headers.update({"User-Agent": "OBSIDIAN/SessionReview", "Accept": "text/html,application/json"})
                if profile:
                    header = "Cookie" if profile["mode"] == "cookie" else "Authorization"
                    session.headers[header] = profile["secret"] if header == "Cookie" else "Bearer " + profile["secret"]
                sessions[identity] = session
            identity_markers = {identity: config[identity]["marker"] for identity in ("primary", "secondary") if config.get(identity)}
            anonymous_canary = self._get(sessions["anonymous"], config["canary"], identity_markers)
            valid_sessions = {}
            for identity in ("primary", "secondary"):
                if identity not in sessions:
                    continue
                observation = self._get(sessions[identity], config["canary"], {"expected": config[identity]["marker"], **{other: marker for other, marker in identity_markers.items() if other != identity}})
                if identity == "primary":
                    scan.response_status = observation["http_status"]
                valid_sessions[identity] = (observation["http_status"] is not None and 200 <= observation["http_status"] < 300
                                            and not observation["body_limit_reached"] and observation["matches"].get("expected", False)
                                            and anonymous_canary["http_status"] is not None and not anonymous_canary["body_limit_reached"]
                                            and not anonymous_canary["matches"].get(identity, False)
                                            and not any(observation["matches"].get(other, False) for other in identity_markers if other != identity))
                checks.append({"check": "Session canary", "identity": identity, "url": sanitize_text(config["canary"]),
                               "outcome": "PASS" if valid_sessions[identity] else "INCONCLUSIVE", **observation})
            if valid_sessions.get("primary"):
                for case in config["cases"]:
                    primary = self._get(sessions["primary"], case["url"], {"expected": case["marker"], "forbidden": case["forbidden"]})
                    baseline = (primary["http_status"] is not None and 200 <= primary["http_status"] < 300
                                and primary["matches"].get("expected", False) and not primary["body_limit_reached"])
                    checks.append({"check": "Authenticated path", "identity": "primary", "url": sanitize_text(case["url"]),
                                   "outcome": "PASS" if baseline else "INCONCLUSIVE", **primary})
                    if not baseline:
                        continue
                    if case["forbidden"]:
                        failed = primary["matches"].get("forbidden", False)
                        checks.append({"check": "Declared read-only business expectation", "identity": "primary",
                                       "url": sanitize_text(case["url"]), "http_status": primary["http_status"], "outcome": "FAIL" if failed else "PASS"})
                        if failed:
                            findings.append(self._finding(scan, case, "Declared read-only business expectation failed", "primary", primary, business=True))
                    for identity in ("anonymous", "secondary"):
                        if identity not in sessions:
                            continue
                        if identity == "secondary" and not valid_sessions.get("secondary"):
                            continue
                        allowed = case[f"{identity}_allowed"]
                        if identity == "anonymous":
                            sessions[identity].cookies.clear()
                        value = self._get(sessions[identity], case["url"], {"expected": case["marker"]})
                        exposed = value["http_status"] is not None and 200 <= value["http_status"] < 300 and value["matches"].get("expected", False)
                        if value["body_limit_reached"] or value.get("error_type"):
                            outcome = "INCONCLUSIVE"
                        elif exposed:
                            outcome = "PASS" if allowed else "FAIL"
                        elif value["http_status"] in {401, 403, 404} and not allowed:
                            outcome = "PASS"
                        else:
                            outcome = "INCONCLUSIVE"
                        if outcome == "FAIL":
                            repeated = self._get(sessions[identity], case["url"], {"expected": case["marker"]})
                            stable = (repeated["http_status"] is not None and 200 <= repeated["http_status"] < 300
                                      and repeated["matches"].get("expected", False) and not repeated["body_limit_reached"])
                            value["repeat_marker_matched"] = stable
                            value["repeat_body_sha256"] = repeated.get("body_sha256")
                            # Recheck the owner as well: expiry or role changes after the
                            # initial baseline invalidate an access-control comparison.
                            recheck_identities = ["primary"] + (["secondary"] if identity == "secondary" else [])
                            identity_checks = {}
                            for account in recheck_identities:
                                canary = self._get(sessions[account], config["canary"], identity_markers)
                                identity_checks[account] = bool(
                                    canary["http_status"] is not None and 200 <= canary["http_status"] < 300
                                    and not canary["body_limit_reached"] and canary["matches"].get(account, False)
                                    and not any(canary["matches"].get(other, False) for other in identity_markers if other != account))
                            stable = stable and all(identity_checks.values())
                            value["identity_revalidated"] = identity_checks
                            if not stable:
                                outcome = "INCONCLUSIVE"
                        checks.append({"check": "Declared access policy", "identity": identity, "url": sanitize_text(case["url"]),
                                       "expected_allowed": allowed, "outcome": outcome, **value})
                        if outcome == "FAIL":
                            findings.append(self._finding(scan, case, f"Protected content matched for {identity} access", identity, value))
            inconclusive = sum(item["outcome"] == "INCONCLUSIVE" for item in checks)
            scan.status = "PARTIAL" if inconclusive else "COMPLETED"
            scan.exit_code = 0
            scan.completion_reason = (
                f"Read-only session/access review: {len(checks)} checks; {inconclusive} inconclusive; {self.request_count} actual GET requests. "
                "Only supplied paths and expectations were checked. Account identity and business impact require assessor review. "
                "Login flows, MFA, password reset, state-changing workflows and unlisted resources were not tested."
            )
            scan.execution_log.append({"operation": "Session/access review", "state": scan.status, "checks": checks,
                                       "request_count": self.request_count, "response_body_limit_bytes": MAX_BODY_BYTES,
                                       "configured_paths": len(config["cases"]), "secondary_configured": bool(config["secondary"])})
        except (ValueError, TypeError) as exc:
            scan.status, scan.exit_code = "FAILED", -1
            scan.error_message = str(exc)
            scan.completion_reason = "Session/access review did not complete. " + str(exc)
            scan.execution_log.append({"operation": "Session/access review", "state": "FAILED", "error_type": type(exc).__name__, "checks": []})
        finally:
            for session in sessions.values():
                session.headers.clear()
                session.cookies.clear()
                session.close()
        scan.request_count = self.request_count
        scan.duration_ms = int((time.monotonic() - started) * 1000)
        scan.end_time = datetime.now(timezone.utc).isoformat()
        scan.findings_count = len(findings)
        return scan, findings

    def _finding(self, scan, case, title, identity, observation, business=False):
        safe = {"identity": identity, "url": sanitize_text(case["url"]), "observation": observation,
                "expected_allowed": False, "content_marker_sha256": hashlib.sha256(case["marker"].encode()).hexdigest(),
                "raw_response": "not retained", "credentials": "not retained",
                "preconditions": "Assessor-declared synthetic accounts, read-only resource and expected-denied identity.",
                "expected": "The declared denied identity cannot observe the supplied protected marker.",
                "observed": "Protected content marker reproduced in two independent successful requests." if not business else "The declared forbidden content marker was observed.",
                "reproduction_steps": ["Validate each test-account marker against the canary and anonymous control.", "Repeat GET on the explicit resource under primary and expected-denied identities.", "Inspect role assignment and synthetic-object ownership before assigning exploit impact."],
                "limitations": "No ID enumeration, account creation, login attempt or state-changing workflow was performed."}
        return Finding(scan_id=scan.id, title=title, description=(
            "A supplied content assertion failed. Review the application rule and reproduce manually; this does not establish exploit impact."
            if business else "A known content marker was visible under an identity declared denied by the assessor, while the primary account baseline matched. Verify role assignment, resource ownership and impact."),
            source_tool=self.name, target=sanitize_text(case["url"]), tool_version="1.0",
            severity=FindingSeverity.LOW if business else FindingSeverity.HIGH,
            severity_source="User-declared read-only expectation and observed response content",
            confidence=FindingConfidence.MEDIUM, confidence_justification="Content match under supplied sessions; role identity and impact were not independently established.",
            status=FindingStatus.POTENTIAL if business else FindingStatus.SCANNER_REPORTED,
            evidence_raw=json.dumps(safe), evidence_summary=f"{identity}: HTTP {observation['http_status']}; marker matched; response hash retained.",
            cwe_id=None if business else "CWE-862", remediation="Enforce server-side access and ownership rules; review the supplied expectation and verify with authorized test accounts.")
