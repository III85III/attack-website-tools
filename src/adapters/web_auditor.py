"""
III85III OBSIDIAN — Native Web Security Auditor
Comprehensive, zero-API web application vulnerability, headers, cookies, and exposure auditor.
"""
from __future__ import annotations

import re
import hashlib
import json
import time
import secrets
from collections import deque
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from src.adapters.base import BaseToolAdapter
from src.adapters.browser_xss import BrowserXSSVerifier, MAX_BROWSER_CANDIDATES
from src.core.application_map import ApplicationMap, origin as map_origin, safe_url as map_safe_url, read_only_candidate
from src.core.privacy import sanitize_data, sanitize_text
from src.core.coverage import CoverageLedger
from src.core.traffic_inventory import validate_traffic_plan, synthetic_input_points
from src.core.assessment_intelligence import route_coverage, sql_hypothesis
from src.core.evidence import distinct_findings
from src.core.cve_intel import CVEIntelligenceEngine
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)


MAX_CRAWL_PAGES = 40
MAX_RESPONSE_BYTES = 1_000_000
CRAWL_DELAY_SECONDS = 0.20
MAX_ACTIVE_PARAMETERS = 15
INPUT_PROBE_MARKER = "SENTINEL-PROBE"


def _probe_text(response):
    try:
        return response.content[:MAX_RESPONSE_BYTES].decode(response.encoding or "utf-8", errors="replace")
    except LookupError:
        return response.content[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")


SQL_ERROR_SIGNATURES = {
    "PostgreSQL": ("pg_query(", "postgresql query failed", "pg_exec()"),
    "MySQL": ("mysql_fetch", "you have an error in your sql syntax", "mysqli_sql_exception"),
    "Microsoft SQL Server": ("unclosed quotation mark after the character string", "microsoft sql server"),
    "Oracle": ("ora-00933", "ora-01756", "quoted string not properly terminated"),
    "SQLite": ("sqlite3.operationalerror", "sqlite error", "unrecognized token:"),
}


class _PageInventoryParser(HTMLParser):
    """Collect same-origin crawl candidates and safe form metadata only."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.scripts: List[str] = []
        self._form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": values.get("method", "get").lower(),
                "password_field": False,
                "has_csrf_token": False,
                "fields": [],
                "query_defaults": {},
            }
            self.forms.append(self._form)
        elif tag in {"input", "textarea", "select", "button"} and self._form is not None:
            inp_type = values.get("type", "").lower()
            inp_name = values.get("name", "")
            if inp_type == "password":
                self._form["password_field"] = True
            if any(k in inp_name.lower() for k in ("csrf", "xsrf", "token", "_token", "authenticity_token", "nonce")):
                self._form["has_csrf_token"] = True
            if inp_name:
                if inp_name not in self._form["fields"]:
                    self._form["fields"].append(inp_name)
                if ("disabled" not in values and inp_type not in {"password", "file", "submit", "button", "reset"}
                        and (inp_type not in {"checkbox", "radio"} or "checked" in values)
                        and not re.search(r"(?i)csrf|xsrf|nonce|token|secret|password|auth|cookie|session", inp_name)):
                    self._form["query_defaults"][inp_name] = values.get("value", "")[:256]

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


class HTMLReflectionContext(str, Enum):
    HTML_BODY = "HTML_BODY"
    ATTRIBUTE_VALUE_QUOTED = "ATTRIBUTE_VALUE_QUOTED"
    ATTRIBUTE_VALUE_UNQUOTED = "ATTRIBUTE_VALUE_UNQUOTED"
    ATTRIBUTE_EVENT_HANDLER = "ATTRIBUTE_EVENT_HANDLER"
    ATTRIBUTE_URI = "ATTRIBUTE_URI"
    SCRIPT_BLOCK = "SCRIPT_BLOCK"
    INERT_TAG = "INERT_TAG"
    COMMENT = "COMMENT"
    UNKNOWN = "UNKNOWN"


@dataclass
class ReflectionAnalysis:
    probe_found: bool
    context: HTMLReflectionContext
    can_break_out: bool
    details: str
    recommends_alert: bool
    suggested_severity: FindingSeverity
    suggested_confidence: FindingConfidence


class HTMLReflectionContextAnalyzer:
    """
    Analyzes DOM context of reflected probes to distinguish genuine XSS breakout candidates
    from safely encoded or inert reflections (in attributes, comments, textarea, etc.).
    """

    @classmethod
    def analyze(cls, html_body: str, probe_value: str) -> ReflectionAnalysis:
        if not html_body or not probe_value or probe_value not in html_body:
            return ReflectionAnalysis(
                probe_found=False,
                context=HTMLReflectionContext.UNKNOWN,
                can_break_out=False,
                details="Probe marker not found in response body",
                recommends_alert=False,
                suggested_severity=FindingSeverity.INFO,
                suggested_confidence=FindingConfidence.LOW,
            )

        idx = html_body.find(probe_value)
        prefix = html_body[:idx]

        # 1. Check if inside HTML comment: <!-- ... probe ... -->
        last_comment_open = prefix.rfind("<!--")
        if last_comment_open != -1:
            last_comment_close = prefix.rfind("-->")
            if last_comment_close < last_comment_open:
                can_break = "-->" in probe_value
                return ReflectionAnalysis(
                    probe_found=True,
                    context=HTMLReflectionContext.COMMENT,
                    can_break_out=can_break,
                    details="Probe reflected inside HTML comment <!-- ... -->" + (" (breaks out with -->)" if can_break else " (safely trapped in comment)"),
                    recommends_alert=can_break,
                    suggested_severity=FindingSeverity.HIGH if can_break else FindingSeverity.LOW,
                    suggested_confidence=FindingConfidence.CONFIRMED if can_break else FindingConfidence.LOW,
                )

        # 2. Check if inside inert non-executable tags: textarea, title, style, noscript
        for tag in ("textarea", "title", "style", "noscript"):
            last_open = prefix.lower().rfind(f"<{tag}")
            if last_open != -1:
                last_close = prefix.lower().rfind(f"</{tag}>")
                if last_close < last_open:
                    can_break = f"</{tag}>" in probe_value.lower()
                    return ReflectionAnalysis(
                        probe_found=True,
                        context=HTMLReflectionContext.INERT_TAG,
                        can_break_out=can_break,
                        details=f"Probe reflected inside inert <{tag}> container" + (f" (breaks out with </{tag}>)" if can_break else f" (inert without closing </{tag}> tag)"),
                        recommends_alert=can_break,
                        suggested_severity=FindingSeverity.HIGH if can_break else FindingSeverity.LOW,
                        suggested_confidence=FindingConfidence.CONFIRMED if can_break else FindingConfidence.LOW,
                    )

        # 3. Check if inside <script> tag
        last_script_open = prefix.lower().rfind("<script")
        if last_script_open != -1:
            last_script_close = prefix.lower().rfind("</script>")
            if last_script_close < last_script_open:
                can_break = "</script>" in probe_value.lower() or any(c in probe_value for c in ("'", '"', ";", "`"))
                return ReflectionAnalysis(
                    probe_found=True,
                    context=HTMLReflectionContext.SCRIPT_BLOCK,
                    can_break_out=can_break,
                    details="Probe reflected inside <script> block" + (" (contains unescaped script breakout / syntax delimiters)" if can_break else " (safely encoded or trapped)"),
                    recommends_alert=can_break,
                    suggested_severity=FindingSeverity.HIGH if can_break else FindingSeverity.LOW,
                    suggested_confidence=FindingConfidence.HIGH if can_break else FindingConfidence.LOW,
                )

        # 4. Check if inside an HTML tag attribute: <tag attr="probe" ...>
        last_tag_open = prefix.rfind("<")
        last_tag_close = prefix.rfind(">")
        if last_tag_open > last_tag_close:
            tag_content_prefix = prefix[last_tag_open:]
            attr_match = re.search(r'([a-zA-Z0-9_\-:]+)\s*=\s*([\'"]?)[^\'"]*$', tag_content_prefix)
            attr_name = attr_match.group(1).lower() if attr_match else ""
            quote_char = attr_match.group(2) if attr_match else ""

            if attr_name.startswith("on"):
                return ReflectionAnalysis(
                    probe_found=True,
                    context=HTMLReflectionContext.ATTRIBUTE_EVENT_HANDLER,
                    can_break_out=True,
                    details=f"Probe reflected directly into event handler attribute '{attr_name}', allowing inline JavaScript execution",
                    recommends_alert=True,
                    suggested_severity=FindingSeverity.HIGH,
                    suggested_confidence=FindingConfidence.CONFIRMED,
                )

            if attr_name in {"href", "src", "action", "formaction"}:
                can_break = quote_char in probe_value if quote_char else (" " in probe_value or ">" in probe_value)
                return ReflectionAnalysis(
                    probe_found=True,
                    context=HTMLReflectionContext.ATTRIBUTE_URI,
                    can_break_out=can_break,
                    details=f"Probe reflected in URI attribute '{attr_name}'" + (" (breaks out of attribute)" if can_break else " (trapped in URI attribute)"),
                    recommends_alert=can_break or probe_value.lower().startswith("javascript:"),
                    suggested_severity=FindingSeverity.HIGH if can_break else FindingSeverity.MEDIUM,
                    suggested_confidence=FindingConfidence.HIGH,
                )

            if quote_char in {'"', "'"}:
                can_break = quote_char in probe_value
                return ReflectionAnalysis(
                    probe_found=True,
                    context=HTMLReflectionContext.ATTRIBUTE_VALUE_QUOTED,
                    can_break_out=can_break,
                    details=f"Probe reflected inside quoted attribute '{attr_name}' ({quote_char})" + (f" (breaks out using unescaped {quote_char})" if can_break else f" (safely enclosed; delimiter {quote_char} is escaped)"),
                    recommends_alert=can_break,
                    suggested_severity=FindingSeverity.HIGH if can_break else FindingSeverity.LOW,
                    suggested_confidence=FindingConfidence.CONFIRMED if can_break else FindingConfidence.LOW,
                )

            can_break = any(c in probe_value for c in (" ", ">", "\t", "\n"))
            return ReflectionAnalysis(
                probe_found=True,
                context=HTMLReflectionContext.ATTRIBUTE_VALUE_UNQUOTED,
                can_break_out=can_break,
                details=f"Probe reflected in unquoted attribute '{attr_name}'" + (" (breaks out with whitespace/closing delimiter)" if can_break else " (safely bounded)"),
                recommends_alert=can_break,
                suggested_severity=FindingSeverity.HIGH if can_break else FindingSeverity.LOW,
                suggested_confidence=FindingConfidence.CONFIRMED if can_break else FindingConfidence.LOW,
            )

        # 5. Default: HTML body between tags
        can_break = "<" in probe_value and ">" in probe_value
        return ReflectionAnalysis(
            probe_found=True,
            context=HTMLReflectionContext.HTML_BODY,
            can_break_out=can_break,
            details="Probe reflected directly in HTML body context" + (" with unescaped HTML tag delimiters (< >)" if can_break else " without unescaped tag delimiters (< >)"),
            recommends_alert=can_break,
            suggested_severity=FindingSeverity.HIGH if can_break else FindingSeverity.LOW,
            suggested_confidence=FindingConfidence.CONFIRMED if can_break else FindingConfidence.LOW,
        )


class JavaScriptDataFlowAnalyzer:
    """
    Lightweight static source-to-sink data flow analyzer for frontend JavaScript bundles.
    Detects DOM-based Cross-Site Scripting (CWE-79) and Client-Side Open Redirects (CWE-601).
    """

    DOM_SOURCES = [
        r"location\.search",
        r"location\.hash",
        r"location\.href",
        r"location\.pathname",
        r"document\.URL",
        r"document\.documentURI",
        r"document\.referrer",
        r"window\.name",
    ]

    DOM_XSS_SINKS = [
        (r"\.innerHTML\s*=", "innerHTML assignment"),
        (r"\.outerHTML\s*=", "outerHTML assignment"),
        (r"document\.write\s*\(", "document.write invocation"),
        (r"document\.writeln\s*\(", "document.writeln invocation"),
        (r"\beval\s*\(", "eval invocation"),
        (r"setTimeout\s*\([^,)]*?,", "setTimeout invocation with dynamic code"),
        (r"setInterval\s*\([^,)]*?,", "setInterval invocation with dynamic code"),
        (r"new\s+Function\s*\(", "Function constructor execution"),
    ]

    DOM_REDIRECT_SINKS = [
        (r"location(?:\.href)?\s*=", "location.href assignment"),
        (r"location\.(?:assign|replace)\s*\(", "location navigation method"),
        (r"window\.location(?:\.href)?\s*=", "window.location assignment"),
        (r"window\.open\s*\(", "window.open invocation"),
    ]

    @classmethod
    def analyze_script(cls, script_url, script_text, scan_id=None):
        from src.adapters.javascript_analysis import analyze_flows
        return analyze_flows(script_url, script_text, scan_id)


class DifferentialAccessEvaluator:
    """
    Evaluates multi-state and identifier differential responses to detect genuine
    Broken Object-Level Authorization (BOLA/IDOR - CWE-639) while suppressing
    false positives caused by public catalogs, blogs, and soft-404 errors.
    """

    PUBLIC_CATALOG_INDICATORS = {
        "product", "item", "catalog", "shop", "store", "article", "post",
        "blog", "news", "doc", "document", "category", "topic", "faq", "listing"
    }

    SOFT_404_INDICATORS = (
        "not found", "item not found", "does not exist", "record not found",
        "invalid id", "error 404", "could not find", "no results found",
        "page not found", "resource not found", "cannot find the requested"
    )

    PRIVATE_DATA_PATTERNS = [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", "email address"),
        (r"\b(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?\d{3}[-. ]?\d{4}\b", "phone number"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "social security / tax number"),
        (r"""["'](?:password|password_hash|passwd|secret|token|api_key|access_token|private_key)["']\s*:\s*["'][^"']+["']""", "credential or secret token"),
        (r"""["'](?:balance|credit_card|card_number|cvv|account_balance|billing_address)["']\s*:""", "financial or billing data"),
        (r"""["'](?:ssn|user_id|member_id|customer_id|tenant_id)["']\s*:\s*(?:[0-9]+|["'][^"']+["'])""", "identity / tenant record identifier"),
    ]

    @classmethod
    def evaluate_object_access(cls, baseline_response, probe_response, parameter, original_val, probe_val):
        return {"is_vulnerable": False, "confidence": FindingConfidence.LOW, "severity": FindingSeverity.INFO,
                "reason": "Response/size differences do not establish object ownership or expected denial; use the declared multi-identity session review.",
                "leaked_fields": [], "is_public_catalog": False, "is_soft_404": False}


class WebAuditorAdapter(BaseToolAdapter):
    """
    Comprehensive Python-native Web Security Auditor.
    Performs OWASP-aligned passive and safe active checks against target web applications.
    """

    name: str = "Web Security Auditor"
    version: str = "2.1.0 (Scoped Safe DAST)"

    def __init__(self, cve_engine: Optional[CVEIntelligenceEngine] = None):
        super().__init__("native_python")
        self.cve_engine = cve_engine or CVEIntelligenceEngine()
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) III85III-OBSIDIAN/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self._scan_metrics: Dict[str, Any] = {}
        self._coverage = CoverageLedger()
        self._browser_checks: List[Dict[str, Any]] = []
        self._hypotheses = []

    def detect(self) -> ToolHealthInfo:
        return ToolHealthInfo(
            name=self.name,
            installed=True,
            version=self.version,
            path="Internal Adapter",
            status_message=f"Ready: bounded same-origin crawl, safe GET-only checks, max {MAX_CRAWL_PAGES} pages.",
            availability_status="INSTALLED_AND_VERIFIED",
        )

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        """Ensure the URL has a scheme and valid host."""
        url = raw_url.strip()
        if "://" not in url:
            url = "http://" + url
        return url

    @classmethod
    def validate_target_url(cls, raw_url: str) -> Tuple[bool, str, str]:
        """Validate one HTTP(S) base URL before any network request is made."""
        if not isinstance(raw_url, str) or not raw_url.strip():
            return False, "Target URL is empty.", ""
        try:
            normalized = cls.normalize_url(raw_url)
            parsed = urlparse(normalized)
            _ = parsed.port  # Raises ValueError for malformed/out-of-range ports.
        except ValueError:
            return False, "Target URL is malformed.", ""
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or any(char.isspace() for char in normalized)
        ):
            return False, "Use an HTTP or HTTPS base URL without credentials, query strings, or fragments.", ""
        return True, "Valid HTTP/S base URL.", normalized

    def audit_url(
        self,
        target_url: str,
        scan_id: Optional[str] = None,
        progress_callback: Optional[Any] = None,
        deep_scan: bool = False,
    ) -> List[Finding]:
        """
        Run bounded web security checks:
        1. Transport Security & HTTPS verification
        2. Security headers (HSTS, CSP, clickjacking, and content-type options)
        3. Information Disclosure & Server Fingerprinting
        4. Cookie HttpOnly and Secure attributes
        5. Selected sensitive-file exposure checks
        6. Bounded same-origin input inventory and optional safe GET probes
        7. CVE correlation for detected components
        """
        findings: List[Finding] = []
        self._coverage = CoverageLedger()
        self._hypotheses = []
        self._browser_checks = []
        self._discovered_endpoints = []
        self._collected_scripts_text = []
        self._untested_checks = []
        self._application_map = ApplicationMap(target_url)
        self._authorized_origin = map_origin(target_url)
        self._request_attempts = 0
        self._collection_stop = None
        self._request_evidence = []
        self._next_request_at = 0
        valid_target, validation_message, url = self.validate_target_url(target_url)
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or url
        except ValueError:
            parsed = urlparse("")
            domain = url

        if not valid_target:
            return [Finding(
                scan_id=scan_id,
                title="Web audit target rejected by URL policy",
                description=validation_message,
                source_tool=self.name,
                tool_version=self.version,
                target=domain,
                severity=FindingSeverity.INFO,
                severity_source="Target URL validation policy",
                confidence=FindingConfidence.CONFIRMED,
                confidence_justification="The URL did not pass the scanner's target URL validation.",
                status=FindingStatus.FAILED_COLLECTION,
                evidence_raw="Target rejected before any network request was sent.",
                evidence_summary="No traffic was sent because the target URL is invalid.",
                remediation="Enter an HTTP or HTTPS base URL for a target you own or have explicit authorization to assess.",
            )]

        traffic = getattr(self, "_traffic_plan", None)
        if traffic:
            findings.append(Finding(scan_id=scan_id, title="Imported HTTP traffic route inventory", description="Routes observed in an operator-supplied HAR, not a live scan or proof of vulnerability. Captured headers, cookies, bodies and query values were discarded.",
                source_tool="HAR route discovery", target=url, severity=FindingSeverity.INFO,
                severity_source="Supplied capture metadata", confidence=FindingConfidence.HIGH,
                confidence_justification="Parsed bounded HAR with a source SHA-256; live reachability and identity not inferred.",
                status=FindingStatus.OBSERVED, evidence_raw=json.dumps(traffic),
                evidence_summary=f"{len(traffic['routes'])} in-scope routes; synthetic probes enabled={getattr(self, '_traffic_probes', False)}",
                remediation="Review scope, read-only semantics and synthetic-account prerequisites before testing imported routes."))
            for item in traffic["routes"]:
                context = "captured-authenticated-not-replayed" if item["authentication_recorded"] else "anonymous"
                prior_nodes = set(self._application_map.nodes)
                key = self._application_map.add(item["url"], "imported_route", method=item["method"])
                if key:
                    # Keep credential-context observations distinct even when URL/method match.
                    if context != "anonymous":
                        node = dict(self._application_map.nodes[key])
                        if key not in prior_nodes:
                            self._application_map.nodes.pop(key)
                        if len(self._application_map.nodes) >= self._application_map.MAX_NODES:
                            self._application_map.truncated = True
                            continue
                        key += "-authenticated"
                        node["id"] = key
                        self._application_map.nodes[key] = node
                    self._application_map.nodes[key]["identity_context"] = context
                    self._application_map.nodes[key]["capture_source_sha256"] = traffic["source_sha256"]
            self._coverage.record("HAR route discovery", "COMPLETED", "Offline metadata parsed; no captured requests or credentials replayed.", 0)

        if progress_callback:
            progress_callback(f"Connecting to {url}...")

        # 1. Transport Security (HTTP vs HTTPS)
        if parsed.scheme == "http":
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Insecure Unencrypted Transport (HTTP) on {domain}",
                    description=(
                        f"The target URL '{url}' uses unencrypted HTTP. Data sent over this connection is not protected by TLS; "
                        "the scan did not submit credentials or test for interception."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.MEDIUM,
                    severity_source="OWASP Transport Layer Protection",
                    confidence=FindingConfidence.HIGH,
                    confidence_justification="URL scheme is explicitly http://",
                    status=FindingStatus.OBSERVED,
                    evidence_raw=f"Scheme: {parsed.scheme}://{parsed.netloc}",
                    evidence_summary="Plaintext HTTP transmission without TLS encryption.",
                    remediation="Migrate the service to HTTPS and redirect all HTTP traffic to HTTPS via 301 redirects.",
                )
            )

        # Send initial request
        try:
            resp = self._bounded_get(url, timeout=10)
        except requests.RequestException as exc:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Connection Failure to Web Target: {url}",
                    description=f"Could not establish HTTP connection to target: {str(exc)}",
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.INFO,
                    severity_source="Network Socket Check",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification=str(exc),
                    status=FindingStatus.FAILED_COLLECTION,
                    evidence_raw=str(exc),
                    evidence_summary="Target host unreachable or refused connection.",
                    remediation="Verify target host is online, reachable, and firewall allows port 80/443.",
                )
            )
            return findings

        headers = resp.headers
        if resp.status_code in {429, 503} or self._cancelled():
            return findings

        # Crawl a bounded number of same-origin HTML pages. The crawler issues
        # GET requests only; it never submits forms or follows redirects.
        inventory = self._covered_operation("Same-origin application mapping", self._crawl_same_origin, url, resp, progress_callback)
        if inventory["pages"]:
            findings.append(self._inventory_finding(url, scan_id, inventory))
            password_forms = inventory["http_password_forms"]
            if password_forms:
                findings.append(Finding(
                    scan_id=scan_id,
                    title=f"Password form served over unencrypted HTTP on {domain}",
                    description=(
                        f"The same-origin crawl found {password_forms} HTML password form(s) served over HTTP. "
                        "A browser may submit credentials without transport encryption. OBSIDIAN did not submit any form."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.HIGH,
                    severity_source="Observed HTTP origin and password input field",
                    confidence=FindingConfidence.HIGH,
                    confidence_justification="The page response was served over HTTP and contained an input[type=password]; no credentials were entered or transmitted by OBSIDIAN.",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=json.dumps({"password_forms": password_forms, "page_paths": inventory["password_form_paths"][:20]}, ensure_ascii=False),
                    evidence_summary=f"{password_forms} password form(s) found; forms were not submitted.",
                    cwe_id="CWE-319",
                    remediation="Serve login pages and credential submission endpoints only over HTTPS, and configure HSTS after validating HTTPS deployment.",
                ))

        # A harmless, unpredictable Origin value detects permissive CORS
        # reflection without sending credentials or modifying target state.
        if deep_scan:
            if progress_callback:
                progress_callback("Checking CORS policy and safe query-parameter probes...")
            findings.extend(self._covered_operation("CORS origin controls", self._check_cors, url, scan_id))
            # (Parameter probing scheduled after JS asset and endpoint discovery)

        # Frontend JavaScript Assets & Endpoints Analysis
        if inventory.get("scripts"):
            findings.extend(self._covered_operation("JavaScript and source maps", self._audit_javascript_assets, url, inventory["scripts"], scan_id, progress_callback))

        # Merge discovered API endpoints into input points for active parameter testing
        discovered_input_points = list(inventory.get("input_points", []))
        if traffic:
            if getattr(self, "_traffic_probes", False):
                # A HAR may repeat a live-discovered route. Prefer its real
                # crawl defaults; do not run a second synthetic copy of that signature.
                live_signatures = {map_safe_url(point["url"]) for point in discovered_input_points}
                discovered_input_points.extend(point for point in synthetic_input_points(traffic)
                    if map_safe_url(point["url"]) not in live_signatures)
            else:
                self._coverage.record("HAR synthetic query checks", "BLOCKED", "Operator has not approved read-only synthetic probes for imported routes.")
        if hasattr(self, "_discovered_endpoints") and self._discovered_endpoints:
            for ep in self._discovered_endpoints:
                if len(discovered_input_points) >= MAX_ACTIVE_PARAMETERS:
                    break
                ep_parsed = urlparse(ep)
                if ep_parsed.query:
                    names = list(dict.fromkeys(name for name, _ in parse_qsl(ep_parsed.query, keep_blank_values=True) if name))
                    if names:
                        ep_url = urljoin(url, ep)
                        discovered_input_points.append({
                            "url": ep_url,
                            "names": names[:MAX_ACTIVE_PARAMETERS],
                        })

        for point in discovered_input_points:
            self._application_map.add(point["url"], "input_route", method="GET")
        if deep_scan:
            findings.extend(self._covered_operation("Discovered GET input checks", self._probe_query_parameters, discovered_input_points, scan_id, progress_callback))

        # 2. Security Headers Audit
        if progress_callback:
            progress_callback("Auditing HTTP security headers...")

        # A. Content-Security-Policy (CSP)
        if "Content-Security-Policy" not in headers:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Missing Content-Security-Policy (CSP) on {domain}",
                    description=(
                        "The application does not enforce a Content-Security-Policy (CSP) header. "
                        "A suitable CSP provides defense in depth against script injection. "
                        "This missing header alone does not establish XSS or prove script execution."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.MEDIUM,
                    severity_source="OWASP Secure Headers Project",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification="Header 'Content-Security-Policy' is absent from HTTP response",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=str(self._safe_headers(headers)),
                    evidence_summary="Missing header: Content-Security-Policy",
                    cwe_id="CWE-1021",
                    remediation="Implement a robust Content-Security-Policy header, e.g.: default-src 'self'; script-src 'self';",
                )
            )

        # B. Strict-Transport-Security (HSTS)
        if parsed.scheme == "https" and "Strict-Transport-Security" not in headers:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Missing HTTP Strict Transport Security (HSTS) on {domain}",
                    description=(
                        "The HTTPS application lacks the 'Strict-Transport-Security' header. "
                        "This permits SSL-stripping attacks where a local attacker downgrades the user's connection to HTTP."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.MEDIUM,
                    severity_source="OWASP Top 10 A02:2021 Cryptographic Failures",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification="Header 'Strict-Transport-Security' is absent on HTTPS response",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=str(self._safe_headers(headers)),
                    evidence_summary="Missing header: Strict-Transport-Security",
                    cwe_id="CWE-319",
                    remediation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                )
            )

        # C. X-Frame-Options (Clickjacking)
        csp_policy = headers.get("Content-Security-Policy", "").lower()
        if "X-Frame-Options" not in headers and "frame-ancestors" not in csp_policy:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Missing Clickjacking Defense (X-Frame-Options) on {domain}",
                    description=(
                        "Neither 'X-Frame-Options' nor a CSP 'frame-ancestors' directive was provided. "
                        "The application can be embedded in an attacker's iframe, exposing users to UI redressing (Clickjacking)."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.LOW,
                    severity_source="OWASP Clickjacking Defense",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification="Header 'X-Frame-Options' is missing",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=str(self._safe_headers(headers)),
                    evidence_summary="Missing header: X-Frame-Options",
                    cwe_id="CWE-1021",
                    remediation="Add header: X-Frame-Options: SAMEORIGIN or DENY",
                )
            )

        # D. X-Content-Type-Options
        if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Missing X-Content-Type-Options: nosniff on {domain}",
                    description=(
                        "The 'X-Content-Type-Options: nosniff' header prevents browsers from MIME-sniffing "
                        "a response away from the declared content-type, preventing executable content in images."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.LOW,
                    severity_source="OWASP Secure Headers Project",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification="Header 'X-Content-Type-Options: nosniff' missing or misconfigured",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=f"X-Content-Type-Options: {headers.get('X-Content-Type-Options', 'NOT_SET')}",
                    evidence_summary="Missing X-Content-Type-Options: nosniff",
                    remediation="Configure web server to return: X-Content-Type-Options: nosniff",
                )
            )

        # E. Referrer-Policy
        if "Referrer-Policy" not in headers:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Missing Referrer-Policy Header on {domain}",
                    description=(
                        "The application does not specify a 'Referrer-Policy' header. "
                        "When navigating to third-party links, sensitive URL parameters or internal tokens may leak in the HTTP Referer header."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.LOW,
                    severity_source="OWASP Secure Headers Project",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification="Header 'Referrer-Policy' is absent from HTTP response",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=str(self._safe_headers(headers)),
                    evidence_summary="Missing header: Referrer-Policy",
                    cwe_id="CWE-116",
                    remediation="Add header: Referrer-Policy: strict-origin-when-cross-origin",
                )
            )

        # F. Permissions-Policy
        if "Permissions-Policy" not in headers and "Feature-Policy" not in headers:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Missing Permissions-Policy Header on {domain}",
                    description=(
                        "The application does not set a 'Permissions-Policy' header to restrict browser features "
                        "(e.g., camera, microphone, geolocation, payment). "
                        "Defining a restrictive policy strengthens defense against malicious third-party scripts."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.INFO,
                    severity_source="W3C Permissions Policy",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification="Headers 'Permissions-Policy' and 'Feature-Policy' are missing",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=str(self._safe_headers(headers)),
                    evidence_summary="Missing header: Permissions-Policy",
                    cwe_id="CWE-1021",
                    remediation="Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                )
            )

        # 3. Information Disclosure & Server Fingerprinting
        if progress_callback:
            progress_callback("Analyzing technology stack & information leakage...")

        server_banner = headers.get("Server", "")
        if server_banner:
            # Check if version numbers are disclosed
            if re.search(r"[0-9]+\.[0-9]+", server_banner):
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"Detailed Server Banner Disclosed ({server_banner}) on {domain}",
                        description=(
                            f"The web server exposes its detailed version via the 'Server' header: '{server_banner}'. "
                            "This simplifies automated vulnerability matching for attackers."
                        ),
                        source_tool=self.name,
                        tool_version=self.version,
                        target=url,
                        severity=FindingSeverity.LOW,
                        severity_source="OWASP Information Disclosure",
                        confidence=FindingConfidence.CONFIRMED,
                        confidence_justification=f"Server header received: '{server_banner}'",
                        status=FindingStatus.OBSERVED,
                        evidence_raw=f"Server: {server_banner}",
                        evidence_summary=f"Banner leakage: {server_banner}",
                        affected_component=server_banner,
                        remediation="Configure server tokens to minimal/off (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).",
                    )
                )
                # Correlate with CVE Intelligence!
                cve_matches = self.cve_engine.correlate_component(server_banner, "", url, scan_id)
                findings.extend(cve_matches)

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"Technology Stack Disclosure via X-Powered-By ({powered_by}) on {domain}",
                    description=(
                        f"The header 'X-Powered-By: {powered_by}' reveals underlying backend frameworks "
                        "(e.g., PHP, ASP.NET, Express). This information aids targeted exploits."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.LOW,
                    severity_source="OWASP Information Exposure",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification=f"X-Powered-By header: '{powered_by}'",
                    status=FindingStatus.OBSERVED,
                    evidence_raw=f"X-Powered-By: {powered_by}",
                    evidence_summary=f"Backend disclosed: {powered_by}",
                    affected_component=powered_by,
                    remediation="Disable the X-Powered-By header in application configuration (e.g. expose_php = Off).",
                )
            )

        # 4. Cookie Security Flags Audit
        if progress_callback:
            progress_callback("Auditing cookie security flags...")

        for cookie in resp.cookies:
            c_name = cookie.name
            c_secure = cookie.secure
            c_httponly = cookie.has_nonstandard_attr("httponly") or "httponly" in cookie._rest

            if not c_httponly:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"Cookie '{c_name}' Missing HttpOnly Flag on {domain}",
                        description=(
                            f"The cookie '{c_name}' was set without the 'HttpOnly' flag. "
                            "JavaScript running in the browser can read this cookie, making session tokens vulnerable to XSS theft."
                        ),
                        source_tool=self.name,
                        tool_version=self.version,
                        target=f"{url} [cookie:{c_name}]",
                        severity=FindingSeverity.MEDIUM,
                        severity_source="OWASP Session Management",
                        confidence=FindingConfidence.CONFIRMED,
                        confidence_justification="Cookie Set-Cookie header lacks HttpOnly attribute",
                        status=FindingStatus.SCANNER_REPORTED,
                        evidence_raw=str({"name": c_name, "secure": c_secure, "httponly": c_httponly, "value": "[NOT STORED]"}),
                        evidence_summary=f"Cookie {c_name}: HttpOnly=False",
                        cwe_id="CWE-1004",
                        affected_component=f"Cookie:{c_name}",
                        remediation="Set the 'HttpOnly' flag on all session and sensitive cookies.",
                    )
                )

            if parsed.scheme == "https" and not c_secure:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"Cookie '{c_name}' Missing Secure Flag on {domain}",
                        description=(
                            f"The cookie '{c_name}' was transmitted over HTTPS without the 'Secure' attribute. "
                            "Browsers may send this cookie in subsequent unencrypted HTTP requests."
                        ),
                        source_tool=self.name,
                        tool_version=self.version,
                        target=f"{url} [cookie:{c_name}]",
                        severity=FindingSeverity.MEDIUM,
                        severity_source="OWASP Session Management",
                        confidence=FindingConfidence.CONFIRMED,
                        confidence_justification="Cookie Set-Cookie header lacks Secure attribute",
                        status=FindingStatus.SCANNER_REPORTED,
                        evidence_raw=str({"name": c_name, "secure": c_secure, "httponly": c_httponly, "value": "[NOT STORED]"}),
                        evidence_summary=f"Cookie {c_name}: Secure=False",
                        cwe_id="CWE-614",
                        affected_component=f"Cookie:{c_name}",
                        remediation="Set the 'Secure' flag on all cookies transmitted over HTTPS.",
                    )
                )

            c_samesite = None
            if hasattr(cookie, "has_nonstandard_attr") and cookie.has_nonstandard_attr("samesite"):
                c_samesite = cookie.get_nonstandard_attr("samesite")
            elif "samesite" in getattr(cookie, "_rest", {}):
                c_samesite = cookie._rest["samesite"]

            if not c_samesite:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"Cookie '{c_name}' Missing SameSite Attribute on {domain}",
                        description=(
                            f"The cookie '{c_name}' does not declare a 'SameSite' attribute. "
                            "Configuring SameSite=Lax or SameSite=Strict provides browser-level defense in depth against CSRF."
                        ),
                        source_tool=self.name,
                        tool_version=self.version,
                        target=f"{url} [cookie:{c_name}]",
                        severity=FindingSeverity.LOW,
                        severity_source="OWASP Session Management",
                        confidence=FindingConfidence.CONFIRMED,
                        confidence_justification="Cookie Set-Cookie header lacks SameSite attribute",
                        status=FindingStatus.SCANNER_REPORTED,
                        evidence_raw=str({"name": c_name, "samesite": "NOT_SET", "secure": c_secure}),
                        evidence_summary=f"Cookie {c_name}: SameSite=Not Set",
                        cwe_id="CWE-1275",
                        affected_component=f"Cookie:{c_name}",
                        remediation="Set SameSite=Lax or SameSite=Strict on all sensitive session cookies.",
                    )
                )

        # 5. Sensitive File & Endpoint Probing (Safe Heuristic Checks)
        if progress_callback:
            progress_callback("Checking sensitive file & endpoint exposures...")

        sensitive_paths = [
            ("robots.txt", "Robots Exclusion File"),
            (".git/HEAD", "Exposed Git Repository Metadata"),
            (".env", "Exposed Environment Configuration File"),
            (".well-known/security.txt", "Security Disclosure Contact File"),
            ("sitemap.xml", "Sitemap XML File"),
            ("actuator/health", "Spring Boot Actuator Health Endpoint"),
            ("actuator/env", "Spring Boot Actuator Environment Endpoint"),
            ("actuator", "Spring Boot Actuator Base Endpoint"),
            ("swagger-ui.html", "Swagger UI Documentation"),
            ("swagger-ui/index.html", "Swagger UI Interactive Console"),
            ("graphql", "GraphQL API Endpoint"),
            ("composer.json", "PHP Composer Dependency Manifest"),
            ("package.json", "Node.js Dependency Manifest"),
        ]

        for s_path, s_desc in sensitive_paths:
            test_url = urljoin(url, s_path)
            try:
                s_resp = self._bounded_get(test_url, timeout=5)
                if s_resp.status_code == 200 and len(s_resp.text.strip()) > 0:
                    body_sample = s_resp.text[:300]

                    # Specific validations
                    if s_path == ".git/HEAD" and "ref: refs/" in body_sample:
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                title=f"Potentially Exposed Git Metadata at {test_url}",
                                description=(
                                    f"The endpoint '{test_url}' returned a Git HEAD signature. This confirms metadata exposure, "
                                    "but this check did not verify that repository objects, source files, or commit history are downloadable."
                                ),
                                source_tool=self.name,
                                tool_version=self.version,
                                target=test_url,
                                severity=FindingSeverity.MEDIUM,
                                severity_source="Potential source-control metadata exposure",
                                confidence=FindingConfidence.MEDIUM,
                                confidence_justification="Response matches 'ref: refs/' Git signature",
                                status=FindingStatus.SCANNER_REPORTED,
                                evidence_raw=json.dumps({"status_code": 200, "signature": "git_ref_head", "body_sha256": hashlib.sha256(s_resp.content).hexdigest()}),
                                evidence_summary="HTTP 200 matched the Git HEAD signature; response body was not stored.",
                                cwe_id="CWE-538",
                                remediation="Block public access to .git directories in web server rules immediately.",
                            )
                        )
                    elif s_path == ".env" and ("=" in body_sample and ("KEY" in body_sample or "SECRET" in body_sample or "PASS" in body_sample or "DB" in body_sample)):
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                title=f"Potentially Exposed Environment Configuration at {test_url}",
                                description=(
                                    f"The endpoint '{test_url}' returned environment-assignment markers. "
                                    "The response body was discarded, so the presence of real credentials was not verified."
                                ),
                                source_tool=self.name,
                                tool_version=self.version,
                                target=test_url,
                                severity=FindingSeverity.HIGH,
                                severity_source="OWASP A05:2021 Security Misconfiguration",
                                confidence=FindingConfidence.MEDIUM,
                                confidence_justification="Response contains environment assignment syntax",
                                status=FindingStatus.SCANNER_REPORTED,
                                evidence_raw=json.dumps({"status_code": 200, "signature": "environment_assignment_markers", "body_sha256": hashlib.sha256(s_resp.content).hexdigest(), "body": "[NOT STORED]"}),
                                evidence_summary="HTTP 200 matched environment assignment markers; response body and secret values were not stored.",
                                cwe_id="CWE-552",
                                remediation="Deny web access to .env and keep environment files outside web root.",
                            )
                        )
                    elif s_path == "robots.txt":
                        disallows = re.findall(r"Disallow:\s*([^\r\n]+)", s_resp.text)
                        if disallows:
                            findings.append(
                                Finding(
                                    scan_id=scan_id,
                                    title=f"Robots.txt Discloses {len(disallows)} Restricted Paths on {domain}",
                                    description=(
                                        f"The robots.txt file reveals paths intended to be hidden:\n"
                                        f"{', '.join(disallows[:10])}\n"
                                        "Robots.txt does not enforce access control and is commonly harvested by attackers."
                                    ),
                                    source_tool=self.name,
                                    tool_version=self.version,
                                    target=test_url,
                                    severity=FindingSeverity.INFO,
                                    severity_source="Robots.txt Analysis",
                                    confidence=FindingConfidence.CONFIRMED,
                                    confidence_justification="Direct HTTP 200 response from /robots.txt",
                                    status=FindingStatus.OBSERVED,
                                    evidence_raw=s_resp.text[:500],
                                    evidence_summary=f"Found {len(disallows)} Disallow rules in robots.txt",
                                    remediation="Ensure sensitive administrative routes enforce strict server-side authorization.",
                                )
                            )
                    elif s_path == "sitemap.xml" and ("<urlset" in body_sample.lower() or "<sitemapindex" in body_sample.lower()):
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                title=f"Public Sitemap XML Exposed at {test_url}",
                                description=f"The sitemap file '{test_url}' exposes public URLs and endpoints for indexing.",
                                source_tool=self.name,
                                tool_version=self.version,
                                target=test_url,
                                severity=FindingSeverity.INFO,
                                severity_source="Sitemap Discovery",
                                confidence=FindingConfidence.CONFIRMED,
                                confidence_justification="HTTP 200 containing valid XML sitemap tags",
                                status=FindingStatus.OBSERVED,
                                evidence_raw=s_resp.text[:500],
                                evidence_summary="Valid sitemap.xml discovered on target host",
                                remediation="Review exposed sitemap paths to ensure private administrative or staging endpoints are not listed.",
                                )
                            )
                    elif s_path == "actuator/env" and ("propertysources" in body_sample.lower() or "activeprofiles" in body_sample.lower()):
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                title=f"Exposed Spring Boot Actuator Environment at {test_url}",
                                description=(
                                    f"The endpoint '{test_url}' exposes Spring Boot environment properties without authentication. "
                                    "This can reveal server environment variables, configuration parameters, and application metadata."
                                ),
                                source_tool=self.name,
                                tool_version=self.version,
                                target=test_url,
                                severity=FindingSeverity.HIGH,
                                severity_source="OWASP A05:2021 Security Misconfiguration",
                                confidence=FindingConfidence.CONFIRMED,
                                confidence_justification="HTTP 200 with Spring Boot propertySources JSON structure",
                                status=FindingStatus.SCANNER_REPORTED,
                                evidence_raw=json.dumps({"status_code": 200, "sample": body_sample[:150]}, ensure_ascii=False),
                                evidence_summary="Spring Boot actuator/env exposed publicly",
                                cwe_id="CWE-200",
                                remediation="Restrict Spring Boot actuator endpoints to internal management networks or require strong authentication.",
                            )
                        )
                    elif s_path in {"actuator", "actuator/health"} and ("\"status\"" in body_sample.lower() or "\"_links\"" in body_sample.lower()):
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                title=f"Exposed Spring Boot Actuator at {test_url}",
                                description=f"The endpoint '{test_url}' exposes Spring Boot actuator management metadata.",
                                source_tool=self.name,
                                tool_version=self.version,
                                target=test_url,
                                severity=FindingSeverity.LOW,
                                severity_source="OWASP Information Exposure",
                                confidence=FindingConfidence.CONFIRMED,
                                confidence_justification="HTTP 200 matching Spring Boot Actuator response markers",
                                status=FindingStatus.OBSERVED,
                                evidence_raw=body_sample[:150],
                                evidence_summary="Spring Boot Actuator endpoint accessible",
                                cwe_id="CWE-200",
                                remediation="Ensure sensitive actuator endpoints are excluded in application.properties (e.g., management.endpoints.web.exposure.include=health,info).",
                            )
                        )
                    elif "swagger-ui" in s_path and ("swagger-ui" in body_sample.lower() or "id=\"swagger-ui\"" in body_sample.lower()):
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                title=f"Exposed Interactive Swagger UI at {test_url}",
                                description=(
                                    f"Interactive API documentation was discovered at '{test_url}'. "
                                    "Swagger UI documents application endpoints and parameters, allowing attackers to map full API capabilities."
                                ),
                                source_tool=self.name,
                                tool_version=self.version,
                                target=test_url,
                                severity=FindingSeverity.LOW,
                                severity_source="OWASP Information Exposure",
                                confidence=FindingConfidence.CONFIRMED,
                                confidence_justification="HTML contains Swagger UI container markers",
                                status=FindingStatus.OBSERVED,
                                evidence_raw=body_sample[:150],
                                evidence_summary="Public Swagger UI interactive console found",
                                cwe_id="CWE-200",
                                remediation="Disable Swagger UI in production environments or place it behind authentication.",
                            )
                        )
                    elif s_path in {"composer.json", "package.json"} and ("\"require\"" in body_sample.lower() or "\"dependencies\"" in body_sample.lower()):
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                title=f"Exposed Dependency Manifest ({s_path}) at {test_url}",
                                description=f"The dependency manifest file '{s_path}' is publicly accessible, disclosing exact library names and versions.",
                                source_tool=self.name,
                                tool_version=self.version,
                                target=test_url,
                                severity=FindingSeverity.LOW,
                                severity_source="OWASP Information Disclosure",
                                confidence=FindingConfidence.CONFIRMED,
                                confidence_justification=f"HTTP 200 containing {s_path} package definitions",
                                status=FindingStatus.OBSERVED,
                                evidence_raw=body_sample[:200],
                                evidence_summary=f"Public {s_path} exposes package dependencies",
                                cwe_id="CWE-200",
                                remediation="Block public access to package.json, composer.json, and lockfiles via web server rules.",
                            )
                        )
                        findings.extend(self._audit_dependency_manifest(test_url, s_path, s_resp.text, scan_id))
                    elif s_path == "graphql":
                        try:
                            g_resp = self._bounded_get(test_url + "?" + urlencode({"query": "{ __schema { types { name } } }"}), timeout=5)
                            if g_resp.status_code == 200 and "__schema" in g_resp.text:
                                findings.append(
                                    Finding(
                                        scan_id=scan_id,
                                        title=f"GraphQL Introspection Schema Enabled at {test_url}",
                                        description=(
                                            f"The GraphQL endpoint '{test_url}' has schema introspection enabled. "
                                            "Introspection permits querying the entire schema, revealing internal types, fields, queries, and mutations."
                                        ),
                                        source_tool=self.name,
                                        tool_version=self.version,
                                        target=test_url,
                                        severity=FindingSeverity.MEDIUM,
                                        severity_source="OWASP API Security Top 10 API8:2023 Security Misconfiguration",
                                        confidence=FindingConfidence.CONFIRMED,
                                        confidence_justification="GET query returned a schema-shaped introspection response; permissions and impact not established",
                                        status=FindingStatus.SCANNER_REPORTED,
                                        evidence_raw=g_resp.text[:300],
                                        evidence_summary="GraphQL introspection enabled and queryable",
                                        cwe_id="CWE-200",
                                        remediation="Disable GraphQL introspection in production environments.",
                                    )
                                )
                        except requests.RequestException:
                            pass
            except requests.RequestException as exc:
                if self._scan_metrics and not isinstance(exc, requests.RequestException) and len(self._scan_metrics["errors"]) < 20:
                    self._scan_metrics["errors"].append(type(exc).__name__)
                continue

        # 6. Passive Certificate Transparency Subdomain Intelligence
        findings.extend(self._audit_subdomains(domain, scan_id, progress_callback))

        # 7. Form Anti-CSRF Audit
        if inventory.get("csrf_forms"):
            findings.extend(self._audit_csrf_forms(domain, inventory.get("csrf_forms", []), resp.cookies, scan_id))

        # 8. JWT Security Audit across headers, cookies, and scripts
        findings.extend(self._audit_jwt_tokens(url, resp.cookies, headers, getattr(self, "_collected_scripts_text", []), scan_id))

        # 9. BFLA & HTTP Method Tampering (for deep_scan)
        if deep_scan:
            findings.extend(self._covered_operation("GET and HEAD status comparison", self._audit_bfla_and_verbs, url, scan_id, progress_callback))

        # 10. Excessive Data Exposure Audit for discovered API routes
        disc_eps = getattr(self, "_discovered_endpoints", [])
        if disc_eps:
            findings.extend(self._covered_operation("Anonymous API response inspection", self._audit_api_data_exposure, url, disc_eps, scan_id))

        return findings

    def _bounded_get(self, url: str, timeout: int, headers: Optional[Dict[str, str]] = None, method: str = "GET") -> Any:
        """Fetch a response without redirects and cap its in-memory body size."""
        if self._cancelled():
            raise requests.RequestException("Assessment cancelled")
        if getattr(self, "_collection_stop", None):
            raise requests.RequestException("Collection stopped after a target backpressure response")
        if method not in {"GET", "HEAD"}:
            raise requests.RequestException("Unsupported collection method")
        if getattr(self, "_authorized_origin", None) and map_origin(url) != self._authorized_origin:
            raise requests.RequestException("Out-of-origin request rejected")
        if not read_only_candidate(url):
            raise requests.RequestException("Discovery policy excludes this request")
        self._request_attempts = getattr(self, "_request_attempts", 0) + 1
        if self._request_attempts > 240:
            if self._scan_metrics and "request_budget_exceeded" not in self._scan_metrics["errors"]:
                self._scan_metrics["errors"].append("request_budget_exceeded")
            raise requests.RequestException("Native request budget exhausted")
        time.sleep(max(0, getattr(self, "_next_request_at", 0) - time.monotonic()))
        if self._cancelled():
            raise requests.RequestException("Assessment cancelled during rate limiting")
        self._next_request_at = time.monotonic() + 0.05
        if self._scan_metrics:
            self._scan_metrics["request_count"] += 1
        try:
            transport = self.session.get if method == "GET" else self.session.head
            response = transport(
                url,
                timeout=(3, timeout),
                allow_redirects=False,
                verify=True,
                stream=True,
                headers=headers,
            )
        except requests.RequestException as exc:
            if self._scan_metrics and len(self._scan_metrics["errors"]) < 20:
                # Exception strings can embed URLs and query values. Persist only
                # a type/name, never the transport library's raw message.
                self._scan_metrics["errors"].append(type(exc).__name__)
            raise
        if self._scan_metrics:
            self._scan_metrics["response_statuses"].append(int(response.status_code))
            if self._scan_metrics["initial_response_status"] is None:
                self._scan_metrics["initial_response_status"] = int(response.status_code)
        chunks: List[bytes] = []
        size = 0
        try:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                remaining = MAX_RESPONSE_BYTES - size
                if remaining <= 0:
                    break
                chunks.append(chunk[:remaining])
                size += min(len(chunk), remaining)
                if size >= MAX_RESPONSE_BYTES:
                    if self._scan_metrics:
                        self._scan_metrics["body_limit_hits"] += 1
                    break
            response._content = b"".join(chunks)
            response._content_consumed = True
        except requests.RequestException as exc:
            if self._scan_metrics:
                self._scan_metrics["body_read_errors"] += 1
                if self._scan_metrics["request_count"] == 1:
                    self._scan_metrics["initial_body_failed"] = True
                if len(self._scan_metrics["errors"]) < 20:
                    self._scan_metrics["errors"].append(type(exc).__name__)
            raise
        finally:
            response.close()
        if response.status_code in {429, 503}:
            self._collection_stop = f"HTTP {response.status_code}: target requested backoff or was unavailable"
            if self._scan_metrics:
                self._scan_metrics["errors"].append("target_backpressure_stop")
        if hasattr(self, "_request_evidence") and len(self._request_evidence) < 240:
            self._request_evidence.append({"method": method, "url": map_safe_url(url), "status": response.status_code,
                "collected_at_utc": datetime.now(timezone.utc).isoformat(), "body_bytes_collected": len(response._content), "response_sha256": hashlib.sha256(response._content).hexdigest()})
        return response

    def _crawl_same_origin(self, start_url: str, first_response: Any, progress_callback: Optional[Any]) -> Dict[str, Any]:
        start = urlparse(start_url)
        origin = self._web_origin(start)
        if origin is None:
            return {"pages": 0, "paths": [], "http_password_forms": 0, "password_form_paths": []}
        queue = deque([(start_url, 0, first_response)])
        visited = set()
        paths: List[str] = []
        password_form_paths: List[str] = []
        input_points: List[Dict[str, Any]] = []
        input_point_keys = set()
        password_forms = 0
        scripts_found: List[str] = []
        csrf_vulnerable_forms: List[Dict[str, Any]] = []

        while queue and len(visited) < MAX_CRAWL_PAGES:
            page_url, depth, response = queue.popleft()
            parsed = urlparse(page_url)
            if not 200 <= response.status_code < 300:
                continue
            key = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
            if key in visited:
                continue
            visited.add(key)
            paths.append(parsed.path or "/")

            content_type = str(response.headers.get("Content-Type", "")).lower()
            if "text/html" not in content_type:
                continue

            parser = _PageInventoryParser()
            try:
                parser.feed(response.text[:MAX_RESPONSE_BYTES])
            except (TypeError, ValueError):
                continue

            page_has_password_form = False
            for form in parser.forms:
                if form["password_field"]:
                    password_forms += 1
                    page_has_password_form = True
                if form["method"] == "post" and not form["has_csrf_token"]:
                    csrf_vulnerable_forms.append({
                        "page": parsed.path or "/",
                        "action": form["action"] or parsed.path or "/",
                        "fields": form.get("fields", [])[:8],
                    })
                if form["method"] == "get" and form.get("fields"):
                    form_action = urljoin(page_url, form.get("action") or parsed.path or "/")
                    fa_parsed = urlparse(form_action)
                    if self._web_origin(fa_parsed) == origin:
                        f_names = list(form.get("query_defaults", {}))
                        if f_names:
                            f_query = urlencode([(f, form["query_defaults"][f]) for f in f_names])
                            f_url = urlunparse((fa_parsed.scheme, fa_parsed.netloc, fa_parsed.path or "/", "", f_query, ""))
                            point_key = (f_url, tuple(f_names))
                            if point_key not in input_point_keys and len(input_points) < MAX_ACTIVE_PARAMETERS:
                                input_point_keys.add(point_key)
                                input_points.append({
                                    "url": f_url,
                                    "names": f_names[:MAX_ACTIVE_PARAMETERS],
                                })
            graph = getattr(self, "_application_map", None)
            if graph:
                graph.add(page_url, "page", collected=True)
                for form in parser.forms:
                    graph.add(urljoin(page_url, form["action"]), "form", page_url, "contains_form", method=form["method"].upper())
            if page_has_password_form:
                password_form_paths.append(parsed.path or "/")

            for s_src in parser.scripts:
                try:
                    s_candidate = urljoin(page_url, s_src)
                    s_parsed = urlparse(s_candidate)
                    if self._web_origin(s_parsed) == origin and read_only_candidate(s_candidate) and s_candidate not in scripts_found:
                        scripts_found.append(s_candidate)
                except ValueError:
                    continue

            if depth >= 2:
                continue

            for href in parser.links:
                try:
                    candidate = urlparse(urljoin(page_url, href))
                except ValueError:
                    continue
                candidate_origin = self._web_origin(candidate)
                # Do not crawl off-origin, credentialed, or non-web URLs.
                # Query values are not stored in findings; deep scan replaces
                # one parameter at a time with a synthetic test value.
                if candidate_origin != origin or not read_only_candidate(candidate.geturl()):
                    continue
                if candidate.username or candidate.password:
                    continue
                candidate_key = urlunparse((candidate.scheme, candidate.netloc, candidate.path or "/", "", "", ""))
                if candidate.query and len(input_points) < MAX_ACTIVE_PARAMETERS:
                    names = list(dict.fromkeys(name for name, _ in parse_qsl(candidate.query, keep_blank_values=True) if name))
                    point_key = (candidate_key, tuple(names))
                    if names and point_key not in input_point_keys:
                        input_point_keys.add(point_key)
                        input_points.append({
                            "url": urlunparse((candidate.scheme, candidate.netloc, candidate.path or "/", "", candidate.query, "")),
                            "names": names[:MAX_ACTIVE_PARAMETERS],
                        })
                if candidate_key in visited or any(item[0] == candidate_key for item in queue):
                    continue
                if len(visited) + len(queue) >= MAX_CRAWL_PAGES:
                    break
                if progress_callback:
                    progress_callback(f"Crawling {len(visited) + 1}/{MAX_CRAWL_PAGES}: {candidate.path or '/'}")
                time.sleep(CRAWL_DELAY_SECONDS)
                try:
                    page_response = self._bounded_get(candidate_key, timeout=8)
                except requests.RequestException:
                    continue
                if 200 <= page_response.status_code < 300:
                    queue.append((candidate_key, depth + 1, page_response))

        return {
            "pages": len(paths),
            "paths": list(dict.fromkeys(paths))[:MAX_CRAWL_PAGES],
            "http_password_forms": password_forms,
            "password_form_paths": list(dict.fromkeys(password_form_paths)),
            "input_points": input_points,
            "scripts": list(dict.fromkeys(scripts_found))[:15],
            "csrf_forms": csrf_vulnerable_forms[:10],
        }

    def _check_cors(self, url, scan_id=None):
        """Distinguish static allowlists from repeatable arbitrary-origin reflection."""
        findings, observations = [], []
        probes = ['https://' + secrets.token_hex(10) + '.invalid' for _ in range(2)]
        for value in probes + ['null']:
            self.session.cookies.clear()
            try:
                response = self._bounded_get(url, timeout=6, headers={'Origin': value})
                observations.append({'origin': value, 'status': response.status_code,
                    'allow_origin': response.headers.get('Access-Control-Allow-Origin', '').strip(),
                    'allow_credentials': response.headers.get('Access-Control-Allow-Credentials', '').strip() == 'true'})
            except requests.RequestException:
                observations.append({'origin': value, 'status': None, 'allow_origin': '', 'allow_credentials': False})
        reflected = all(row['status'] is not None and 200 <= row['status'] < 300 and row['allow_origin'] == row['origin'] for row in observations[:2])
        null = observations[-1]
        cases = []
        if reflected:
            cases.append(('CORS policy reflects arbitrary Origins on repeated probes', observations[:2]))
        if null['status'] is not None and 200 <= null['status'] < 300 and null['allow_origin'] == 'null' and null['allow_credentials']:
            cases.append(('CORS policy permits a credentialed null Origin', [null]))
        for title, rows in cases:
            credentials = all(row['allow_credentials'] for row in rows)
            findings.append(Finding(scan_id=scan_id, title=title,
                description='An anonymous successful response advertised a permissive CORS policy. Protected-data access, cookie eligibility and browser readability were not demonstrated. This policy observation is not a confirmed data breach.',
                source_tool=self.name, tool_version=self.version, target=map_safe_url(url),
                severity=FindingSeverity.MEDIUM if credentials else FindingSeverity.LOW,
                severity_source='Observed CORS policy; protected response impact remains unverified',
                confidence=FindingConfidence.HIGH, confidence_justification='Two unpredictable origins must both reflect exactly; fixed allowlists do not qualify. Null-origin policy is recorded separately.',
                status=FindingStatus.POTENTIAL, cwe_id='CWE-942',
                evidence_raw=json.dumps({'observations': rows, 'credentials_sent': False, 'browser_read_verified': False,
                    'reproduction_steps': ['Repeat anonymous GET with each recorded Origin header.', 'Confirm expected application policy and test browser readability with an authorized synthetic session.'],
                    'expected': 'Only explicitly trusted origins can read protected responses.', 'observed': 'Recorded response policy accepts the controlled origin values.',
                    'limitations': 'No protected response body retained, no credentials sent, and no browser data-read proof.'}),
                evidence_summary='CORS policy reproduced anonymously; credentialed data access is unverified.',
                remediation='Allow only trusted origins, use Vary: Origin where responses vary, and validate actual protected-data access with authorized test accounts.'))
        return findings

    def _verify_open_redirect(self, original, pairs, parameter, scan_id, safe_target):
        """Reviewed GET-only verifier: baseline, relative control, two unique destinations."""
        started = datetime.now(timezone.utc).isoformat()
        observations = []
        state, reason = "INCONCLUSIVE", "Verification did not complete."
        proof = False
        challenges = ["https://obsidian.invalid/proof/" + secrets.token_hex(12) for _ in range(2)]
        attempts = [("baseline", None), ("relative_control", "/obsidian-control-" + secrets.token_hex(8)),
                    ("challenge_1", challenges[0]), ("challenge_2", challenges[1])]
        try:
            for role, value in attempts:
                query = pairs if value is None else [(name, value if name == parameter else current) for name, current in pairs]
                address = urlunparse(original._replace(query=urlencode(query, doseq=True)))
                response = self._bounded_get(address, timeout=5)
                location = response.headers.get("Location", "")
                observations.append({"role": role, "request": {"method": "GET", "url": map_safe_url(address),
                    "synthetic_input": value, "headers": "not retained"},
                    "response": {"status": response.status_code, "location": sanitize_text(location),
                    "sha256": hashlib.sha256(response.content).hexdigest()},
                    "collected_at_utc": datetime.now(timezone.utc).isoformat()})
                if not 200 <= response.status_code < 400:
                    reason = "A denied, failed or backpressure response prevented a controlled comparison."
                    break
                if role.startswith("challenge") and not (response.status_code in {301, 302, 303, 307, 308} and location == value):
                    state, reason = "COMPLETED", "The supplied destination was not reproduced as an HTTP redirect."
                    break
            else:
                proof = all(item["response"]["location"] not in challenges for item in observations[:2])
                state = "COMPLETED"
                reason = "Two independent destinations matched; baseline and relative control did not match either destination." if proof else "A control contradicted the redirect hypothesis."
        except requests.RequestException as exc:
            reason = "Controlled redirect verification interrupted: " + type(exc).__name__
        evidence = {"module": "controlled_open_redirect_v2", "method": "GET", "parameter": parameter,
            "started_at_utc": started, "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            "outcome": "VERIFIED" if proof else "NOT_REPRODUCED" if state == "COMPLETED" else "INCONCLUSIVE",
            "rule": "Both unique external synthetic destinations must match Location exactly after successful controls.",
            "observations": observations, "request_budget": 4, "redirects_followed": False,
            "limitations": "Only the redirect response is established; no destination visit or credential interaction.",
            "reproduction_steps": ["Repeat the recorded relative control on the authorized route.",
                "Supply each synthetic destination separately and compare the status and Location header.",
                "Do not follow the external redirects."], "demonstrated_impact": "Untrusted input controls an external HTTP redirect."}
        self._coverage.record("Controlled open redirect", state, reason, len(observations),
            route=map_safe_url(original.geturl()), parameter=parameter, method="GET", verification=evidence)
        if not proof:
            return []
        return [Finding(scan_id=scan_id, title=f"Validated Open Redirect via Parameter '{parameter}'",
            description="Two independent harmless external destinations were reproduced in redirect responses; controls excluded fixed redirects. No external destination was contacted.",
            source_tool=self.name, tool_version=self.version, target=safe_target,
            severity=FindingSeverity.MEDIUM, severity_source="Repeatable externally controlled HTTP redirect",
            confidence=FindingConfidence.CONFIRMED, confidence_justification=reason,
            status=FindingStatus.VALIDATED, cwe_id="CWE-601", evidence_raw=json.dumps(evidence),
            evidence_summary="Four response comparisons; two exact independent destination matches; redirects not followed.",
            remediation="Restrict navigation to explicitly allowed same-origin paths; reject external destinations.")]

    def _verify_template_arithmetic(self, original, pairs, parameter, scan_id, safe_target):
        """Require two independent benign arithmetic challenges, not a fixed number."""
        for opening, closing, label in [('{{', '}}', 'double braces'), ('${', '}', 'dollar braces'), ('<%=', '%>', 'template expression')]:
            proofs = []
            for _ in range(2):
                left, right = 31 + secrets.randbelow(60), 101 + secrets.randbelow(70)
                prefix = INPUT_PROBE_MARKER + secrets.token_hex(8) + ':'
                expression = opening + f'{left}*{right}' + closing
                probe = prefix + expression
                url = urlunparse(original._replace(query=urlencode([(name, probe if name == parameter else value) for name, value in pairs], doseq=True)))
                try:
                    response = self._bounded_get(url, timeout=5)
                    text = _probe_text(response)
                    expected = prefix + str(left * right)
                    if not (200 <= response.status_code < 300 and expected in text and probe not in text):
                        break
                    proofs.append({'input': probe, 'expected': expected, 'observed': expected, 'status': response.status_code})
                except requests.RequestException:
                    break
            if len(proofs) == 2:
                return [Finding(scan_id=scan_id, title=f'Reproducible Server-Side Template Injection arithmetic indicator ({label})',
                    description='Two unique arithmetic challenges were transformed into the expected products in HTTP response bodies. This supports server-side expression evaluation; template-engine identity, code execution and business impact have not been established.',
                    source_tool=self.name, tool_version=self.version, target=safe_target, severity=FindingSeverity.HIGH,
                    severity_source='Independent benign arithmetic transformations; exploit impact unverified',
                    confidence=FindingConfidence.HIGH, confidence_justification='Two random prefixes and operands matched computed products; literal reflection and fixed sample numbers do not qualify.',
                    status=FindingStatus.POTENTIAL, cwe_id='CWE-1336',
                    evidence_raw=json.dumps({'parameter': parameter, 'challenges': proofs,
                        'reproduction_steps': ['Replay both harmless recorded query values on the authorized endpoint.', 'Confirm products are server-rendered and determine whether template source receives untrusted input.'],
                        'limitations': 'No command execution, filesystem access or exploit-impact confirmation was attempted.'}),
                    evidence_summary='Two independent arithmetic evaluations reproduced; exploit impact unverified.',
                    remediation='Pass input as template data rather than concatenating it into template source. Validate the template context and retest both challenges after remediation.')]
        return []

    def _covered_operation(self, check, operation, *args):
        before = self._scan_metrics.get("request_count", 0)
        errors = len(self._scan_metrics.get("errors", []))
        result = operation(*args)
        count = self._scan_metrics.get("request_count", 0) - before
        interrupted = self._cancelled() or getattr(self, "_collection_stop", None)
        state = "INCONCLUSIVE" if interrupted or len(self._scan_metrics.get("errors", [])) > errors else "COMPLETED"
        self._coverage.record(check, state, "Bounded operation executed; findings and individual controls determine evidence strength.", count)
        return result

    def _cancelled(self):
        if getattr(self, "_was_cancelled", False):
            return True
        callback = getattr(self, "_cancel_check", None)
        if callback and callback():
            self._was_cancelled = True
            return True
        return False

    def _controlled_sql_error(self, original, pairs, parameter, scan_id, safe_target):
        """Confirm a repeatable error condition, never label it proven SQL injection."""
        observations = []
        marker = "OBSIDIAN" + secrets.token_hex(8)
        for label, value in (("baseline", None), ("control", marker), ("quote", "'"), ("repeat_quote", "'")):
            query = pairs if value is None else [(n, value if n == parameter else v) for n, v in pairs]
            url = urlunparse(original._replace(query=urlencode(query, doseq=True)))
            try:
                response = self._bounded_get(url, timeout=6)
            except requests.RequestException:
                self._coverage.record("SQL error differential", "INCONCLUSIVE", "A required response was unavailable.", len(observations), target=safe_target, route=map_safe_url(original.geturl()), parameter=parameter)
                self._hypotheses.append(sql_hypothesis(safe_target, parameter, observations, [], []))
                return []
            body = _probe_text(response).casefold()
            engines = sorted(engine for engine, signatures in SQL_ERROR_SIGNATURES.items() if any(sig in body for sig in signatures))
            observations.append({"role": label, "status": response.status_code, "engines": engines,
                "response_sha256": hashlib.sha256(response.content).hexdigest()})
            blocked = response.status_code in {401, 403, 429, 503} or 300 <= response.status_code < 400
            ambiguous_control = label in {"baseline", "control"} and (engines or not 200 <= response.status_code < 300)
            if blocked or ambiguous_control:
                reason = "Access/redirect/backpressure prevents this verification." if blocked else "Database error or unsuccessful response already present in a control; quote attribution is inconclusive."
                self._coverage.record("SQL error differential", "INCONCLUSIVE", reason, len(observations), target=safe_target, route=map_safe_url(original.geturl()), parameter=parameter)
                hypothesis = sql_hypothesis(safe_target, parameter, observations, [], [])
                hypothesis["stop_reason"] = reason
                hypothesis["decision"] = "Do not send remaining probes; restore a valid baseline or review error handling before a new authorized test."
                self._hypotheses.append(hypothesis)
                return []
        initial = set(observations[0]["engines"]) | set(observations[1]["engines"])
        repeated = (set(observations[2]["engines"]) & set(observations[3]["engines"])) - initial
        # An upstream denial/challenge is not database error evidence.
        repeated = repeated if all(o["status"] not in {401, 403, 429} for o in observations) else set()
        self._coverage.record("SQL error differential", "COMPLETED", "Baseline, alphanumeric control and two quote responses compared; no extraction or timing payloads.", 4, target=safe_target, route=map_safe_url(original.geturl()), parameter=parameter, new_repeated_signatures=sorted(repeated))
        self._hypotheses.append(sql_hypothesis(safe_target, parameter, observations, sorted(repeated), []))
        if not repeated:
            return []
        engine = sorted(repeated)[0]
        return [Finding(scan_id=scan_id, title=f"Reproducible {engine} error after quote input",
            description="A database-specific error was absent from the original input and alphanumeric control, and present in both quote responses. This demonstrates input-dependent error disclosure; exploitable SQL injection and data access remain unverified.",
            source_tool=self.name, tool_version=self.version, target=safe_target,
            severity=FindingSeverity.MEDIUM, severity_source="Repeated database error disclosure; no extraction or authorization impact established",
            confidence=FindingConfidence.HIGH, confidence_justification="Same signature in two quote responses and neither control response.",
            status=FindingStatus.POTENTIAL, cwe_id="CWE-209",
            evidence_raw=json.dumps({"verification_method": "controlled_sql_error_differential", "method": "GET", "parameter": parameter,
                "observations": observations, "control_value": marker,
                "prerequisites": "Authorized read-only query endpoint; restore original non-test query values locally.",
                "reproduction_steps": ["Request the endpoint with its original input and record status and database error signatures.",
                    "Replace only the indicated parameter with the recorded alphanumeric control and compare.",
                    "Replace only that parameter with a single quote twice; verify the same new database signature in both responses."],
                "demonstrated_impact": "Input-dependent database error disclosure only.",
                "limitations": "No SQL data extraction, command execution, timing query or proof of injectable query semantics."}),
            evidence_summary="Four response fingerprints retained; raw bodies and private query values excluded.",
            remediation="Use parameterized database calls; return generic errors and keep detailed exceptions in protected server logs.")]

    def _verify_file_canary(self, original, pairs, parameter, scan_id, safe_target):
        """Only assessor-provisioned harmless files, with an explicit expected marker."""
        plans = getattr(self, "_canary_files", [])
        plan = next((item for item in plans if item.get("endpoint") == original.path and item.get("parameter") == parameter), None)
        if not plan:
            self._coverage.record("File boundary canary", "BLOCKED", "No explicitly provisioned harmless file and expected marker for this endpoint/parameter.", target=safe_target, parameter=parameter)
            return []
        proofs = []
        for role, value in (("baseline", None), ("nonexistent_control", "obsidian-missing-" + secrets.token_hex(12)), ("canary", plan["value"]), ("repeat_canary", plan["value"])):
            query = pairs if value is None else [(n, value if n == parameter else v) for n, v in pairs]
            try:
                response = self._bounded_get(urlunparse(original._replace(query=urlencode(query, doseq=True))), timeout=5)
            except requests.RequestException:
                self._coverage.record("File boundary canary", "INCONCLUSIVE", "A required canary/control response was unavailable.", len(proofs), target=safe_target)
                return []
            proofs.append({"role": role, "status": response.status_code, "marker_present": plan["marker"] in _probe_text(response),
                "response_sha256": hashlib.sha256(response.content).hexdigest()})
        matched = not any(x["marker_present"] for x in proofs[:2]) and all(x["marker_present"] and 200 <= x["status"] < 300 for x in proofs[2:])
        self._coverage.record("File boundary canary", "COMPLETED", "Two controls and repeated assessor-provisioned canary compared.", 4, target=safe_target, marker_reproduced=matched)
        if not matched:
            return []
        return [Finding(scan_id=scan_id, title="Declared file boundary canary reproduced",
            description="The assessor declared this synthetic canary outside the allowed file boundary. Its expected marker appeared twice and was absent from two controls. Boundary placement is assessor-supplied; arbitrary file access or real sensitive file exposure was not tested.",
            source_tool=self.name, tool_version=self.version, target=safe_target, severity=FindingSeverity.MEDIUM,
            severity_source="Repeatable synthetic canary access; real sensitive file impact not assessed",
            confidence=FindingConfidence.HIGH, confidence_justification="Two successful marker observations and negative controls; boundary placement requires assessor review.",
            status=FindingStatus.POTENTIAL, cwe_id="CWE-22", evidence_raw=json.dumps({"verification_method": "declared_file_canary",
                "parameter": parameter, "observations": proofs, "canary_input": plan["value"], "boundary_declared_by_assessor": True,
                "reproduction_steps": ["Provision the harmless canary outside the declared allowed file root.", "Replay the recorded canary input twice, then a nonexistent filename; compare expected marker presence."],
                "limitations": "Canary marker and raw file content are not retained. Assessor must verify the declared boundary."}),
            evidence_summary="Expected synthetic marker reproduced twice; controls did not contain it.",
            remediation="Resolve canonical paths and require containment within the allowed file root, or map opaque identifiers to approved files.")]

    def _probe_query_parameters(
        self,
        input_points: List[Dict[str, Any]],
        scan_id: Optional[str] = None,
        progress_callback: Optional[Any] = None,
    ) -> List[Finding]:
        """Run capped, non-destructive GET probes on discovered query parameters."""
        findings: List[Finding] = []
        tested = 0
        seen = set()
        browser_verifier = BrowserXSSVerifier()
        for point in input_points:
            if not read_only_candidate(point["url"]):
                continue
            original = urlparse(point["url"])
            pairs = parse_qsl(original.query, keep_blank_values=True)
            for parameter in point["names"]:
                key = (point["url"], parameter)
                if key in seen:
                    continue
                seen.add(key)
                if self._cancelled():
                    return findings
                if tested >= MAX_ACTIVE_PARAMETERS:
                    return findings
                tested += 1
                if progress_callback:
                    progress_callback(f"Safely probing query parameter {tested}/{MAX_ACTIVE_PARAMETERS}: {parameter[:48]}")

                probe_value = f"{INPUT_PROBE_MARKER}{time.monotonic_ns()}<sentinel-probe>"
                probe_pairs = [(name, probe_value if name == parameter else value) for name, value in pairs]
                probe_url = urlunparse(original._replace(query=urlencode(probe_pairs, doseq=True)))
                safe_target = urlunparse(original._replace(query=urlencode([(parameter[:80], "[redacted]")])))
                try:
                    response = self._bounded_get(probe_url, timeout=6)
                except requests.RequestException:
                    continue
                content_type = response.headers.get("Content-Type", "").lower()
                body = _probe_text(response)

                if "text/html" in content_type and probe_value in body:
                    refl_analysis = HTMLReflectionContextAnalyzer.analyze(body, probe_value)
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Reflected XSS Candidate in Executable HTML Context" if refl_analysis.recommends_alert else "Reflected Input in Inert HTML Context",
                        description=(
                            "A unique inert HTML marker supplied through a query parameter was returned unescaped in an HTML response. "
                            "This is an XSS candidate, not proof of script execution; browser context and client-side handling require review."
                        ),
                        source_tool=self.name,
                        tool_version=self.version,
                        target=safe_target,
                        severity=FindingSeverity.MEDIUM,
                        severity_source=f"DOM Reflection Context: {refl_analysis.context.value}",
                        confidence=FindingConfidence.MEDIUM,
                        confidence_justification=refl_analysis.details,
                        status=FindingStatus.SCANNER_REPORTED,
                        evidence_raw=json.dumps({"parameter": parameter[:80], "marker_reflected_raw": True,
                                                 "verification_method": "inert_marker_reflection", "script_execution_verified": False,
                                                 "response_sha256": hashlib.sha256(response.content).hexdigest()}),
                        evidence_summary=f"Reflected in {refl_analysis.context.value} context ({'breakout possible' if refl_analysis.can_break_out else 'safely enclosed'}).",
                        cwe_id="CWE-79",
                        remediation="Apply context-aware output encoding and validate the sink in a browser; do not rely on input filtering alone.",
                    ))
                    candidate = findings[-1]
                    candidate.severity = refl_analysis.suggested_severity
                    candidate.confidence = FindingConfidence.MEDIUM
                    candidate.status = FindingStatus.SCANNER_REPORTED if refl_analysis.recommends_alert else FindingStatus.OBSERVED
                    if len(self._browser_checks) < MAX_BROWSER_CANDIDATES:
                        if self._cancelled():
                            return findings
                        if progress_callback:
                            progress_callback("Verifying reflected input in an isolated browser…")
                        proof = browser_verifier.verify(point["url"], parameter)
                        self._browser_checks.append({"target": safe_target, **proof})
                        evidence = json.loads(candidate.evidence_raw)
                        evidence["browser_verification"] = proof
                        candidate.evidence_summary += " Browser: " + proof["reason"]
                        if proof["script_execution_verified"]:
                            evidence.update({"verification_method": "browser_execution_probe", "script_execution_verified": True})
                            candidate.title = "Browser-confirmed reflected XSS"
                            candidate.description = (
                                "A benign input supplied through this query parameter executed JavaScript in an isolated browser's main document. "
                                "The injected code computed a unique expected value; the verifier only read that property. "
                                "An attacker-controlled link may execute code in the site's origin. Account-specific impact was not tested."
                            )
                            candidate.severity = FindingSeverity.HIGH
                            candidate.severity_source = "Observed arbitrary JavaScript execution from reflected GET input; account impact not tested"
                            candidate.confidence = FindingConfidence.CONFIRMED
                            candidate.confidence_justification = "The browser observed the exact unique computed proof; response was 2xx in the main document."
                            candidate.status = FindingStatus.VALIDATED
                        candidate.evidence_raw = json.dumps(evidence)
                    else:
                        candidate.evidence_summary += " Browser confirmation was not attempted: per-assessment candidate limit reached."

                findings.extend(self._controlled_sql_error(original, pairs, parameter, scan_id, safe_target))

                # Check for Open Redirect on redirect-like parameters
                if re.search(r"(?i)^(redirect|redirect_uri|redir|url|next|return|return_to|dest|destination|target|to|uri|link|forward|out)$", parameter):
                    findings.extend(self._verify_open_redirect(original, pairs, parameter, scan_id, safe_target))

                findings.extend(self._verify_template_arithmetic(original, pairs, parameter, scan_id, safe_target))

                if re.search(r"(?i)^(id|user_id|uid|account_id|order_id|invoice_id|tenant_id|url|webhook|fetch|proxy)$", parameter):
                    self._untested_checks = getattr(self, "_untested_checks", [])
                    self._untested_checks.append({"path": original.path, "parameter": parameter,
                        "outcome": "NOT_TESTED", "reason": "Object ownership needs declared synthetic identities/resources; SSRF needs explicitly approved callback infrastructure. No adjacent-ID or server-loopback probe sent."})

                if re.search(r"(?i)^(file|filename|filepath|path|doc|document|page|template|view|include|folder|dir|log)$", parameter):
                    findings.extend(self._verify_file_canary(original, pairs, parameter, scan_id, safe_target))

                # HTTP Header Injection / CRLF probe on redirect parameters
                if re.search(r"(?i)^(redirect|redirect_uri|redir|url|next|return|return_to|dest|destination|target|to|uri|link|forward|out)$", parameter):
                    crlf_nonce = secrets.token_hex(10)
                    crlf_probe = f"sentinel%0d%0aSet-Cookie:%20sentinel_crlf_probe={crlf_nonce}"
                    crlf_pairs = [(name, crlf_probe if name == parameter else value) for name, value in pairs]
                    crlf_url = urlunparse(original._replace(query=urlencode(crlf_pairs, doseq=True)))
                    try:
                        crlf_resp = self._bounded_get(crlf_url, timeout=5)
                        if any(f"sentinel_crlf_probe={crlf_nonce}" in v for v in crlf_resp.headers.get("Set-Cookie", "").split(",")):
                            findings.append(Finding(
                                scan_id=scan_id,
                                title=f"HTTP Response Splitting / Header Injection in Parameter '{parameter}'",
                                description=(
                                    f"Injected CRLF sequences (%0d%0a) into parameter '{parameter}' resulted in an arbitrary 'Set-Cookie' header "
                                    "being injected into the server's HTTP response. This enables session fixation, XSS, and cache poisoning."
                                ),
                                source_tool=self.name,
                                tool_version=self.version,
                                target=safe_target,
                                severity=FindingSeverity.HIGH,
                                severity_source="Observed Set-Cookie header injected via CRLF in query parameter",
                                confidence=FindingConfidence.CONFIRMED,
                                confidence_justification="Response headers reflected the injected Set-Cookie directive",
                                status=FindingStatus.VALIDATED,
                                evidence_raw=json.dumps({"parameter": parameter, "injected_header": "Set-Cookie: sentinel_crlf_probe=[redacted]"}),
                                evidence_summary=f"CRLF injection in parameter '{parameter}' successfully injected HTTP response headers.",
                                cwe_id="CWE-113",
                                remediation="Strip CR (%0d, \\r) and LF (%0a, \\n) characters from user inputs before incorporating them into HTTP headers or redirect locations.",
                            ))
                    except requests.RequestException:
                        pass
        return findings

    def _audit_javascript_assets(self, base_url, script_urls=None, scan_id=None, progress_callback=None, *, scripts=None):
        from src.adapters.javascript_assets import audit_assets
        return audit_assets(self, base_url, script_urls if script_urls is not None else scripts or [], scan_id, progress_callback)

    def _audit_subdomains(self, domain: str, scan_id: Optional[str] = None, progress_callback: Optional[Any] = None) -> List[Finding]:
        """Passive certificate transparency asset discovery via crt.sh without target traffic."""
        if not domain or domain in {"localhost", "127.0.0.1"} or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", domain):
            return []

        parts = domain.lower().split(".")
        if len(parts) < 2:
            return []

        apex = domain.lower().rstrip(".")  # Do not infer a registrable domain by taking two labels.
        if progress_callback:
            progress_callback(f"Querying passive Certificate Transparency logs for {apex}...")

        subdomains: set[str] = set()
        try:
            ct_url = f"https://crt.sh/?q=%.{apex}&output=json"
            with requests.Session() as passive_http:
                passive_http.trust_env = False
                resp = passive_http.get(ct_url, timeout=(3, 7), allow_redirects=False, stream=True,
                                        headers={"User-Agent": "OBSIDIAN-CT/1.0"})
                try:
                    raw = resp.raw.read(1_000_001, decode_content=True)
                finally:
                    resp.close()
                if not isinstance(raw, bytes) or len(raw) > 1_000_000:
                    return []
            if resp.status_code == 200:
                entries = json.loads(raw)
                if isinstance(entries, list):
                    for entry in entries[:200]:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name.startswith("*."):
                                name = name[2:]
                            if (name.endswith(f".{apex}") or name == apex) and re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", name):
                                subdomains.add(name)
        except Exception:
            return []

        if subdomains:
            sorted_subs = sorted(subdomains)[:40]
            return [
                Finding(
                    scan_id=scan_id,
                    title=f"Discovered {len(subdomains)} Subdomain Assets via Certificate Transparency for {apex}",
                    description=(
                        f"Passive Certificate Transparency log enumeration discovered {len(subdomains)} subdomains for '{apex}':\n\n"
                        + "\n".join(f"• {s}" for s in sorted_subs[:25])
                        + (f"\n... and {len(sorted_subs) - 25} more" if len(sorted_subs) > 25 else "")
                        + "\n\nImportant: Verify engagement authorization and program scope before performing any active assessment against these discovered assets."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=apex,
                    severity=FindingSeverity.INFO,
                    severity_source="Certificate Transparency (crt.sh)",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification=f"Retrieved authentic TLS certificate records from public Certificate Transparency logs for apex {apex}",
                    status=FindingStatus.OBSERVED,
                    evidence_raw=json.dumps({"apex": apex, "count": len(subdomains), "subdomains": sorted_subs, "source": "https://crt.sh/", "active_testing_authorized": False}, ensure_ascii=False),
                    evidence_summary=f"Found {len(subdomains)} subdomains via public CT logs; active traffic was not sent to subdomains.",
                    remediation="Audit external-facing assets regularly to identify forgotten development subdomains, exposed admin consoles, and dangling CNAME records.",
                )
            ]
        return []

    def _audit_jwt_tokens(
        self,
        base_url: str,
        cookies: Any,
        headers: Any,
        scripts_content: List[str],
        scan_id: Optional[str] = None,
    ) -> List[Finding]:
        """Inspect discovered JWTs across headers, cookies, and scripts for security weaknesses."""
        findings = []
        jwt_candidates: set[str] = set()

        # Check headers (Authorization, Set-Cookie, etc.)
        for h_key, h_val in headers.items():
            for match in re.findall(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])", str(h_val)):
                jwt_candidates.add(match)

        # Check cookies
        for cookie in cookies:
            c_val = getattr(cookie, "value", "")
            for match in re.findall(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])", str(c_val)):
                jwt_candidates.add(match)

        # Check frontend scripts
        for script_text in scripts_content:
            for match in re.findall(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])", str(script_text)):
                jwt_candidates.add(match)

        def _b64url_json(segment: str) -> Optional[dict]:
            import base64
            padded = segment + "=" * ((4 - len(segment) % 4) % 4)
            try:
                decoded = base64.urlsafe_b64decode(padded)
                obj = json.loads(decoded)
                return obj if isinstance(obj, dict) else None
            except Exception:
                return None

        audited_tokens = 0
        for token in sorted(jwt_candidates):
            if audited_tokens >= 5:
                break
            audited_tokens += 1
            parts = token.split(".")
            if len(parts) < 2:
                continue
            hdr = _b64url_json(parts[0])
            payload = _b64url_json(parts[1])
            if not hdr or not payload:
                continue

            # 1. alg: none vulnerability
            alg = str(hdr.get("alg", "")).strip().lower()
            if alg == "none":
                findings.append(Finding(
                    scan_id=scan_id,
                    title=f"Critical Unsecured JWT with 'none' Algorithm Disclosed on {base_url}",
                    description=(
                        "A JSON Web Token (JWT) utilizing 'alg': 'none' was discovered. "
                        "Tokens with 'none' algorithm lack digital signature verification, allowing attackers to forge arbitrary claims, roles, and user identities."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=base_url,
                    severity=FindingSeverity.CRITICAL,
                    severity_source="Decoded JWT header with alg: none",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification="JWT header explicitly declared 'alg': 'none'",
                    status=FindingStatus.VALIDATED,
                    evidence_raw=json.dumps({"header": hdr, "token_prefix": token[:20] + "...[REDACTED]"}),
                    evidence_summary="JWT header declared alg: none without cryptographic signature.",
                    cwe_id="CWE-327",
                    remediation="Reject tokens with 'none' algorithm on the server and mandate strong asymmetric (RS256/ES256) or symmetric (HS256) algorithms.",
                ))

            # 2. Missing expiration (exp)
            if "exp" not in payload:
                findings.append(Finding(
                    scan_id=scan_id,
                    title=f"JWT Lacks Expiration Claim ('exp') on {base_url}",
                    description=(
                        "The discovered JSON Web Token (JWT) does not declare an 'exp' (expiration time) claim. "
                        "Without an expiration timestamp, compromised tokens remain valid indefinitely."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=base_url,
                    severity=FindingSeverity.LOW,
                    severity_source="Decoded JWT payload missing exp claim",
                    confidence=FindingConfidence.CONFIRMED,
                    confidence_justification="Payload lacks 'exp' standard claim",
                    status=FindingStatus.SCANNER_REPORTED,
                    evidence_raw=json.dumps({"payload_keys": list(payload.keys())}),
                    evidence_summary="JWT payload lacks 'exp' expiration claim.",
                    cwe_id="CWE-613",
                    remediation="Always set a short, reasonable expiration time ('exp') on session tokens.",
                ))

            # 3. Sensitive claims exposed in payload
            sensitive_payload_keys = [k for k in payload if any(s in k.lower() for s in ("password", "passwd", "secret", "private", "hash", "ssn"))]
            if sensitive_payload_keys:
                findings.append(Finding(
                    scan_id=scan_id,
                    title=f"Sensitive Claims Disclosed in JWT Payload on {base_url}",
                    description=(
                        f"The JWT payload exposes sensitive internal field(s): {', '.join(sensitive_payload_keys)}. "
                        "JWT payloads are only Base64URL-encoded (not encrypted) and are readable by anyone possessing the token."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=base_url,
                    severity=FindingSeverity.MEDIUM,
                    severity_source="Sensitive field identifiers in unencrypted JWT payload",
                    confidence=FindingConfidence.HIGH,
                    confidence_justification="JWT payload contains sensitive credentials or secret markers",
                    status=FindingStatus.POTENTIAL,
                    evidence_raw=json.dumps({"sensitive_keys": sensitive_payload_keys}),
                    evidence_summary=f"JWT payload exposes sensitive field(s): {', '.join(sensitive_payload_keys)}",
                    cwe_id="CWE-312",
                    remediation="Do not store sensitive credentials, passwords, or internal secrets in unencrypted JWT payloads.",
                ))

            # 4. Dangerous Key ID (kid) pattern
            kid = str(hdr.get("kid", ""))
            if kid and ("../" in kid or ".." in kid or "'" in kid):
                findings.append(Finding(
                    scan_id=scan_id,
                    title=f"Suspicious JWT Key ID ('kid') Pattern on {base_url}",
                    description=f"The JWT header specifies a 'kid' containing directory traversal or punctuation patterns: '{kid[:30]}'.",
                    source_tool=self.name,
                    tool_version=self.version,
                    target=base_url,
                    severity=FindingSeverity.HIGH,
                    severity_source="Directory traversal or injection pattern in JWT kid header",
                    confidence=FindingConfidence.HIGH,
                    confidence_justification="JWT kid header matched traversal pattern",
                    status=FindingStatus.POTENTIAL,
                    evidence_raw=json.dumps({"kid": kid[:40]}),
                    evidence_summary=f"Suspicious kid header in JWT: {kid[:30]}",
                    cwe_id="CWE-347",
                    remediation="Validate 'kid' values against an allowlist of known key identifiers rather than using them directly in file or database lookups.",
                ))

        return findings

    def _audit_csrf_forms(
        self,
        domain: str,
        csrf_forms: List[Dict[str, Any]],
        cookies: Any,
        scan_id: Optional[str] = None,
    ) -> List[Finding]:
        """Audit discovered POST forms lacking anti-CSRF tokens."""
        if not csrf_forms:
            return []

        # Check if cookies are set without SameSite=Strict
        lax_or_none_cookies = []
        for cookie in cookies:
            samesite = getattr(cookie, "_rest", {}).get("samesite")
            if hasattr(cookie, "has_nonstandard_attr") and cookie.has_nonstandard_attr("samesite"):
                samesite = cookie.get_nonstandard_attr("samesite")
            if not samesite or str(samesite).lower() not in {"strict"}:
                lax_or_none_cookies.append(cookie.name)

        if not lax_or_none_cookies and not csrf_forms:
            return []

        findings = []
        sample_forms = csrf_forms[:5]
        findings.append(Finding(
            scan_id=scan_id,
            title=f"State-Changing HTML Form Lacks Anti-CSRF Token on {domain}",
            description=(
                f"OBSIDIAN identified {len(csrf_forms)} state-changing POST form(s) that do not include an anti-CSRF token "
                f"(e.g. csrf, xsrf, _token). In addition, session cookies lack SameSite=Strict protection. "
                "Attackers can induce authenticated users to submit unauthorized requests to these actions."
            ),
            source_tool=self.name,
            tool_version=self.version,
            target=f"https://{domain}",
            severity=FindingSeverity.MEDIUM,
            severity_source="HTML POST form without hidden CSRF token input field",
            confidence=FindingConfidence.HIGH,
            confidence_justification=f"Discovered {len(csrf_forms)} POST form(s) lacking anti-CSRF tokens in page crawl",
            status=FindingStatus.SCANNER_REPORTED,
            evidence_raw=json.dumps({"form_count": len(csrf_forms), "samples": sample_forms}),
            evidence_summary=f"{len(csrf_forms)} POST form(s) without anti-CSRF token found on {domain}",
            cwe_id="CWE-352",
            remediation="Implement unpredictable, cryptographically strong anti-CSRF tokens for all state-changing POST forms and configure SameSite=Strict or Lax on session cookies.",
        ))
        return findings

    def _audit_bfla_and_verbs(self, base_url, scan_id=None, progress_callback=None):
        """Collect method inconsistency as a lead, never infer authorization from HEAD."""
        findings = []
        for route in ('/admin', '/api/admin', '/actuator', '/manage', '/api/users'):
            target = urljoin(base_url, route)
            try:
                get = self._bounded_get(target, timeout=5)
                if get.status_code not in {401, 403}:
                    continue
                head = self._bounded_get(target, timeout=5, method='HEAD')
                if 200 <= head.status_code < 300:
                    findings.append(Finding(scan_id=scan_id, title='HTTP method policy inconsistency (GET versus HEAD)',
                        description='GET was denied while HEAD returned success. HEAD does not return a representation, so this alone does not demonstrate access to protected content or an authentication bypass.',
                        source_tool=self.name, tool_version=self.version, target=target, severity=FindingSeverity.LOW,
                        severity_source='Observed method-status difference; authorization impact unverified',
                        confidence=FindingConfidence.MEDIUM, confidence_justification='Status difference reproduced; no protected content oracle or method-override POST was used.',
                        status=FindingStatus.POTENTIAL, cwe_id='CWE-285',
                        evidence_raw=json.dumps({'get_status': get.status_code, 'head_status': head.status_code,
                            'protected_content_verified': False, 'method_override_post_sent': False,
                            'reproduction_steps': ['Compare GET and HEAD on the recorded path.', 'Review method handling and establish protected-content exposure before claiming a bypass.']}),
                        evidence_summary=f'GET {get.status_code}; HEAD {head.status_code}; protected-data access unverified.',
                        remediation='Apply the intended access policy consistently. Determine whether the difference is only generic HEAD handling.'))
            except requests.RequestException:
                continue
        return findings

    def _audit_dependency_manifest(
        self,
        manifest_url: str,
        manifest_type: str,
        content: str,
        scan_id: Optional[str] = None,
    ) -> List[Finding]:
        """Correlate exposed dependencies with known critical CVE advisories."""
        findings = []
        try:
            data = json.loads(content)
        except Exception:
            return findings

        deps = {}
        if manifest_type == "package.json":
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))
        elif manifest_type == "composer.json":
            deps.update(data.get("require", {}))
            deps.update(data.get("require-dev", {}))

        KNOWN_VULNERABLE_PACKAGES = [
            ("lodash", r"^[\^~]?(4\.(?:[0-9]|1[0-6])\.[0-9]+|4\.17\.(?:[0-9]|1[0-9]|20))$", "CVE-2021-23337", "Command Injection / Prototype Pollution in Lodash", "HIGH", "Upgrade to lodash 4.17.21 or newer."),
            ("axios", r"^[\^~]?(0\.(?:[0-9]|1[0-9]|20)\.[0-9]+)$", "CVE-2020-28168", "Server-Side Request Forgery (SSRF) in Axios", "HIGH", "Upgrade to axios 0.21.1 or newer."),
            ("log4j", r"^[\^~]?(2\.(?:[0-9]|1[0-6])\.[0-9]+)$", "CVE-2021-44228", "Apache Log4j2 JNDI RCE (Log4Shell)", "CRITICAL", "Upgrade to log4j 2.17.1 or newer."),
            ("moment", r"^[\^~]?(2\.(?:[0-9]|1[0-9]|2[0-8])\.[0-9]+)$", "CVE-2022-31129", "Regular Expression Denial of Service (ReDoS) in Moment.js", "MEDIUM", "Upgrade to moment 2.29.4 or newer."),
            ("minimist", r"^[\^~]?(0\.[0-9]+\.[0-9]+|1\.(?:[01])\.[0-9]+|1\.2\.[0-5])$", "CVE-2021-44906", "Prototype Pollution in Minimist", "HIGH", "Upgrade to minimist 1.2.6 or newer."),
            ("jquery", r"^[\^~]?(1\.[0-9]+\.[0-9]+|2\.[0-9]+\.[0-9]+|3\.[0-4]\.[0-9]+)$", "CVE-2020-11022", "Cross-Site Scripting (XSS) in jQuery htmlPrefilter", "MEDIUM", "Upgrade to jQuery 3.5.0 or newer."),
            ("jsonwebtoken", r"^[\^~]?([0-8]\.[0-9]+\.[0-9]+)$", "CVE-2022-23529", "Insecure Key Verification in JsonWebToken", "HIGH", "Upgrade to jsonwebtoken 9.0.0 or newer."),
        ]

        for pkg_name, ver_pattern, cve, title, sev_str, rem in KNOWN_VULNERABLE_PACKAGES:
            if pkg_name in deps:
                declared_ver = str(deps[pkg_name])
                if re.match(ver_pattern, declared_ver):
                    sev = FindingSeverity.CRITICAL if sev_str == "CRITICAL" else (FindingSeverity.HIGH if sev_str == "HIGH" else FindingSeverity.MEDIUM)
                    findings.append(Finding(
                        scan_id=scan_id,
                        title=f"Known Vulnerable Dependency: {pkg_name} ({declared_ver}) - {cve}",
                        description=(
                            f"The public manifest at '{manifest_url}' declares dependency '{pkg_name}' version '{declared_ver}', "
                            f"which is affected by {title} ({cve})."
                        ),
                        source_tool=self.name,
                        tool_version=self.version,
                        target=manifest_url,
                        severity=sev,
                        severity_source="Advisory Database Correlation",
                        confidence=FindingConfidence.HIGH,
                        confidence_justification=f"Manifest declares version '{declared_ver}' matching vulnerable pattern for {cve}",
                        status=FindingStatus.SCANNER_REPORTED,
                        evidence_raw=json.dumps({"manifest": manifest_url, "package": pkg_name, "version": declared_ver, "cve": cve}),
                        evidence_summary=f"Vulnerable dependency {pkg_name}@{declared_ver} ({cve}) in {manifest_type}",
                        cve_id=cve,
                        affected_component=f"{pkg_name}@{declared_ver}",
                        remediation=rem,
                    ))
        return findings

    def _audit_api_data_exposure(
        self,
        base_url: str,
        endpoints: List[str],
        scan_id: Optional[str] = None,
    ) -> List[Finding]:
        """Inspect JSON responses from discovered API endpoints for sensitive field leakage."""
        findings = []
        tested_eps = 0
        SENSITIVE_KEYS = ("password_hash", "pass_hash", "password_digest", "secret_key", "private_key", "social_security", "credit_card", "api_secret")

        for ep in endpoints:
            if tested_eps >= 6:
                break
            tested_eps += 1
            full_url = urljoin(base_url, ep)
            if map_origin(full_url) != map_origin(base_url) or not read_only_candidate(full_url):
                continue
            try:
                resp = self._bounded_get(full_url, timeout=5)
                if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", "").lower():
                    try:
                        data = resp.json()
                    except Exception:
                        continue

                    def _find_keys(obj: Any, keys: set[str], path: str = "") -> List[str]:
                        matches = []
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                curr_path = f"{path}.{k}" if path else k
                                if any(s.lower() == k.lower() for s in keys) and v not in (None, "", False, "[REDACTED]", "***"):
                                    matches.append(curr_path)
                                matches.extend(_find_keys(v, keys, curr_path))
                        elif isinstance(obj, list):
                            for item in obj[:5]:
                                matches.extend(_find_keys(item, keys, path))
                        return matches

                    leaked_fields = _find_keys(data, set(SENSITIVE_KEYS))
                    if leaked_fields:
                        findings.append(Finding(
                            scan_id=scan_id,
                            title=f"Excessive Data Exposure / Sensitive Fields in API at '{ep}'",
                            description=(
                                f"The API endpoint '{ep}' returned JSON containing sensitive internal field(s): {', '.join(leaked_fields[:5])}. "
                                "Review whether these fields are intended for this caller. This observation does not establish mass assignment or object-ownership failure."
                            ),
                            source_tool=self.name,
                            tool_version=self.version,
                            target=full_url,
                            severity=FindingSeverity.HIGH,
                            severity_source="OWASP API Security Top 10 API3:2023 Broken Object Property Level Authorization",
                            confidence=FindingConfidence.HIGH,
                            confidence_justification=f"API JSON response contains sensitive key(s): {', '.join(leaked_fields[:5])}",
                            status=FindingStatus.POTENTIAL,
                            evidence_raw=json.dumps({"endpoint": ep, "sensitive_fields": leaked_fields[:8], "status_code": 200}),
                            evidence_summary=f"Sensitive field(s) exposed in API response: {', '.join(leaked_fields[:5])}",
                            cwe_id="CWE-200",
                            remediation="Implement Data Transfer Objects (DTOs) or strict response filtering schemas to prevent internal properties from leaking to clients.",
                        ))
            except requests.RequestException:
                continue
        return findings

    @staticmethod
    def _web_origin(parsed: Any) -> Optional[Tuple[str, str, int]]:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return None
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError:
            return None
        return parsed.scheme.lower(), parsed.hostname.lower(), port

    def _inventory_finding(self, url: str, scan_id: Optional[str], inventory: Dict[str, Any]) -> Finding:
        paths = inventory["paths"]
        return Finding(
            scan_id=scan_id,
            title=f"Web attack surface mapped: {inventory['pages']} same-origin pages",
            description=(
                f"OBSIDIAN crawled up to {MAX_CRAWL_PAGES} same-origin HTML pages to map the reachable surface. "
                "Only GET requests were sent; forms were inspected but not submitted, and redirects were not followed."
            ),
            source_tool=self.name,
            tool_version=self.version,
            target=url,
            severity=FindingSeverity.INFO,
            severity_source="Direct same-origin crawl observations",
            confidence=FindingConfidence.HIGH,
            confidence_justification="Page paths and form metadata were collected from successful same-origin HTML responses.",
            status=FindingStatus.OBSERVED,
            evidence_raw=json.dumps({"page_count": inventory["pages"], "paths": paths, "forms_submitted": 0}, ensure_ascii=False),
            evidence_summary=f"Mapped {inventory['pages']} page(s): {', '.join(paths[:8])}",
            remediation="Review the mapped routes and confirm that every sensitive page enforces server-side authorization.",
        )

    @staticmethod
    def _safe_headers(headers: Any) -> Dict[str, str]:
        """Keep only security-relevant response headers; never persist cookies."""
        allowed = {
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "server",
            "x-powered-by",
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "content-type",
        }
        return {
            str(key): str(value)[:1000]
            for key, value in headers.items()
            if str(key).lower() in allowed
        }

    def run_scan(
        self,
        target: str,
        scan_run: ScanRun,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ScanRun, List[Finding]]:
        self._traffic_plan = None
        self._traffic_probes = (options or {}).get("traffic_probes_approved") is True
        if (options or {}).get("traffic_plan") is not None:
            self._traffic_plan = validate_traffic_plan(target, options["traffic_plan"])
        self._cancel_check = (options or {}).get("cancel_check")
        self._was_cancelled = False
        self._canary_files = []
        for item in (options or {}).get("file_canaries", [])[:10]:
            if (isinstance(item, dict) and item.get("boundary_confirmed") is True
                    and all(isinstance(item.get(k), str) and 0 < len(item[k]) <= 256 for k in ("endpoint", "parameter", "value", "marker"))
                    and len(item["marker"]) >= 24 and item["endpoint"].startswith("/")
                    and not any(x in item["value"].lower() for x in ("/etc/", "windows/", "windows\\", "proc/", "dev/"))):
                self._canary_files.append(item)
        started = time.monotonic()
        scan_run.start_time = datetime.now(timezone.utc).isoformat()
        valid_target, _validation_message, normalized_target = self.validate_target_url(target)
        try:
            parsed = urlparse(normalized_target if valid_target else "")
        except ValueError:
            parsed = urlparse("")
        safe_target = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", "")) if valid_target else "[invalid target]"
        self._scan_metrics = {
            "request_count": 0,
            "response_statuses": [],
            "initial_response_status": None,
            "errors": [],
            "body_limit_hits": 0,
            "body_read_errors": 0,
            "initial_body_failed": False,
        }
        scan_run.raw_command = f"Python {self.name}.audit_url GET {safe_target}; deep_scan={bool((options or {}).get('deep_scan', False))}"
        scan_run.execution_log.append({
            "timestamp": scan_run.start_time,
            "scanner": self.name,
            "scanner_version": self.version,
            "operation": "Bounded live HTTP assessment; redirects disabled; TLS verification enabled; response body capped",
            "target": safe_target,
            "state": "RUNNING",
        })

        findings = self.audit_url(
            target,
            scan_id=scan_run.id,
            progress_callback=(options or {}).get("progress_callback"),
            deep_scan=bool((options or {}).get("deep_scan", False)),
        )

        findings = distinct_findings([Finding.from_dict(sanitize_data(item.to_dict())) for item in findings])
        graph = getattr(self, "_application_map", None)
        if graph:
            snapshot = graph.snapshot()
            scan_run.execution_log.append({"operation": "Application relationships", **snapshot})
            if snapshot["nodes"]:
                findings.append(Finding(scan_id=scan_run.id, title="Application relationship map",
                    description="Same-origin pages, scripts, literal API routes and source maps linked to discovery provenance. References do not prove reachability or authorization.",
                    source_tool=self.name, target=safe_target, severity=FindingSeverity.INFO,
                    severity_source="Observed application relationships", confidence=FindingConfidence.HIGH,
                    confidence_justification="Discovery sources retained with redacted query values.", status=FindingStatus.OBSERVED,
                    evidence_raw=json.dumps(snapshot), evidence_summary=f"{len(snapshot['nodes'])} nodes; {len(snapshot['relationships'])} relationships; truncated={snapshot['truncated']}",
                    remediation="Review discovered components against the agreed scope and declared access expectations."))
        if getattr(self, "_untested_checks", None):
            scan_run.execution_log.append({"operation": "Declared-scenario coverage gaps", "checks": self._untested_checks[:40]})
        scan_run.execution_log.append({
            "operation": "Browser XSS verification", "checks": self._browser_checks,
            "request_count": sum(item["request_count"] for item in self._browser_checks),
            "candidate_limit": MAX_BROWSER_CANDIDATES,
            "coverage": "Only raw HTML reflection candidates from deep GET probes; untested inputs are not declared safe.",
            "request_count_note": "Browser requests are separate from the native HTTP request count.",
        })

        scan_run.end_time = datetime.now(timezone.utc).isoformat()
        scan_run.duration_ms = int((time.monotonic() - started) * 1000)
        scan_run.request_count = int(self._scan_metrics["request_count"])
        scan_run.response_status = self._scan_metrics["initial_response_status"]
        scan_run.findings_count = len(findings)
        coverage_limitation = ""
        if scan_run.response_status is not None and not 200 <= scan_run.response_status < 300:
            if 300 <= scan_run.response_status < 400:
                coverage_limitation = (
                    "The initial redirect was not followed; destination content was not assessed. "
                    "Enter the authorized destination URL for a separate assessment."
                )
            elif scan_run.response_status in {401, 403}:
                coverage_limitation = "The initial response limited access; protected application coverage was not established."
            else:
                coverage_limitation = "The initial response was not successful; normal application content coverage was not established."
        if self._was_cancelled:
            scan_run.status = "CANCELLED"
            scan_run.exit_code = 0
            scan_run.completion_reason = "Cancelled by the assessor; collected evidence retained, remaining checks untested."
        elif self._scan_metrics["initial_response_status"] is None or self._scan_metrics["initial_body_failed"]:
            scan_run.status = "FAILED"
            scan_run.exit_code = -1
            scan_run.error_message = (
                "The initial HTTP response body could not be read completely."
                if self._scan_metrics["initial_body_failed"]
                else "The initial HTTP request did not produce a response."
            )
            scan_run.completion_reason = scan_run.error_message + " This was not a completed security assessment."
        else:
            incomplete = bool(self._scan_metrics["errors"] or self._scan_metrics["body_limit_hits"] or coverage_limitation)
            scan_run.status = "PARTIAL" if incomplete else "COMPLETED"
            scan_run.exit_code = 0
            limitations = []
            if self._scan_metrics["errors"] or self._scan_metrics["body_limit_hits"]:
                limitations.append("HTTP collection had errors or reached the response body limit.")
            if coverage_limitation:
                limitations.append(coverage_limitation)
            scan_run.error_message = " ".join(limitations) or None
            scan_run.completion_reason = (
                f"Live HTTP assessment {scan_run.status.lower()} with {scan_run.request_count} request(s); "
                f"initial HTTP status {scan_run.response_status if scan_run.response_status is not None else 'unavailable'}; "
                f"{len(self._scan_metrics['errors'])} recorded collection error(s); "
                f"{self._scan_metrics['body_limit_hits']} response body limit hit(s)."
            )
            if limitations:
                scan_run.completion_reason += " " + " ".join(limitations)
        self._coverage.record("Native HTTP collection", "FAILED" if scan_run.status == "FAILED" else "INCONCLUSIVE" if scan_run.status in {"PARTIAL", "CANCELLED"} else "COMPLETED", scan_run.completion_reason, scan_run.request_count)
        self._coverage.record("JavaScript assets and mapping", "COMPLETED" if getattr(self, "_collected_scripts_text", []) else "SKIPPED", "Only collected scripts analyzed; static candidates are not runtime exploit proof.")
        self._coverage.record("Browser reflected XSS", "COMPLETED" if self._browser_checks and all(x.get("script_execution_verified") for x in self._browser_checks) else "INCONCLUSIVE" if self._browser_checks else "SKIPPED", "Only selected reflected candidates; inspect per-attempt browser evidence.", sum(x.get("request_count", 0) for x in self._browser_checks))
        for check, reason in (("Stored XSS", "Requires a declared synthetic write/read workflow."), ("Command injection", "No command execution checks are implemented."), ("SSRF callbacks", "Requires an explicitly approved callback receiver; no internal address probes."), ("Business logic and mass assignment", "Requires synthetic reversible workflow and declared expected transitions."), ("Access control and sessions", "Separate declared multi-identity adapter; inspect its session review entry if configured.")):
            self._coverage.record(check, "BLOCKED", reason)
        for check in ("NoSQL injection", "File upload validation", "Host-header trust", "Parser/deserialization exploitation", "Authentication/MFA/reset lifecycle", "GraphQL authorization", "Workflow/race verification"):
            self._coverage.record(check, "BLOCKED", "No reviewed execution module with declared synthetic prerequisites is configured; this class was not tested.")
        if getattr(self, "_collection_stop", None):
            self._coverage.record("Target availability", "BLOCKED", self._collection_stop)
        scan_run.execution_log.append({"operation": "Native request provenance", "requests": getattr(self, "_request_evidence", []),
            "query_values_retained": False, "redirects_followed": False})
        for hypothesis in self._hypotheses:
            hypothesis["finding_ids"] = [f.id for f in findings if f.target == hypothesis["target"] and f.cwe_id == "CWE-209"]
        scan_run.execution_log.append({"operation": "Research hypotheses", "hypotheses": sanitize_data(self._hypotheses),
            "meaning": "Bounded SQL-error research records only. Supported candidates are not verified SQL injection or attack chains."})
        scan_run.execution_log.append(route_coverage(graph.snapshot() if graph else {}, getattr(self, "_request_evidence", []), self._coverage.checks, findings, self._traffic_plan))
        scan_run.execution_log.append(self._coverage.snapshot())
        scan_run.execution_log.append({
            "timestamp": scan_run.end_time,
            "scanner": self.name,
            "operation": "Live HTTP assessment result",
            "state": scan_run.status,
            "request_count": scan_run.request_count,
            "response_status": scan_run.response_status,
            "response_statuses": self._scan_metrics["response_statuses"][:100],
            "request_error_types": self._scan_metrics["errors"],
            "response_body_limit_bytes": MAX_RESPONSE_BYTES,
            "response_body_limit_hits": self._scan_metrics["body_limit_hits"],
            "response_body_read_errors": self._scan_metrics["body_read_errors"],
            "initial_response_coverage_limited": bool(coverage_limitation),
            "initial_response_limitation": coverage_limitation or None,
            "finding_count": scan_run.findings_count,
            "duration_ms": scan_run.duration_ms,
            "reason": scan_run.completion_reason or scan_run.error_message,
        })
        return scan_run, findings
