"""
III85III QOLAM SENTINEL — Native Web Security Auditor
Comprehensive, zero-API web application vulnerability, headers, cookies, and exposure auditor.
"""
from __future__ import annotations

import re
import hashlib
import json
import time
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from src.adapters.base import BaseToolAdapter
from src.adapters.browser_xss import BrowserXSSVerifier, MAX_BROWSER_CANDIDATES
from src.core.cve_intel import CVEIntelligenceEngine
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)


MAX_CRAWL_PAGES = 25
MAX_RESPONSE_BYTES = 1_000_000
CRAWL_DELAY_SECONDS = 0.20
MAX_ACTIVE_PARAMETERS = 10
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
        self._form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        elif tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": values.get("method", "get").lower(),
                "password_field": False,
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and values.get("type", "").lower() == "password":
            self._form["password_field"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


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
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) III85III-QolamSentinel/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self._scan_metrics: Dict[str, Any] = {}
        self._browser_checks: List[Dict[str, Any]] = []

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
        self._browser_checks = []
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

        # Crawl a bounded number of same-origin HTML pages. The crawler issues
        # GET requests only; it never submits forms or follows redirects.
        inventory = self._crawl_same_origin(url, resp, progress_callback)
        if inventory["pages"]:
            findings.append(self._inventory_finding(url, scan_id, inventory))
            password_forms = inventory["http_password_forms"]
            if password_forms:
                findings.append(Finding(
                    scan_id=scan_id,
                    title=f"Password form served over unencrypted HTTP on {domain}",
                    description=(
                        f"The same-origin crawl found {password_forms} HTML password form(s) served over HTTP. "
                        "A browser may submit credentials without transport encryption. Sentinel did not submit any form."
                    ),
                    source_tool=self.name,
                    tool_version=self.version,
                    target=url,
                    severity=FindingSeverity.HIGH,
                    severity_source="Observed HTTP origin and password input field",
                    confidence=FindingConfidence.HIGH,
                    confidence_justification="The page response was served over HTTP and contained an input[type=password]; no credentials were entered or transmitted by Sentinel.",
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
            findings.extend(self._check_cors(url, scan_id))
            findings.extend(self._probe_query_parameters(inventory.get("input_points", []), scan_id, progress_callback))

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

        # 5. Sensitive File & Endpoint Probing (Safe Heuristic Checks)
        if progress_callback:
            progress_callback("Checking sensitive file & endpoint exposures...")

        sensitive_paths = [
            ("robots.txt", "Robots Exclusion File"),
            (".git/HEAD", "Exposed Git Repository Metadata"),
            (".env", "Exposed Environment Configuration File"),
            (".well-known/security.txt", "Security Disclosure Contact File"),
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
            except requests.RequestException as exc:
                if self._scan_metrics and not isinstance(exc, requests.RequestException) and len(self._scan_metrics["errors"]) < 20:
                    self._scan_metrics["errors"].append(type(exc).__name__)
                continue

        return findings

    def _bounded_get(self, url: str, timeout: int, headers: Optional[Dict[str, str]] = None) -> Any:
        """Fetch a response without redirects and cap its in-memory body size."""
        if self._scan_metrics:
            self._scan_metrics["request_count"] += 1
        try:
            response = self.session.get(
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
            if page_has_password_form:
                password_form_paths.append(parsed.path or "/")

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
                if candidate_origin != origin:
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
        }

    def _check_cors(self, url: str, scan_id: Optional[str]) -> List[Finding]:
        """Check for arbitrary-origin CORS reflection with a non-credentialed GET."""
        probe_origin = "https://sentinel.invalid"
        try:
            response = self._bounded_get(url, timeout=6, headers={"Origin": probe_origin})
        except requests.RequestException:
            return []
        allow_origin = response.headers.get("Access-Control-Allow-Origin", "").strip()
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        if allow_origin != probe_origin:
            return []
        confidence = FindingConfidence.HIGH if allow_credentials else FindingConfidence.MEDIUM
        severity = FindingSeverity.HIGH if allow_credentials else FindingSeverity.LOW
        condition = "with credentialed cross-origin access enabled" if allow_credentials else "without credentialed cross-origin access"
        return [Finding(
            scan_id=scan_id,
            title="CORS policy reflects an arbitrary Origin",
            description=(
                "The server returned the caller-supplied Origin unchanged. This may allow an untrusted website to read responses; "
                "impact depends on the protected data, credentials policy, and browser behavior. Sentinel sent no credentials."
            ),
            source_tool=self.name,
            tool_version=self.version,
            target=url,
            severity=severity,
            severity_source="Observed Access-Control-Allow-Origin response to a controlled Origin probe",
            confidence=confidence,
            confidence_justification=f"Access-Control-Allow-Origin reflected {probe_origin}; {condition}.",
            status=FindingStatus.SCANNER_REPORTED,
            evidence_raw=json.dumps({
                "access_control_allow_origin": allow_origin,
                "access_control_allow_credentials": allow_credentials,
                "probe_origin": probe_origin,
            }),
            evidence_summary=f"Arbitrary Origin was reflected {condition}.",
            cwe_id="CWE-942",
            remediation="Allow only explicitly trusted origins and avoid credentialed CORS unless required; verify access from an untrusted browser origin.",
        )]

    def _probe_query_parameters(
        self,
        input_points: List[Dict[str, Any]],
        scan_id: Optional[str],
        progress_callback: Optional[Any],
    ) -> List[Finding]:
        """Run capped, non-destructive GET probes on discovered query parameters."""
        findings: List[Finding] = []
        tested = 0
        browser_verifier = BrowserXSSVerifier()
        for point in input_points:
            original = urlparse(point["url"])
            pairs = parse_qsl(original.query, keep_blank_values=True)
            for parameter in point["names"]:
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
                    findings.append(Finding(
                        scan_id=scan_id,
                        title="Potential unescaped reflected input",
                        description=(
                            "A unique inert HTML marker supplied through a query parameter was returned unescaped in an HTML response. "
                            "This is an XSS candidate, not proof of script execution; browser context and client-side handling require review."
                        ),
                        source_tool=self.name,
                        tool_version=self.version,
                        target=safe_target,
                        severity=FindingSeverity.MEDIUM,
                        severity_source="Reflected inert marker in text/html response",
                        confidence=FindingConfidence.MEDIUM,
                        confidence_justification="The exact random probe marker, including raw angle brackets, appeared in the response HTML; no script payload was sent or executed.",
                        status=FindingStatus.SCANNER_REPORTED,
                        evidence_raw=json.dumps({"parameter": parameter[:80], "marker_reflected_raw": True,
                                                 "verification_method": "inert_marker_reflection", "script_execution_verified": False,
                                                 "response_sha256": hashlib.sha256(response.content).hexdigest()}),
                        evidence_summary=f"An inert marker was reflected without HTML escaping for parameter {parameter[:80]!r}; manually verify its output context.",
                        cwe_id="CWE-79",
                        remediation="Apply context-aware output encoding and validate the sink in a browser; do not rely on input filtering alone.",
                    ))
                    candidate = findings[-1]
                    if len(self._browser_checks) < MAX_BROWSER_CANDIDATES:
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

                quote_pairs = [(name, "'" if name == parameter else value) for name, value in pairs]
                quote_url = urlunparse(original._replace(query=urlencode(quote_pairs, doseq=True)))
                time.sleep(CRAWL_DELAY_SECONDS)
                try:
                    quote_response = self._bounded_get(quote_url, timeout=6)
                except requests.RequestException:
                    continue
                quote_body = _probe_text(quote_response).casefold()
                matched_engine = next((engine for engine, signatures in SQL_ERROR_SIGNATURES.items() if any(signature in quote_body for signature in signatures)), None)
                if matched_engine:
                    findings.append(Finding(
                        scan_id=scan_id,
                        title=f"Verbose {matched_engine} error after quote input",
                        description="A database-specific error signature appeared after a single-quote query input. This may indicate unsafe query handling or verbose error disclosure; it does not prove exploitable SQL injection.",
                        source_tool=self.name,
                        tool_version=self.version,
                        target=safe_target,
                        severity=FindingSeverity.MEDIUM,
                        severity_source="Database error signature in response to a non-destructive quote probe",
                        confidence=FindingConfidence.MEDIUM,
                        confidence_justification=f"Response matched a known {matched_engine} error signature; no data-modifying SQL payloads were sent.",
                        status=FindingStatus.SCANNER_REPORTED,
                        evidence_raw=json.dumps({"parameter": parameter[:80], "database_signature": matched_engine, "response_sha256": hashlib.sha256(quote_response.content).hexdigest()}),
                        evidence_summary=f"A {matched_engine} error signature was returned; response content and user data were not stored.",
                        cwe_id="CWE-209",
                        remediation="Use parameterized queries and return generic client errors while logging detailed exceptions server-side.",
                    ))
        return findings

    @staticmethod
    def _web_origin(parsed: Any) -> Optional[Tuple[str, str, int]]:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
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
                f"Sentinel crawled up to {MAX_CRAWL_PAGES} same-origin HTML pages to map the reachable surface. "
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
        if self._scan_metrics["initial_response_status"] is None or self._scan_metrics["initial_body_failed"]:
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
