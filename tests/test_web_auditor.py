"""
Unit tests for WebAuditorAdapter.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.adapters.web_auditor import WebAuditorAdapter
from src.core.models import FindingSeverity


def test_url_normalization():
    auditor = WebAuditorAdapter()
    assert auditor.normalize_url("example.com") == "http://example.com"
    assert auditor.normalize_url("https://example.com") == "https://example.com"
    assert auditor.normalize_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_unknown_response_charset_does_not_abort_query_review():
    from src.adapters.web_auditor import _probe_text
    response = SimpleNamespace(content=b"<p>marker</p>", encoding="not-a-real-charset")
    assert _probe_text(response) == "<p>marker</p>"


@patch("requests.Session.get")
def test_web_audit_detects_missing_headers(mock_get):
    # Mock response lacking security headers and leaking server version
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "Content-Type": "text/html",
    }
    mock_resp.cookies = []
    mock_resp.text = "<html><body>Hello Test</body></html>"
    mock_get.return_value = mock_resp

    auditor = WebAuditorAdapter()
    findings = auditor.audit_url("http://test.local")

    # Should detect:
    # 1. Insecure HTTP transport
    # 2. Missing CSP
    # 3. Missing X-Frame-Options
    # 4. Missing X-Content-Type-Options: nosniff
    # 5. Server banner leakage (Apache 2.4.41)
    # 6. X-Powered-By leakage (PHP 7.4.3)
    titles = [f.title for f in findings]

    assert any("Insecure Unencrypted Transport" in t for t in titles)
    assert any("Missing Content-Security-Policy" in t for t in titles)
    assert any("Missing Clickjacking Defense" in t for t in titles)
    assert any("Missing X-Content-Type-Options" in t for t in titles)
    assert any("Detailed Server Banner Disclosed" in t for t in titles)
    assert any("Technology Stack Disclosure" in t for t in titles)


@patch("requests.Session.get")
def test_cookie_flags_audit(mock_get):
    mock_cookie = MagicMock()
    mock_cookie.name = "session_id"
    mock_cookie.secure = False
    mock_cookie.has_nonstandard_attr.return_value = False
    mock_cookie._rest = {}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    mock_resp.cookies = [mock_cookie]
    mock_resp.text = "OK"
    mock_get.return_value = mock_resp

    auditor = WebAuditorAdapter()
    findings = auditor.audit_url("https://secure.local")

    titles = [f.title for f in findings]
    assert any("Cookie 'session_id' Missing HttpOnly Flag" in t for t in titles)
    assert any("Cookie 'session_id' Missing Secure Flag" in t for t in titles)


def test_deep_scan_reports_arbitrary_cors_origin_reflection():
    auditor = WebAuditorAdapter()
    response = SimpleNamespace(
        headers={
            "Access-Control-Allow-Origin": "https://sentinel.invalid",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    auditor._bounded_get = MagicMock(return_value=response)

    findings = auditor._check_cors("https://owned.test", "scan-1")

    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].cwe_id == "CWE-942"
    assert "credentialed" in findings[0].evidence_summary


@patch("src.adapters.web_auditor.BrowserXSSVerifier.verify", return_value={"script_execution_verified": False, "request_count": 0, "reason": "Unavailable in unit fixture"})
def test_deep_query_probe_reports_reflection_without_storing_query_value(_browser_verify):
    auditor = WebAuditorAdapter()
    calls = []

    def bounded_get(url, timeout, headers=None):
        calls.append(url)
        from urllib.parse import parse_qs, urlparse
        value = parse_qs(urlparse(url).query, keep_blank_values=True)["q"][0]
        if value.startswith("SENTINEL-PROBE"):
            body = f"<p>{value}</p>".encode()
            return SimpleNamespace(content=body, headers={"Content-Type": "text/html"}, encoding="utf-8")
        return SimpleNamespace(content=b"<p>search complete</p>", headers={"Content-Type": "text/html"}, encoding="utf-8")

    auditor._bounded_get = bounded_get
    findings = auditor._probe_query_parameters(
        [{"url": "https://owned.test/search?q=private-value", "names": ["q"]}], "scan-1", None
    )

    assert len(calls) == 2
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-79"
    assert "private-value" not in findings[0].target
    assert "private-value" not in findings[0].evidence_raw


def test_deep_query_probe_marks_database_error_as_candidate_only():
    auditor = WebAuditorAdapter()

    def bounded_get(url, timeout, headers=None):
        from urllib.parse import parse_qs, urlparse
        value = parse_qs(urlparse(url).query, keep_blank_values=True)["id"][0]
        body = b"<p>safe</p>" if value.startswith("SENTINEL-PROBE") else b"You have an error in your SQL syntax"
        return SimpleNamespace(content=body, headers={"Content-Type": "text/html"}, encoding="utf-8")

    auditor._bounded_get = bounded_get
    findings = auditor._probe_query_parameters(
        [{"url": "https://owned.test/item?id=123", "names": ["id"]}], "scan-1", None
    )

    assert len(findings) == 1
    assert "Verbose MySQL error" in findings[0].title
    assert findings[0].cwe_id == "CWE-209"
    assert "does not prove exploitable" in findings[0].description


def test_crawler_discovers_query_parameter_names_without_persisting_values():
    auditor = WebAuditorAdapter()
    page = SimpleNamespace(
        status_code=200,
        headers={"Content-Type": "text/html; charset=utf-8"},
        text='<a href="/search?q=secret&tab=private">Search</a>',
    )
    auditor._bounded_get = MagicMock(return_value=page)

    inventory = auditor._crawl_same_origin("https://owned.test/", page, None)

    assert inventory["input_points"] == [
        {"url": "https://owned.test/search?q=secret&tab=private", "names": ["q", "tab"]}
    ]
