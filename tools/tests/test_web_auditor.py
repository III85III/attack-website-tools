"""
Unit tests for WebAuditorAdapter.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.adapters.web_auditor import WebAuditorAdapter
from src.core.models import FindingConfidence, FindingSeverity


def test_url_normalization():
    auditor = WebAuditorAdapter()
    assert auditor.normalize_url("example.com") == "http://example.com"
    assert auditor.normalize_url("https://example.com") == "https://example.com"
    assert auditor.normalize_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_unknown_response_charset_does_not_abort_query_review():
    from src.adapters.web_auditor import _probe_text
    response = SimpleNamespace(status_code=200, content=b"<p>marker</p>", encoding="not-a-real-charset")
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
    auditor=WebAuditorAdapter()
    def fetch(url,timeout,headers):
        return _fixture_response(headers={"Access-Control-Allow-Origin":headers["Origin"] if headers["Origin"]!="null" else "", "Access-Control-Allow-Credentials":"true"})
    auditor._bounded_get=fetch
    findings=auditor._check_cors("https://owned.test","scan-1")
    assert len(findings)==1 and findings[0].severity==FindingSeverity.MEDIUM
    assert findings[0].cwe_id=="CWE-942" and findings[0].status.value=="POTENTIAL"



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
            return SimpleNamespace(status_code=200, content=body, headers={"Content-Type": "text/html"}, encoding="utf-8")
        return SimpleNamespace(status_code=200, content=b"<p>search complete</p>", headers={"Content-Type": "text/html"}, encoding="utf-8")

    auditor._bounded_get = bounded_get
    findings = auditor._probe_query_parameters(
        [{"url": "https://owned.test/search?q=private-value", "names": ["q"]}], "scan-1", None
    )

    assert len(calls) == 8  # Reflection, four SQL controls and three template syntaxes.
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-79"
    assert "private-value" not in findings[0].target
    assert "private-value" not in findings[0].evidence_raw


def test_deep_query_probe_marks_database_error_as_candidate_only():
    auditor = WebAuditorAdapter()

    def bounded_get(url, timeout, headers=None):
        from urllib.parse import parse_qs, urlparse
        value = parse_qs(urlparse(url).query, keep_blank_values=True)["id"][0]
        body = b"You have an error in your SQL syntax" if value == "'" else b"<p>safe</p>"
        return SimpleNamespace(status_code=200, content=body, headers={"Content-Type": "text/html"}, encoding="utf-8")

    auditor._bounded_get = bounded_get
    findings = auditor._probe_query_parameters(
        [{"url": "https://owned.test/item?id=123", "names": ["id"]}], "scan-1", None
    )

    assert len(findings) == 1
    assert "Reproducible MySQL error" in findings[0].title
    assert findings[0].cwe_id == "CWE-209"
    assert "remain unverified" in findings[0].description


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


def test_open_redirect_probe_detection():
    from urllib.parse import urlsplit,parse_qs
    auditor=WebAuditorAdapter()
    def fetch(url,timeout,**kwargs):
        value=parse_qs(urlsplit(url).query)["redirect_uri"][0]
        return _fixture_response(status=302,headers={"Location":value}) if value.startswith("https://obsidian.invalid/proof/") else _fixture_response()
    auditor._bounded_get=fetch
    findings=auditor._probe_query_parameters([{"url":"https://owned.test/login?redirect_uri=home","names":["redirect_uri"]}],"fixture",None)
    assert any(row.cwe_id=="CWE-601" and row.status.value=="VALIDATED" for row in findings)



def test_ssti_arithmetic_probe_detection():
    import re
    from urllib.parse import urlsplit,parse_qs
    auditor=WebAuditorAdapter()
    def fetch(url,timeout,**kwargs):
        value=parse_qs(urlsplit(url).query)["name"][0]
        return _fixture_response(re.sub(r"\{\{(\d+)\*(\d+)\}\}",lambda m:str(int(m[1])*int(m[2])),value))
    auditor._bounded_get=fetch
    findings=auditor._probe_query_parameters([{"url":"https://owned.test/render?name=guest","names":["name"]}],"fixture",None)
    found=next(row for row in findings if row.cwe_id=="CWE-1336")
    import json
    assert len(json.loads(found.evidence_raw)["challenges"])==2 and found.status.value=="POTENTIAL"



def test_javascript_asset_analysis_detects_routes_and_source_maps():
    import json
    auditor=WebAuditorAdapter()
    synthetic_key="AKIA"+"Z"*16
    code='const api="/api/v1/users"; const key="'+synthetic_key+'";\n//# sourceMappingURL=bundle.js.map'
    def fetch(url,timeout):
        return _fixture_response(json.dumps({"version":3,"sources":["app.ts"],"mappings":"AAAA"})) if url.endswith(".map") else _fixture_response(code)
    auditor._bounded_get=fetch
    findings=auditor._audit_javascript_assets("https://owned.test",scripts=["https://owned.test/bundle.js"])
    assert any(row.title=="Exposed JavaScript Source Map" for row in findings)
    assert any("API Routes" in row.title for row in findings)
    key=next(row for row in findings if "AWS Access Key" in row.title)
    assert synthetic_key not in key.evidence_raw and "[REDACTED]" in key.evidence_raw



def test_passive_subdomain_intelligence(monkeypatch):
    import json
    auditor=WebAuditorAdapter()
    response=MagicMock(status_code=200)
    response.raw.read.return_value=json.dumps([{"name_value":"api.example.com\nadmin.example.com"},{"name_value":"*.internal.example.com"}]).encode()
    http=MagicMock();http.get.return_value=response;http.__enter__.return_value=http
    monkeypatch.setattr("src.adapters.web_auditor.requests.Session",lambda:http)
    findings=auditor._audit_subdomains("example.com","fixture")
    assert len(findings)==1 and "api.example.com" in findings[0].description
    assert json.loads(findings[0].evidence_raw)["active_testing_authorized"] is False
    assert http.get.call_args.kwargs["allow_redirects"] is False



def test_probe_query_parameters_path_traversal():
    from urllib.parse import unquote
    auditor=WebAuditorAdapter()
    auditor._bounded_get=lambda url,timeout,**kwargs:_fixture_response("root:x:0:0:[SYNTHETIC]" if "etc/passwd" in unquote(url) else "safe")
    findings=auditor._probe_query_parameters([{"url":"https://owned.test/view?file=intro.txt","names":["file"]}],"fixture",None)
    assert not any(row.cwe_id=="CWE-22" for row in findings)
    assert any(row["check"] == "File boundary canary" and row["state"] == "BLOCKED" for row in auditor._coverage.checks)



def test_probe_query_parameters_ssrf_indicator():
    from urllib.parse import unquote
    auditor=WebAuditorAdapter();calls=[]
    def fetch(url,timeout,**kwargs):
        calls.append(unquote(url));return _fixture_response()
    auditor._bounded_get=fetch
    findings=auditor._probe_query_parameters([{"url":"https://owned.test/fetch?url=safe","names":["url"]}],"fixture",None)
    assert not any("127.0.0.1" in url or "169.254." in url for url in calls)
    assert not any(row.cwe_id=="CWE-918" for row in findings)
    assert auditor._untested_checks[0]["outcome"]=="NOT_TESTED"



def test_probe_query_parameters_crlf_injection():
    import re
    from urllib.parse import urlsplit,parse_qs
    auditor=WebAuditorAdapter()
    def fetch(url,timeout,**kwargs):
        value=parse_qs(urlsplit(url).query)["url"][0]
        found=re.search(r"sentinel_crlf_probe=([a-f0-9]+)",value)
        return _fixture_response(headers={"Set-Cookie":"sentinel_crlf_probe="+found[1]}) if found else _fixture_response()
    auditor._bounded_get=fetch
    findings=auditor._probe_query_parameters([{"url":"https://owned.test/out?url=home","names":["url"]}],"fixture",None)
    assert any(row.cwe_id=="CWE-113" for row in findings)



def test_jwt_audit_alg_none_and_missing_exp():
    import base64
    import json
    auditor = WebAuditorAdapter()

    # Create unsecured JWT with alg: none and missing exp
    hdr_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "role": "root", "password_hash": "abc"}).encode()).decode().rstrip("=")
    token = f"{hdr_b64}.{payload_b64}."

    headers = {"Authorization": f"Bearer {token}"}
    cookies = []
    scripts = []

    findings = auditor._audit_jwt_tokens("https://example.com", cookies, headers, scripts, scan_id="scan-jwt")

    cwes = [f.cwe_id for f in findings]
    assert "CWE-327" in cwes  # alg: none
    assert "CWE-613" in cwes  # missing exp
    assert "CWE-312" in cwes  # password_hash exposed in payload

    none_finding = next(f for f in findings if f.cwe_id == "CWE-327")
    assert none_finding.severity == FindingSeverity.CRITICAL


def test_csrf_forms_audit():
    auditor = WebAuditorAdapter()
    csrf_forms = [
        {"action": "https://example.com/transfer", "inputs": [{"name": "amount"}, {"name": "to"}]}
    ]
    cookies = []

    findings = auditor._audit_csrf_forms("example.com", csrf_forms, cookies, scan_id="scan-csrf")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-352"
    assert "Anti-CSRF" in findings[0].title


def test_bfla_and_verbs_audit():
    auditor = WebAuditorAdapter()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 403  # GET restricted
        return resp

    def mock_head(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200  # HEAD bypass
        return resp

    def mock_post(url, **kwargs):
        resp = MagicMock()
        headers = kwargs.get("headers", {})
        if headers.get("X-HTTP-Method-Override") == "GET":
            resp.status_code = 200  # Override bypass
        else:
            resp.status_code = 403
        return resp

    auditor.session.get = mock_get
    auditor.session.head = mock_head
    auditor.session.post = mock_post

    findings = auditor._audit_bfla_and_verbs("https://example.com", scan_id="scan-bfla")
    assert len(findings) >= 2
    cwes = [f.cwe_id for f in findings]
    assert "CWE-285" in cwes


def test_dependency_manifest_cve_correlation():
    import json
    auditor = WebAuditorAdapter()
    pkg_json = json.dumps({
        "name": "vulnerable-app",
        "dependencies": {
            "lodash": "4.17.15",
            "axios": "0.19.0"
        }
    })

    findings = auditor._audit_dependency_manifest(
        "https://example.com/package.json",
        "package.json",
        pkg_json,
        scan_id="scan-dep"
    )

    assert len(findings) == 2
    cves = [f.cve_id for f in findings]
    assert "CVE-2021-23337" in cves
    assert "CVE-2020-28168" in cves


def test_api_excessive_data_exposure():
    auditor = WebAuditorAdapter()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.json.return_value = {
        "status": "success",
        "user": {
            "id": 101,
            "username": "alice",
            "password_hash": "$2a$12$e8ZbzPZ6.K...",
            "is_admin": True
        }
    }
    auditor._bounded_get = MagicMock(return_value=mock_resp)

    findings = auditor._audit_api_data_exposure(
        "https://example.com",
        ["/api/v1/profile"],
        scan_id="scan-exp"
    )

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-200"
    assert "Excessive Data Exposure" in findings[0].title
    assert "password_hash" in findings[0].evidence_summary


def _fixture_response(body="safe", status=200, headers=None):
    import requests
    response=requests.Response()
    response.status_code=status
    response._content=body.encode()
    response.encoding="utf-8"
    response.headers.update(headers or {"Content-Type":"text/html"})
    return response
