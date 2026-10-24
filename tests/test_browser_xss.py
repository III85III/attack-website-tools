"""Real signed-browser checks against a disposable loopback fixture only."""
import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from src.adapters.browser_xss import BrowserXSSVerifier, origin
from src.adapters.web_auditor import WebAuditorAdapter
from src.core.models import FindingStatus, ScanRun


@pytest.fixture
def local_target():
    observed = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            observed.append(("GET", parsed.path, self.headers.get("Cookie")))
            value = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
            if parsed.path == "/":
                body = '<a href="/reflect?q=seed">search</a>'
            elif parsed.path == "/escaped":
                body = html.escape(value)
            elif parsed.path == "/attribute":
                body = '<input value="' + value + '">'
            elif parsed.path == "/busy":
                body = value + '<script>while(true){}</script>'
            elif parsed.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/never-follow?q=" + parsed.query)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            elif parsed.path == "/network":
                body = value + ('<script>fetch("/mutate",{method:"POST",body:"x"});'
                                'fetch("http://127.0.0.1:1/offscope");'
                                'new WebSocket("ws://127.0.0.1:1/ws");'
                                'window.open("/popup");</script>')
            else:
                body = value
            encoded = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain" if parsed.path == "/plain" else "text/html; charset=utf-8")
            if parsed.path == "/csp":
                self.send_header("Content-Security-Policy", "script-src 'none'")
            self.send_header("Content-Length", str(len(encoded)))
            if parsed.path == "/give-cookie":
                self.send_header("Set-Cookie", "sid=AUTOMATIC_FIXTURE; Path=/")
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):
            observed.append(("POST", self.path, None))
            self.send_response(500)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", observed
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.fixture(scope="module")
def verifier():
    instance = BrowserXSSVerifier()
    assert instance._discover(), "A signed installed browser is required for release execution verification"
    return instance


@pytest.mark.parametrize("path,confirmed", [("reflect", True), ("attribute", True), ("escaped", False),
                                           ("plain", False), ("csp", False), ("redirect", False)])
def test_actual_browser_proof(local_target, verifier, path, confirmed):
    base, observed = local_target
    result = verifier.verify(base + "/" + path + "?q=PRIVATE_QUERY_VALUE", "q")
    assert result["script_execution_verified"] is confirmed, result
    assert result["request_count"] >= 1, result
    assert all(cookie is None for _, _, cookie in observed)
    assert not any(path == "/never-follow" for _, path, _ in observed)
    assert "PRIVATE_QUERY_VALUE" not in json.dumps(result)
    if confirmed:
        assert result["proof_expected"] == result["proof_observed"]
        assert result["browser_version"]
    else:
        assert result["outcome"] == "INCONCLUSIVE"


def test_browser_blocks_mutations_and_offscope(local_target, verifier):
    base, observed = local_target
    result = verifier.verify(base + "/network?q=seed", "q")
    assert result["script_execution_verified"], result
    assert result["blocked_requests"] >= 2
    assert not any(method == "POST" or path == "/popup" for method, path, _ in observed)


def test_unavailable_browser_keeps_candidate_unconfirmed(monkeypatch):
    monkeypatch.setattr("src.adapters.browser_xss.signed_browser", lambda: None)
    value = BrowserXSSVerifier().verify("http://127.0.0.1/search?q=x", "q")
    assert not value["script_execution_verified"] and value["request_count"] == 0
    assert value["outcome"] == "INCONCLUSIVE"


def test_unresponsive_page_has_a_hard_lifetime(local_target, verifier, monkeypatch):
    import time
    monkeypatch.setattr("src.adapters.browser_xss.BROWSER_LIFETIME_SECONDS", 3)
    base, _ = local_target
    started = time.monotonic()
    result = verifier.verify(base + "/busy?q=seed", "q")
    assert time.monotonic() - started < 15, result
    assert not result["script_execution_verified"]
    assert result.get("cleanup_forced"), result


@pytest.mark.parametrize("url", ["https://user:secret@owned.invalid/?q=x", "file:///test?q=x", "http://localhost:99999/?q=x"])
def test_invalid_candidates_send_no_requests(url):
    result = BrowserXSSVerifier().verify(url, "q")
    assert result["request_count"] == 0


def test_origin_uses_scheme_host_port():
    assert origin("https://OWNED.invalid/a") == ("https", "owned.invalid", 443)
    assert origin("https://owned.invalid:444/") != origin("https://owned.invalid/")


def test_browser_budget_keeps_remaining_reflections_unverified(monkeypatch):
    from types import SimpleNamespace
    from urllib.parse import parse_qs
    calls = []
    def verify(self, url, parameter):
        calls.append(url)
        return {"script_execution_verified": False, "request_count": 0, "reason": "Fixture browser unavailable"}
    monkeypatch.setattr(BrowserXSSVerifier, "verify", verify)
    adapter = WebAuditorAdapter()
    def fetch(url, timeout):
        value = parse_qs(urlsplit(url).query)["q"][0]
        body = value.encode() if value.startswith("SENTINEL-PROBE") else b"safe"
        return SimpleNamespace(content=body, headers={"Content-Type": "text/html"}, encoding="utf-8")
    monkeypatch.setattr(adapter, "_bounded_get", fetch)
    findings = adapter._probe_query_parameters([{"url": f"https://owned.invalid/p{i}?q=private", "names": ["q"]} for i in range(4)], "fixture", None)
    assert len(calls) == 3 and len(findings) == 4
    assert all(item.status == FindingStatus.SCANNER_REPORTED for item in findings)
    assert "limit reached" in findings[-1].evidence_summary


def test_cleanup_never_selects_unrelated_browser(monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace
    from src.adapters.browser_xss import _owned_browser_process
    session = SimpleNamespace(send=lambda _: {"processInfo": [{"type": "browser", "id": 42}]}, detach=lambda: None)
    browser = SimpleNamespace(new_browser_cdp_session=lambda: session)
    monkeypatch.setattr("psutil.Process", lambda: SimpleNamespace(children=lambda recursive: []))
    assert _owned_browser_process(browser, Path("unrelated-browser.exe")) is None


def test_real_adapter_confirms_and_records_separate_browser_requests(local_target):
    base, _ = local_target
    scan, findings = WebAuditorAdapter().run_scan(base, ScanRun(tool_name="Fixture QA", target=base, raw_command=""), {"deep_scan": True})
    confirmed = [item for item in findings if item.title == "Browser-confirmed reflected XSS"]
    assert len(confirmed) == 1
    assert confirmed[0].status == FindingStatus.VALIDATED
    proof = json.loads(confirmed[0].evidence_raw)
    assert proof["script_execution_verified"]
    log = next(item for item in scan.execution_log if item.get("operation") == "Browser XSS verification")
    assert log["request_count"] >= 1
    assert log["checks"][0]["script_execution_verified"]
