"""Bounded anonymous reflected-XSS execution evidence using a signed system browser.

No user profile, browser download, credential forwarding or persistent injection.
Failure to execute is inconclusive, never evidence that a site is XSS-free.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.core.models import ToolHealthInfo

MAX_BROWSER_CANDIDATES = 3
MAX_BROWSER_REQUESTS = 20
BROWSER_LIFETIME_SECONDS = 22


def _owned_browser_process(browser, executable):
    """Find this Playwright browser only; never select a user's existing browser."""
    import psutil
    try:
        session = browser.new_browser_cdp_session()
        try:
            records = session.send("SystemInfo.getProcessInfo")["processInfo"]
        finally:
            session.detach()
        identifier = next(int(item["id"]) for item in records if item["type"] == "browser")
        owned = {process.pid: process for process in psutil.Process().children(recursive=True)}
        process = owned.get(identifier)
        if process and Path(process.exe()).resolve() == executable.resolve():
            return process
    except Exception:
        return None
    return None


def _stop_owned_browser(process, result):
    import psutil
    try:
        if process is not None and process.is_running():
            children = process.children(recursive=True)
            process.kill()  # psutil verifies PID reuse against captured creation time.
            for child in children:
                try:
                    child.kill()
                except psutil.Error:
                    pass
            result["cleanup_forced"] = True
    except psutil.Error:
        result["cleanup_warning"] = "Disposable browser cleanup could not be completed."


def _close_browser(browser, process, result):
    """Give our disposable browser a graceful close, then bound vendor shutdown lag."""
    timer = threading.Timer(3, _stop_owned_browser, args=(process, result))
    timer.daemon = True
    timer.start()
    try:
        browser.close()
    finally:
        timer.cancel()
        timer.join(timeout=1)


def origin(url):
    try:
        item = urlsplit(url)
        if item.scheme not in {"http", "https"} or not item.hostname or item.username or item.password:
            return None
        return item.scheme, item.hostname.lower(), item.port or (443 if item.scheme == "https" else 80)
    except ValueError:
        return None


def signed_browser():
    """Only fixed vendor installation paths; never launch an arbitrary PATH executable."""
    if os.name != "nt":
        return None
    system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = system / "System32/WindowsPowerShell/v1.0/powershell.exe"
    security_module = system / "System32/WindowsPowerShell/v1.0/Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1"
    candidates = [
        (Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"), "Microsoft Corporation"),
        (Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"), "Microsoft Corporation"),
        (Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"), "Google LLC"),
    ]
    for path, publisher in candidates:
        if not path.is_file():
            continue
        command = ("Import-Module '" + str(security_module) + "' -ErrorAction Stop; "
                   "$s=Get-AuthenticodeSignature -LiteralPath '" + str(path) + "'; "
                   "[pscustomobject]@{status=$s.Status.ToString();subject=$s.SignerCertificate.Subject} | ConvertTo-Json -Compress")
        try:
            result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
                                    capture_output=True, text=True, timeout=12,
                                    creationflags=subprocess.CREATE_NO_WINDOW, check=False)
            value = json.loads(result.stdout)
            if result.returncode == 0 and value.get("status") == "Valid" and f"O={publisher}," in value.get("subject", ""):
                return path
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
    return None


class BrowserXSSVerifier:
    name = "Browser XSS verification"

    def __init__(self):
        self._path = None
        self._checked = False

    def _discover(self):
        if not self._checked:
            self._path = signed_browser()
            self._checked = True
        return self._path

    def detect(self):
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            path = self._discover()
        except ImportError:
            path = None
        return ToolHealthInfo(name=self.name, installed=bool(path), path=str(path or ""), version="Runtime checked on use",
                              availability_status="VERSION_CHECK_FAILED" if path else "MISSING",
                              status_message="Signed system browser found; launch checked during an eligible deep scan." if path else
                              "Requires Playwright and a signed system Edge/Chrome. No browser was downloaded.")

    def verify(self, url, parameter):
        result = {"verification_method": "browser_execution_probe", "script_execution_verified": False,
                  "outcome": "INCONCLUSIVE", "request_count": 0, "blocked_requests": 0,
                  "scope": "Anonymous reflected GET input; main document; same origin only",
                  "limitations": "No stored/blind XSS, authenticated coverage or exhaustive DOM analysis; external assets and mutations blocked."}
        allowed_origin = origin(url)
        try:
            parsed = urlsplit(url)
        except ValueError:
            result["reason"] = "Malformed candidate URL; no browser request sent."
            return result
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not allowed_origin or parsed.fragment or "\\" in url or any(c.isspace() for c in url) or not any(k == parameter for k, _ in pairs):
            result["reason"] = "Invalid candidate URL or parameter; no browser request sent."
            return result
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as BrowserTimeout
        except ImportError:
            result["reason"] = "Playwright runtime is unavailable."
            return result
        path = self._discover()
        if not path:
            result["reason"] = "No trusted signed system browser is available."
            return result
        # The evaluator only reads a property. Only the injected input can set it.
        key = "__sentinel_" + secrets.token_hex(12)
        nonce = secrets.token_hex(12)
        a, b = secrets.randbelow(90000) + 10000, secrets.randbelow(90000) + 10000
        expected = str(a * b) + nonce
        payload = f'\"><svg onload="window.{key}=String({a}*{b})+\'{nonce}\'"></svg>'
        probe_url = urlunsplit(parsed._replace(query=urlencode([(k, payload if k == parameter else v) for k, v in pairs])))
        result.update({"proof_key": key, "proof_expected": expected, "payload": payload, "parameter": parameter[:80]})
        started = time.monotonic()
        try:
            with sync_playwright() as runtime:
                browser = runtime.chromium.launch(executable_path=str(path), headless=True, chromium_sandbox=True, timeout=12000)
                owned_process = _owned_browser_process(browser, path)
                deadline = threading.Timer(BROWSER_LIFETIME_SECONDS, _stop_owned_browser, args=(owned_process, result))
                deadline.daemon = True
                deadline.start()
                try:
                    result["browser_version"] = browser.version
                    result["browser_name"] = path.name
                    context = browser.new_context(service_workers="block", accept_downloads=False,
                                                  ignore_https_errors=False, permissions=[])
                    try:
                        page = context.new_page()
                        page.set_default_timeout(2000)
                        page.on("dialog", lambda dialog: dialog.dismiss())
                        # Popup navigation is denied by the route policy below.
                        # Closing a popup synchronously in its creation callback
                        # can deadlock a vendor browser during page.goto.

                        def route_request(route):
                            request = route.request
                            navigation_allowed = True
                            if request.is_navigation_request():
                                try:
                                    navigation_allowed = request.url == probe_url and request.frame == page.main_frame
                                except Exception:
                                    # Popup navigation can arrive before its frame exists.
                                    navigation_allowed = False
                            allowed = (time.monotonic() - started < 22 and origin(request.url) == allowed_origin
                                       and request.method == "GET" and request.redirected_from is None
                                       and result["request_count"] < MAX_BROWSER_REQUESTS
                                       and navigation_allowed)
                            if allowed:
                                result["request_count"] += 1
                                # Browser redirects may bypass route callbacks. Fetch
                                # without redirects and never deliver a 3xx to the page.
                                try:
                                    fetched = route.fetch(max_redirects=0, timeout=7000)
                                    if 300 <= fetched.status < 400 or "attachment" in fetched.headers.get("content-disposition", "").lower():
                                        result["blocked_requests"] += 1
                                        route.abort()
                                    else:
                                        route.fulfill(response=fetched)
                                    fetched.dispose()
                                except Exception:
                                    route.abort()
                            else:
                                result["blocked_requests"] += 1
                                route.abort()

                        context.route("**/*", route_request)
                        def block_websocket(_websocket):
                            # Routed sockets never reach a server unless the
                            # handler explicitly calls connect_to_server().
                            # Synchronous close during the opening handshake
                            # can hang some vendor browser builds.
                            result["blocked_requests"] += 1
                        context.route_web_socket("**/*", block_websocket)
                        try:
                            response = page.goto(probe_url, wait_until="domcontentloaded", timeout=7000)
                            result["response_status"] = response.status if response else None
                            page.wait_for_function("([key, value]) => Object.prototype.hasOwnProperty.call(window, key) && window[key] === value",
                                                   arg=[key, expected], timeout=2000)
                            observed = page.evaluate("key => window[key]", key)
                            if observed == expected and response and 200 <= response.status < 300 and page.url == probe_url:
                                result.update({"script_execution_verified": True, "outcome": "CONFIRMED", "proof_observed": observed,
                                               "reason": "The injected input executed in the main document and computed the expected unique value."})
                        except BrowserTimeout:
                            result["reason"] = "The browser did not observe execution within the bounded window; this does not exclude XSS."
                        if not result["script_execution_verified"] and "reason" not in result:
                            result["reason"] = "Execution was not confirmed in a successful main-document response."
                    finally:
                        context.close()
                finally:
                    try:
                        _close_browser(browser, owned_process, result)
                    finally:
                        deadline.cancel()
                        deadline.join(timeout=1)
        except Exception as exc:
            # Browser errors can include raw URLs, query secrets and server text.
            if result["script_execution_verified"]:
                result["cleanup_warning"] = f"Browser shutdown reported {type(exc).__name__}; observed execution proof is retained."
            else:
                result["reason"] = f"Browser verification unavailable or interrupted ({type(exc).__name__}); candidate remains unverified."
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result
