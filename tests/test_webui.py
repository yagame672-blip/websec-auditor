"""Web UI handler tests: CSRF token, strict origin, rate limiting, deployment gating."""
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from websec_auditor import webui

PORT = 8137
BASE = f"http://127.0.0.1:{PORT}"
UI_RATE_MAX = webui.UI_RATE_MAX


@pytest.fixture(scope="module")
def ui_server():
    os.environ.pop("VERCEL", None)
    os.environ.pop("AWS_LAMBDA_FUNCTION_NAME", None)
    import importlib
    importlib.reload(webui)
    srv = webui.ThreadingHTTPServer(("127.0.0.1", PORT), webui.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    yield srv
    srv.shutdown()
    srv.server_close()


def _post(path, data, origin=None, host=f"127.0.0.1:{PORT}", extra_headers=None):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Host", host)
    if origin:
        req.add_header("Origin", origin)
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")


def test_get_contains_csrf_token(ui_server):
    html = urllib.request.urlopen(f"{BASE}/", timeout=10).read().decode("utf-8", "ignore")
    assert webui.CSRF_TOKEN in html
    assert "csrf_sec_token_websec_auditor" not in html  # static placeholder gone


def test_missing_token_rejected(ui_server):
    st, _ = _post("/code-review", {"code": "x=1"}, origin=BASE)
    assert st == 403


def test_wrong_token_rejected(ui_server):
    st, _ = _post("/code-review", {"code": "x=1", "_token": "bogus"}, origin=BASE)
    assert st == 403


def test_evil_vercel_origin_rejected(ui_server):
    st, _ = _post("/code-review", {"code": "x=1", "_token": webui.CSRF_TOKEN},
                  origin="https://evil.vercel.app")
    assert st == 403


def test_foreign_origin_rejected(ui_server):
    st, _ = _post("/code-review", {"code": "x=1", "_token": webui.CSRF_TOKEN},
                  origin="https://attacker.example")
    assert st == 403


def test_same_origin_with_token_allowed(ui_server):
    st, body = _post("/code-review", {"code": "x = 1", "filename": "a.py",
                                      "_token": webui.CSRF_TOKEN}, origin=BASE)
    assert st == 200


def test_rate_limit_triggers_429(ui_server):
    # 13 rapid requests; Windows can occasionally reset a keep-alive socket
    # under this burst, so retry an aborted request once before counting it.
    codes = []
    for _ in range(UI_RATE_MAX + 3):
        st = -1
        for attempt in range(2):
            try:
                st, _ = _post("/code-review", {"code": "x = 1", "filename": "a.py",
                                               "_token": webui.CSRF_TOKEN}, origin=BASE,
                              extra_headers={"X-Real-IP": "10.9.9.9"})
                break
            except (ConnectionAbortedError, BrokenPipeError):
                continue
        codes.append(st)
    assert 429 in codes


def test_self_harden_disabled_when_deployed(ui_server):
    os.environ["VERCEL"] = "1"
    import importlib
    importlib.reload(webui)
    try:
        srv = webui.ThreadingHTTPServer(("127.0.0.1", 8138), webui.Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        time.sleep(0.4)
        try:
            body = urllib.parse.urlencode({"_token": webui.CSRF_TOKEN}).encode()
            req = urllib.request.Request("http://127.0.0.1:8138/self-harden",
                                         data=body, method="POST")
            req.add_header("Origin", "http://127.0.0.1:8138")
            try:
                r = urllib.request.urlopen(req, timeout=10)
                assert r.status == 403
            except urllib.error.HTTPError as e:
                assert e.code == 403
        finally:
            srv.shutdown()
            srv.server_close()
    finally:
        del os.environ["VERCEL"]
