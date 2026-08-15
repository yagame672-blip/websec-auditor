"""Scanner engine tests against the flawed demo server."""
from websec_auditor import netsafe
from websec_auditor.analyzer.analyze import analyze
from websec_auditor.scanner import engine


def _names(scan_result, status=None):
    out = []
    for f in scan_result.findings:
        if status is None or f.status == status:
            out.append(f.name)
    return out


def test_scan_demo_finds_core_issues(demo_server):
    with netsafe.private_allowed(True):
        res = engine.scan(demo_server, custom_headers=None)
    names = [f.name for f in res.findings if f.status == "fail"]
    assert any(n.startswith("Missing header:") for n in names)
    assert any(n.startswith("Missing cookie flag:") for n in names)
    assert "Session response is cacheable" in names
    assert res.target == demo_server


def test_scan_demo_xss_and_sqli_surfaces(demo_server):
    # The demo's /search reflects the 'q' parameter unencoded and leaks a SQL
    # error for a bare quote. Probe the bare URL so the engine appends markers
    # to 'q' (a pre-filled ?q= would make the demo ignore the appended value).
    with netsafe.private_allowed(True):
        res = engine.scan(f"{demo_server}/search", custom_headers=None)
    names = [f.name for f in res.findings if f.status == "fail"]
    joined = " ".join(names)
    assert "Reflected XSS surface confirmed" in names or "SQL error signature exposed" in names


def test_scan_rejects_private_without_local_scope(demo_server):
    # Without private_allowed, scanning loopback must fail cleanly.
    res = engine.scan(demo_server, custom_headers=None)
    assert any(f.status == "fail" and f.name == "Target unreachable" for f in res.findings)


def test_analyze_grounds_findings(demo_server):
    with netsafe.private_allowed(True):
        res = engine.scan(demo_server, custom_headers=None)
    en = analyze(res)
    assert len(en) > 0
    assert all("finding" in e and "citations" in e for e in en)


def _error_leak_names(body):
    res = engine.ScanResult(target="https://example.test")
    engine.check_error_body_leak(res, 403, body)
    return [f.name for f in res.findings if f.status == "fail"]


def test_error_page_leaks_python_traceback_is_flagged():
    # WSTG-ERRH-02 + CWE-209: a stack trace in an error body is a real leak even
    # when the status is an edge/WAF block page.
    names = _error_leak_names(
        "Traceback (most recent call last):\n  File \"/app/main.py\", line 42, in handle\n    raise ValueError()"
    )
    assert any(n == "Error page leaks internals (HTTP 403)" for n in names)


def test_error_page_leaks_sql_error_is_flagged():
    names = _error_leak_names("You have an error in your SQL syntax; check the manual")
    assert any(n == "Error page leaks internals (HTTP 403)" for n in names)


def test_error_page_framework_debug_page_is_flagged():
    # FRAMEWORK_ERROR_SIGNATURES must still fire on error responses (CWE-200).
    names = _error_leak_names("<h1>Whitelabel Error Page</h1>This application has no explicit mapping")
    assert any(n.startswith("Framework debug page exposed:") for n in names)


def test_clean_block_page_is_not_flagged():
    # A sanitized edge block page with no internals leaks must not be a finding.
    names = _error_leak_names("Access denied. Your request has been blocked by security policy.")
    assert names == []


class _FakeResp:
    def __init__(self, code, headers=None):
        self._code = code
        self.headers = headers or {}

    def getcode(self):
        return self._code


def _run_rate_limit(monkeypatch, fake_get):
    monkeypatch.setattr(engine, "_get", fake_get)
    res = engine.ScanResult(target="https://example.test")
    engine.check_rate_limiting(res, "https://example.test")
    return [(f.status, f.severity, f.name) for f in res.findings]


def test_rate_limit_403_burst_with_blocked_gentle_is_not_a_gap(monkeypatch):
    # WAF expresses throttling as 403 and even the gentle probe stays blocked.
    # That IS a backoff signal, so it must never become the KB "absence of any
    # backoff" hardening gap (CWE-307 false positive).
    results = _run_rate_limit(monkeypatch, lambda *a, **k: _FakeResp(403))
    assert ("info", "info", "Rate limiting / bot protection pushback observed") in results
    assert not any(n.startswith("No rate-limit backoff") for _, _, n in results)


def test_rate_limit_403_burst_with_ok_gentle_is_enforced(monkeypatch):
    calls = {"n": 0}

    def fake_get(url, timeout=10, custom_headers=None, method=None):
        calls["n"] += 1
        return _FakeResp(200 if calls["n"] > 3 else 403)

    results = _run_rate_limit(monkeypatch, fake_get)
    assert ("pass", "info", "Rate limiting enforced") in results


def test_rate_limit_normal_burst_is_still_reported_as_gap(monkeypatch):
    # A burst answered entirely with 2xx, no headers, no pushback: per the KB
    # OWASP-RATELIMIT-DEEP passage the "absence of any backoff signal" is the
    # hardening gap worth reporting.
    results = _run_rate_limit(monkeypatch, lambda *a, **k: _FakeResp(200))
    assert ("warn", "medium", "No rate-limit backoff observed") in results


def test_rate_limit_advertised_via_headers(monkeypatch):
    results = _run_rate_limit(
        monkeypatch, lambda *a, **k: _FakeResp(200, {"ratelimit-limit": "10", "ratelimit-remaining": "9"}))
    assert ("pass", "info", "Rate limiting advertised via headers") in results
