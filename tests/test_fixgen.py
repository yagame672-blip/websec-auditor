"""Fix-bundle generation tests (finding-name matching, note categories)."""
from websec_auditor.analyzer.analyze import analyze
from websec_auditor.fixgen import build_bundle
from websec_auditor.scanner.engine import Finding, ScanResult


def _enriched(findings):
    res = ScanResult(target="t")
    for f in findings:
        res.add(f)
    return analyze(res)


def _f(check, name, status="fail", severity="high"):
    return Finding(check=check, name=name, status=status, severity=severity,
                   detail="d", source_id="", cwe="CWE-1", owasp="A1")


def test_matches_engine_xss_sqli_names():
    en = _enriched([
        _f("xss", "Reflected XSS surface confirmed"),
        _f("sqli", "SQL error signature exposed"),
    ])
    notes = "\n".join(build_bundle(en)["notes"])
    assert "XSS surface" in notes
    assert "SQL error leaked" in notes


def test_matches_blind_sqli_traversal_redirect_csrf():
    en = _enriched([
        _f("blind_sqli", "Blind SQLi (time-based) suspected"),
        _f("path_traversal", "Path traversal / LFI surface confirmed"),
        _f("open_redirect", "Potential Open Redirect detected"),
        _f("csrf_token", "State-changing form(s) without CSRF token"),
    ])
    notes = "\n".join(build_bundle(en)["notes"])
    assert "Blind SQLi suspected" in notes
    assert "Path traversal / LFI" in notes
    assert "Open redirect" in notes
    assert "CSRF token" in notes


def test_missing_headers_collected():
    en = _enriched([
        Finding(check="security_headers", name="Missing header: Strict-Transport-Security",
                status="fail", severity="high", detail="d", source_id="", cwe="CWE-1", owasp="A1"),
        Finding(check="security_headers", name="Missing header: Content-Security-Policy",
                status="fail", severity="high", detail="d", source_id="", cwe="CWE-1", owasp="A1"),
    ])
    b = build_bundle(en)
    assert "Strict-Transport-Security" in b["missing_headers"]
    assert "Content-Security-Policy" in b["missing_headers"]


def test_no_findings_notes():
    en = _enriched([])
    b = build_bundle(en)
    assert any("No remediations needed" in n for n in b["notes"])
