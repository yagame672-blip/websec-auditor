"""Offline checks: static code review, dependency scan, OWASP scorecard, reports."""
import json
import os

from websec_auditor import codereview
from websec_auditor import dependscan
from websec_auditor.analyzer.analyze import analyze
from websec_auditor.report import render
from websec_auditor.scanner.engine import Finding, ScanResult

SAMPLE_CODE = '''
import pickle
import os

def query(sql):
    cur.execute("SELECT * FROM users WHERE name = '" + sql + "'")

def load():
    return pickle.loads(open("data", "rb").read())

os.system("curl " + url)
password = "hunter2"
'''


def test_codereview_flags_bad_patterns():
    findings = codereview.review_text(SAMPLE_CODE, "sample.py")
    names = " ".join(f.name.lower() for f in findings)
    assert any("sql" in f.name.lower() for f in findings)
    assert any("pickle" in f.name.lower() for f in findings)
    assert any("command" in f.name.lower() or "shell" in f.name.lower() for f in findings)
    assert any("hardcoded" in f.name.lower() or "password" in f.name.lower() for f in findings)


def test_depscan_flags_known_vulns(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("django==3.2.5\nrequests==2.28.0\n", encoding="utf-8")
    findings = dependscan.scan_text(manifest.read_text(encoding="utf-8"), "requirements.txt")
    names = " ".join(f.name.lower() for f in findings)
    assert "cve-" in names
    assert len(findings) > 0


def test_json_report_structure():
    en = analyze(_sample_result())
    doc = json.loads(render.render_json(en, "https://example.com"))
    assert doc["tool"] == "websec-auditor"
    assert doc["target"] == "https://example.com"
    assert isinstance(doc["findings"], list)
    assert doc["findings"]


def test_sarif_report_structure():
    en = analyze(_sample_result())
    doc = json.loads(render.render_sarif(en, "https://example.com"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "websec-auditor"
    assert run["results"]
    result = run["results"][0]
    assert result["level"] == "error"  # high severity


def _sample_result():
    res = ScanResult(target="https://example.com")
    res.add(Finding(check="tls_cert", name="TLS certificate expired", status="fail",
                    severity="high", detail="Cert expired.", source_id="CWE-295",
                    cwe="CWE-295", owasp="A02", remediation="Renew the cert.",
                    confidence="high"))
    return res
