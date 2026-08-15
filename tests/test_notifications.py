"""Unit tests for Webhooks, Email alerts, and Asynchronous scan dispatchers.

Grounded in:
  - CWE-918 / OWASP A10 / ASVS V12: Anti-SSRF guards on outgoing webhooks.
  - CWE-93 / CWE-644 / RFC 5322: Anti-CRLF injection sanitization on emails.
  - CWE-345 / RFC 2104: Cryptographic HMAC-SHA256 signature verification.
  - CWE-400 / OWASP A04: Bounded async job queue and worker execution.
"""
import hashlib
import hmac
import json
import time
import pytest

from websec_auditor import netsafe
from websec_auditor import notifier
from websec_auditor import async_scan
from websec_auditor.scanner.engine import ScanResult


def test_sanitize_header_crlf_injection():
    """Verify CWE-93 prevention: strips CR, LF, and control chars from headers."""
    dirty = "alerts@example.com\r\nBcc: attacker@evil.com\nSubject: Injected"
    cleaned = notifier.sanitize_header_field(dirty)
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "Bcc: attacker@evil.com" in cleaned


def test_email_validation_strict_and_safe():
    """Verify RFC 5322 email validation blocks CRLF and malformed addresses."""
    assert notifier.is_valid_email("security@websec-audit.site")
    assert notifier.is_valid_email("user.name+tag@sub.domain.co.uk")
    
    # Must reject CRLF injection attempts
    assert not notifier.is_valid_email("admin@site.com\r\nBcc: evil@hacker.com")
    assert not notifier.is_valid_email("admin@site.com%0d%0a")
    assert not notifier.is_valid_email("plainaddress")
    assert not notifier.is_valid_email("")


def test_summary_statistics_calculation():
    """Verify compliance scorecard and severity count aggregation."""
    mock_findings = [
        {"name": "SQL Injection", "severity": "high"},
        {"name": "Missing CSP", "severity": "high"},
        {"name": "Missing X-Frame-Options", "severity": "medium"},
        {"name": "Missing Referrer-Policy", "severity": "low"},
        {"name": "Info disclosure", "severity": "info"},
    ]
    summary = notifier.build_summary_stats(mock_findings)
    assert summary["counts"]["high"] == 2
    assert summary["counts"]["medium"] == 1
    assert summary["counts"]["low"] == 1
    assert summary["counts"]["info"] == 1
    assert summary["counts"]["total"] == 5
    # 100 - (2*20 + 1*8 + 1*2) = 100 - 50 = 50 -> Grade D
    assert summary["score"] == 50
    assert summary["grade"] == "D"


def test_discord_payload_formatting():
    """Verify Discord webhook embed structure and color coding."""
    summary = {
        "counts": {"high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
        "score": 80,
        "grade": "B",
        "findings_count": 1
    }
    payload = notifier.format_discord_payload("https://example.com", summary, "https://websec-audit.site/reports/123")
    assert "embeds" in payload
    assert payload["username"] == "WebSec Auditor"
    embed = payload["embeds"][0]
    assert embed["color"] == 0xEF4444  # Red for high severity
    assert any(f["name"] == "High Severity" for f in embed["fields"])


def test_slack_payload_formatting():
    """Verify Slack incoming webhook blocks structure."""
    summary = {
        "counts": {"high": 0, "medium": 1, "low": 0, "info": 0, "total": 1},
        "score": 92,
        "grade": "A",
        "findings_count": 1
    }
    payload = notifier.format_slack_payload("https://example.com", summary, "https://websec-audit.site/reports/123")
    assert "blocks" in payload
    assert "WebSec Audit Complete" in payload["blocks"][0]["text"]["text"]


def test_webhook_anti_ssrf_blocking():
    """Verify CWE-918 prevention: blocks loopback, link-local metadata, and private webhook endpoints."""
    mock_findings = [{"name": "Test", "severity": "info"}]
    
    # Loopback blocked by default
    with pytest.raises(netsafe.UnsafeTargetError):
        notifier.send_webhook(
            webhook_url="http://127.0.0.1:8080/hook",
            target="https://example.com",
            findings=mock_findings,
            allow_private=False
        )

    # Cloud metadata blocked
    with pytest.raises(netsafe.UnsafeTargetError):
        notifier.send_webhook(
            webhook_url="http://169.254.169.254/latest/meta-data/",
            target="https://example.com",
            findings=mock_findings,
            allow_private=False
        )


def test_email_alert_simulation():
    """Verify email alert generation returns clean simulated result when SMTP not set."""
    mock_findings = [{"name": "Test Finding", "severity": "low"}]
    res = notifier.send_email_alert(
        recipient="test@example.com",
        target="https://example.com",
        findings=mock_findings,
        report_url="https://websec-audit.site"
    )
    assert res["status"] in ("simulated", "success")
    assert res["recipient"] == "test@example.com"


def test_async_scan_job_lifecycle(monkeypatch):
    """Verify background job queuing and execution."""
    mock_res = ScanResult(target="https://example.com")
    mock_res.add({"check": "test", "name": "Test Finding", "severity": "low", "detail": "test"})
    
    # Mock engine.scan to return immediately
    monkeypatch.setattr("websec_auditor.scanner.engine.scan", lambda target, custom_headers=None: mock_res)

    job = async_scan.enqueue_scan_job(
        target="https://example.com",
        crawl=False,
        email="test@example.com",
        allow_private=True
    )
    assert job["id"]
    assert job["target"] == "https://example.com"
    assert job["status"] in ("queued", "running", "completed")

    # Poll status for completion
    for _ in range(50):
        info = async_scan.get_sanitized_job(job["id"])
        if info["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)

    final_info = async_scan.get_sanitized_job(job["id"])
    assert final_info["status"] == "completed"
    assert "has_email" in final_info
    assert final_info["has_email"] is True
    assert final_info["summary"]["score"] > 0
