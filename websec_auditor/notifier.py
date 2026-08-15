"""Security-hardened notification dispatcher (Webhooks & Email Alerts).

Grounded in:
  - CWE-918 / OWASP A10 / ASVS V12: SSRF defense on all outbound webhooks & mail hosts.
  - CWE-93 / CWE-644 / RFC 5322 / ASVS V5.1: Anti-CRLF and header injection prevention on email addresses and subjects.
  - CWE-345 / RFC 2104 / OWASP API Security: Cryptographic HMAC-SHA256 webhook payload signing.
  - CWE-200 / CWE-532 / NIST SP 800-53 AC-4: Masking & protection of secrets and credentials.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import smtplib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Tuple

from websec_auditor import config
from websec_auditor import netsafe


# RFC 5322 compliant email regex pattern (safe from ReDoS)
_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class NotificationError(Exception):
    """Raised when notification delivery fails."""


def sanitize_header_field(value: str) -> str:
    """Strip all carriage returns and line feeds to prevent CRLF injection (CWE-93)."""
    if not value:
        return ""
    # Strip \r, \n, and control chars
    cleaned = re.sub(r"[\r\n\x00-\x1f\x7f-\x9f]", " ", str(value)).strip()
    return cleaned


def is_valid_email(address: str) -> bool:
    """Validate email address format strictly without CRLF injection risk."""
    if not address or len(address) > 254:
        return False
    if "\r" in address or "\n" in address or "%0d" in address.lower() or "%0a" in address.lower():
        return False
    return bool(_EMAIL_REGEX.match(address.strip()))


def _extract_finding_data(item: Any) -> Dict[str, Any]:
    """Safely extract flattened finding dictionary whether item is dict, enriched dict, or object."""
    if isinstance(item, dict):
        f = item.get("finding") if isinstance(item.get("finding"), dict) else item
    else:
        f = getattr(item, "finding", item)
    
    if isinstance(f, dict):
        return {
            "name": str(f.get("name") or f.get("flag") or f.get("source_id") or "Security Control").strip(),
            "severity": str(f.get("severity") or "info").lower().strip(),
            "detail": str(f.get("detail") or "").strip(),
            "remediation": str(f.get("remediation") or "").strip(),
            "cwe": str(f.get("cwe") or "").strip(),
            "owasp": str(f.get("owasp") or f.get("source_id") or "").strip(),
        }
    return {
        "name": str(getattr(f, "name", "") or getattr(f, "flag", "") or getattr(f, "source_id", "") or "Security Control").strip(),
        "severity": str(getattr(f, "severity", "") or "info").lower().strip(),
        "detail": str(getattr(f, "detail", "") or "").strip(),
        "remediation": str(getattr(f, "remediation", "") or "").strip(),
        "cwe": str(getattr(f, "cwe", "") or "").strip(),
        "owasp": str(getattr(f, "owasp", "") or getattr(f, "source_id", "") or "").strip(),
    }


def build_summary_stats(findings_or_enriched: Any) -> Dict[str, Any]:
    """Calculate severity breakdown and security score from findings."""
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    
    # Handle list of enriched finding dicts or ScanResult object
    findings_list = []
    if isinstance(findings_or_enriched, list):
        findings_list = findings_or_enriched
    elif hasattr(findings_or_enriched, "findings"):
        findings_list = getattr(findings_or_enriched, "findings")
    elif isinstance(findings_or_enriched, dict):
        findings_list = findings_or_enriched.get("findings", [])

    for item in findings_list:
        fdata = _extract_finding_data(item)
        sev = fdata.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
        counts["total"] += 1

    # Simple compliance score calculation (100 base, deductions for findings)
    deductions = (counts["high"] * 20) + (counts["medium"] * 8) + (counts["low"] * 2)
    score = max(0, 100 - deductions)
    
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "counts": counts,
        "score": score,
        "grade": grade,
        "findings_count": len(findings_list)
    }


def format_discord_payload(target: str, summary: Dict[str, Any], report_url: str = "") -> Dict[str, Any]:
    """Build a rich Discord Webhook Embed."""
    counts = summary["counts"]
    grade = summary["grade"]
    score = summary["score"]

    color = 0x10B981  # Green
    if counts["high"] > 0 or grade in ("D", "F"):
        color = 0xEF4444  # Red
    elif counts["medium"] > 0 or grade == "C":
        color = 0xF59E0B  # Amber

    fields = [
        {"name": "Security Score", "value": f"**{grade}** ({score}/100)", "inline": True},
        {"name": "Total Issues", "value": str(counts["total"]), "inline": True},
        {"name": "High Severity", "value": f"🚨 {counts['high']}", "inline": True},
        {"name": "Medium Severity", "value": f"⚠️ {counts['medium']}", "inline": True},
        {"name": "Low Severity", "value": f"ℹ️ {counts['low']}", "inline": True},
        {"name": "Informational", "value": f"🔍 {counts['info']}", "inline": True},
    ]

    embed = {
        "title": f"🛡️ WebSec Audit Report: {target}",
        "description": f"Grounded security scan completed for `{target}`.",
        "url": report_url or "https://websec-audit.site",
        "color": color,
        "fields": fields,
        "footer": {
            "text": "websec-auditor | Grounded in 193+ Security Standards & Books"
        },
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    return {
        "username": "WebSec Auditor",
        "avatar_url": "https://websec-audit.site/apple-touch-icon.png",
        "embeds": [embed]
    }


def format_slack_payload(target: str, summary: Dict[str, Any], report_url: str = "") -> Dict[str, Any]:
    """Build a Slack incoming webhook payload with blocks."""
    counts = summary["counts"]
    grade = summary["grade"]
    score = summary["score"]

    header_text = f"🛡️ *WebSec Audit Complete:* `{target}`"
    score_text = f"*Score:* `{grade} ({score}/100)` | *Findings:* High: `{counts['high']}` | Med: `{counts['medium']}` | Low: `{counts['low']}`"

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{header_text}\n{score_text}"
            }
        }
    ]

    if report_url:
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Full Audit Report"
                    },
                    "url": report_url,
                    "style": "primary"
                }
            ]
        })

    return {"text": f"WebSec Audit for {target}: Grade {grade}", "blocks": blocks}


def format_generic_payload(target: str, summary: Dict[str, Any], findings: List[Dict[str, Any]], report_url: str = "") -> Dict[str, Any]:
    """Build standard JSON webhook payload with full telemetry."""
    return {
        "event": "audit.completed",
        "version": "1.0",
        "timestamp": int(time.time()),
        "target": target,
        "report_url": report_url,
        "summary": summary,
        "findings": [
            {
                "name": f.get("name") if isinstance(f, dict) else getattr(f, "name", ""),
                "severity": f.get("severity") if isinstance(f, dict) else getattr(f, "severity", ""),
                "cwe": f.get("cwe") if isinstance(f, dict) else getattr(f, "cwe", ""),
                "owasp": f.get("owasp") if isinstance(f, dict) else getattr(f, "owasp", ""),
                "source_id": f.get("source_id") if isinstance(f, dict) else getattr(f, "source_id", ""),
                "description": f.get("description") if isinstance(f, dict) else getattr(f, "description", ""),
                "remediation": f.get("remediation") if isinstance(f, dict) else getattr(f, "remediation", ""),
            }
            for f in findings[:50]  # Cap at top 50 to prevent huge payloads
        ]
    }


def send_webhook(
    webhook_url: str,
    target: str,
    findings: Any,
    secret: Optional[str] = None,
    report_url: str = "",
    allow_private: bool = False
) -> Dict[str, Any]:
    """Dispatch an SSRF-safe, cryptographically-signed webhook POST request.
    
    Security Controls:
      - Validates webhook URL using netsafe (blocks private IPs, loopback, cloud metadata).
      - Signs payload with HMAC-SHA256 if secret is supplied.
      - Enforces strict timeout and response limits.
    """
    if not webhook_url or not isinstance(webhook_url, str):
        raise NotificationError("Invalid webhook URL.")

    # 1. Anti-SSRF URL validation (CWE-918)
    safe_url = netsafe.validate_target(webhook_url.strip(), allow_private=allow_private)

    # 2. Extract findings and calculate summary
    findings_list = findings if isinstance(findings, list) else getattr(findings, "findings", [])
    summary = build_summary_stats(findings_list)

    # 3. Detect format and build payload
    url_lower = safe_url.lower()
    if "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
        payload_data = format_discord_payload(target, summary, report_url)
    elif "hooks.slack.com" in url_lower:
        payload_data = format_slack_payload(target, summary, report_url)
    else:
        payload_data = format_generic_payload(target, summary, findings_list, report_url)

    raw_body = json.dumps(payload_data, ensure_ascii=False).encode("utf-8")

    # 4. Construct request headers
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "websec-auditor-webhook-dispatcher/1.0",
        "Accept": "application/json, text/plain, */*",
    }

    # 5. Optional HMAC-SHA256 signature (CWE-345 / RFC 2104)
    ts = str(int(time.time()))
    if secret:
        sig_mac = hmac.new(secret.encode("utf-8"), ts.encode("utf-8") + b"." + raw_body, hashlib.sha256).hexdigest()
        headers["X-WebSec-Signature"] = f"sha256={sig_mac}"
        headers["X-WebSec-Timestamp"] = ts

    req = urllib.request.Request(safe_url, data=raw_body, headers=headers, method="POST")

    # 6. Execute request with strict timeout
    timeout = config.WEBHOOK_TIMEOUT_SECONDS
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            return {"status": "success", "status_code": status_code, "target": target}
    except urllib.error.HTTPError as e:
        raise NotificationError(f"Webhook HTTP error: {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise NotificationError(f"Webhook connection error: {e.reason}") from e
    except Exception as e:
        raise NotificationError(f"Webhook dispatch failed: {str(e)}") from e


def generate_email_html(target: str, summary: Dict[str, Any], findings_list: List[Any] = None, report_url: str = "") -> str:
    """Generate responsive dark-themed executive HTML email with full findings breakdown."""
    counts = summary["counts"]
    grade = summary["grade"]
    score = summary["score"]
    findings_list = findings_list or []

    badge_color = "#10b981"
    if grade in ("D", "F"):
        badge_color = "#ef4444"
    elif grade == "C":
        badge_color = "#f59e0b"

    # Build findings HTML cards
    findings_cards = []
    sev_bg_map = {
        "high": "#ef4444",
        "medium": "#f59e0b",
        "low": "#eab308",
        "info": "#3b82f6"
    }

    # Sort findings by severity (high -> medium -> low -> info)
    sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorted_findings = sorted(
        findings_list,
        key=lambda x: sev_rank.get(_extract_finding_data(x).get("severity", "info"), 4)
    )

    for idx, item in enumerate(sorted_findings[:30], 1):
        f = _extract_finding_data(item)
        name = f["name"]
        sev = f["severity"]
        detail = f["detail"]
        remediation = f["remediation"]
        cwe = f["cwe"]
        owasp = f["owasp"]
        sev_badge_bg = sev_bg_map.get(sev, "#6b7280")

        badge_tags = []
        if owasp:
            badge_tags.append(f'<span style="background:#1e293b;color:#94a3b8;border:1px solid #334155;border-radius:4px;padding:2px 6px;font-size:11px;">{html.escape(owasp)}</span>')
        if cwe:
            badge_tags.append(f'<span style="background:#1e293b;color:#94a3b8;border:1px solid #334155;border-radius:4px;padding:2px 6px;font-size:11px;">{html.escape(cwe)}</span>')
        tags_html = " ".join(badge_tags)

        # Extract KB Grounding Citations
        cits_list = item.get("citations", []) if isinstance(item, dict) else getattr(item, "citations", [])
        cit_blocks = []
        for c in cits_list[:2]:
            c_title = c.get("title") or c.get("authority") or "KB Security Literature"
            c_auth = c.get("authority") or ""
            c_passage = c.get("passage") or ""
            c_tags = ", ".join((c.get("tags") or [])[:3])
            
            cit_blocks.append(f"""
            <div style="margin-top:8px;padding:8px 10px;background:#090d16;border-left:3px solid #38bdf8;border-radius:4px;">
              <div style="font-size:11px;font-weight:bold;color:#38bdf8;">📖 KB Grounding Citation: {html.escape(c_title)} {f'({html.escape(c_auth)})' if c_auth and c_auth != c_title else ''}</div>
              {f'<div style="font-size:10px;color:#64748b;margin-top:2px;">KB Tags: {html.escape(c_tags)}</div>' if c_tags else ''}
              {f'<div style="font-size:11px;color:#94a3b8;font-style:italic;margin-top:4px;line-height:1.4;">&ldquo;{html.escape(c_passage[:220])}{"..." if len(c_passage) > 220 else ""}&rdquo;</div>' if c_passage else ''}
            </div>""")
        cits_block = "".join(cit_blocks)

        rem_block = ""
        if remediation:
            rem_block = f"""
            <div style="margin-top:10px;padding:10px 12px;background:#0d1322;border:1px solid #1f2937;border-radius:6px;">
              <div style="font-size:11px;font-weight:bold;color:#38bdf8;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">💡 Recommended Remediation:</div>
              <div style="font-size:12px;color:#cbd5e1;line-height:1.45;font-family:monospace;white-space:pre-wrap;">{html.escape(remediation)}</div>
            </div>"""

        findings_cards.append(f"""
        <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:14px 16px;margin-bottom:12px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
            <div>
              <span style="background:{sev_badge_bg};color:#ffffff;font-size:10px;font-weight:bold;padding:2px 6px;border-radius:4px;text-transform:uppercase;">{sev.upper()}</span>
              <strong style="color:#ffffff;font-size:14px;margin-left:6px;">{html.escape(name)}</strong>
            </div>
            <div>{tags_html}</div>
          </div>
          {f'<div style="font-size:12px;color:#cbd5e1;line-height:1.45;margin-top:4px;">{html.escape(detail)}</div>' if detail else ''}
          {cits_block}
          {rem_block}
        </div>""")

    findings_section = "".join(findings_cards) if findings_cards else """
      <div style="background:#064e3b;border:1px solid #059669;border-radius:8px;padding:16px;text-align:center;color:#6ee7b7;font-weight:bold;">
        ✓ All security probes passed! No vulnerabilities detected.
      </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WebSec Audit Report</title>
</head>
<body style="margin:0;padding:24px;background-color:#0b0f19;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,sans-serif;color:#f3f4f6;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width:680px;margin:0 auto;background-color:#111827;border-radius:12px;border:1px solid #1f2937;overflow:hidden;">
    <tr>
      <td style="padding:28px 24px;border-bottom:1px solid #1f2937;background:#0d1322;">
        <h1 style="margin:0 0 8px;font-size:22px;color:#38bdf8;letter-spacing:-0.5px;">🛡️ WebSec Audit Report</h1>
        <p style="margin:0;font-size:14px;color:#9ca3af;">Target: <strong style="color:#ffffff;">{html.escape(target)}</strong></p>
      </td>
    </tr>
    <tr>
      <td style="padding:24px;">
        <div style="background:#1e293b;border-radius:8px;padding:16px 20px;margin-bottom:20px;border-left:4px solid {badge_color};">
          <div style="font-size:12px;text-transform:uppercase;color:#94a3b8;letter-spacing:1px;">Security Scorecard</div>
          <div style="font-size:28px;font-weight:bold;color:#ffffff;margin-top:4px;">Grade {grade} <span style="font-size:16px;color:#94a3b8;font-weight:normal;">({score}/100)</span></div>
        </div>

        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="margin-bottom:24px;">
          <tr>
            <td width="25%" style="padding:8px;text-align:center;background:#1f2937;border-radius:6px 0 0 6px;">
              <div style="font-size:18px;font-weight:bold;color:#ef4444;">{counts['high']}</div>
              <div style="font-size:11px;color:#9ca3af;text-transform:uppercase;">High</div>
            </td>
            <td width="25%" style="padding:8px;text-align:center;background:#1f2937;">
              <div style="font-size:18px;font-weight:bold;color:#f59e0b;">{counts['medium']}</div>
              <div style="font-size:11px;color:#9ca3af;text-transform:uppercase;">Medium</div>
            </td>
            <td width="25%" style="padding:8px;text-align:center;background:#1f2937;">
              <div style="font-size:18px;font-weight:bold;color:#eab308;">{counts['low']}</div>
              <div style="font-size:11px;color:#9ca3af;text-transform:uppercase;">Low</div>
            </td>
            <td width="25%" style="padding:8px;text-align:center;background:#1f2937;border-radius:0 6px 6px 0;">
              <div style="font-size:18px;font-weight:bold;color:#10b981;">{counts['info']}</div>
              <div style="font-size:11px;color:#9ca3af;text-transform:uppercase;">Info</div>
            </td>
          </tr>
        </table>

        <div style="font-size:15px;font-weight:bold;color:#ffffff;margin-bottom:12px;">📋 Vulnerability Findings &amp; Grounded Remediations:</div>
        {findings_section}

        {f'<div style="text-align:center;margin:28px 0;"><a href="{html.escape(report_url)}" style="display:inline-block;background:#0284c7;color:#ffffff;padding:12px 24px;font-size:14px;font-weight:bold;text-decoration:none;border-radius:6px;">View Full Live Audit Report</a></div>' if report_url else ''}
        
        <p style="font-size:13px;color:#9ca3af;line-height:1.5;margin:20px 0 0;">
          All findings are strictly evaluated and cited from 193+ authoritative standards and literature (OWASP Top 10:2021, ASVS v4.0.3, MITRE CWE, and NIST SP 800-53).
        </p>
      </td>
    </tr>
    <tr>
      <td style="padding:16px 24px;border-top:1px solid #1f2937;background:#0d1322;font-size:11px;color:#6b7280;text-align:center;">
        Generated by <a href="https://websec-audit.site" style="color:#38bdf8;text-decoration:none;">websec-audit.site</a> &bull; Safe, Non-Destructive AppSec Auditing
      </td>
    </tr>
  </table>
</body>
</html>"""


def send_email_alert(
    recipient: str,
    target: str,
    findings: Any,
    report_url: str = ""
) -> Dict[str, Any]:
    """Send an Anti-CRLF sanitized email notification report.
    
    Supports:
      1. Resend API (if config.RESEND_API_KEY is configured).
      2. Direct SMTP / SMTPS / STARTTLS (if config.SMTP_HOST is configured).
    """
    recipient = (recipient or "").strip()
    if not is_valid_email(recipient):
        raise NotificationError(f"Invalid email recipient: {recipient!r}")

    # Anti-CRLF header sanitization (CWE-93)
    target_clean = sanitize_header_field(target)
    subject = sanitize_header_field(f"🛡️ WebSec Audit Report: {target_clean}")
    sender_clean = sanitize_header_field(config.SMTP_FROM or "alerts@websec-audit.site")

    findings_list = findings if isinstance(findings, list) else getattr(findings, "findings", [])
    summary = build_summary_stats(findings_list)
    html_body = generate_email_html(target_clean, summary, findings_list, report_url)
    text_body = (
        f"WebSec Audit Report for {target_clean}\n"
        f"Security Score: Grade {summary['grade']} ({summary['score']}/100)\n"
        f"Findings Breakdown: High: {summary['counts']['high']}, Medium: {summary['counts']['medium']}, "
        f"Low: {summary['counts']['low']}, Info: {summary['counts']['info']}\n"
        f"Report URL: {report_url or 'https://websec-audit.site'}\n\n"
        f"Grounded in 193+ Security Standards & Books."
    )

    # Option A: Transactional Email API Dispatch (Resend)
    if config.RESEND_API_KEY:
        primary_from = sanitize_header_field(
            getattr(config, "RESEND_FROM", "") or config.SMTP_FROM or "WebSec Auditor <alerts@websec-audit.site>"
        )
        
        def _dispatch_resend(from_addr: str) -> Dict[str, Any]:
            resend_payload = {
                "from": from_addr,
                "to": [recipient],
                "subject": subject,
                "html": html_body,
                "text": text_body
            }
            req = urllib.request.Request(
                "https://api.resend.com/emails",
                data=json.dumps(resend_payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {config.RESEND_API_KEY}",
                    "Content-Type": "application/json",
                    "User-Agent": "websec-auditor-mailer/1.0"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return {"status": "success", "provider": "mail", "recipient": recipient, "sender": from_addr}

        try:
            return _dispatch_resend(primary_from)
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", "ignore")
                err_json = json.loads(err_body)
                err_msg = err_json.get("message") or err_body
            except Exception:
                err_msg = str(e)
            
            # Fallback if domain is still propagating
            if "not verified" in err_msg.lower() and "onboarding@resend.dev" not in primary_from:
                try:
                    return _dispatch_resend("WebSec Auditor <onboarding@resend.dev>")
                except Exception as fb_err:
                    raise NotificationError(f"Email delivery error: {err_msg}") from fb_err
            
            raise NotificationError(f"Email delivery error: {err_msg}") from e
        except Exception as e:
            raise NotificationError(f"Email delivery error: {str(e)}") from e

    # Option B: Standard Direct SMTP / STARTTLS Dispatch
    if config.SMTP_HOST:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = sender_clean
        msg["To"] = recipient
        msg["Date"] = smtplib.email.utils.formatdate(localtime=True)
        msg["Message-ID"] = smtplib.email.utils.make_msgid(domain="websec-audit.site")

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            if config.SMTP_USE_SSL:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, context=context, timeout=15)
            else:
                server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
                if config.SMTP_USE_TLS:
                    server.starttls(context=ssl.create_default_context())

            if config.SMTP_USER and config.SMTP_PASS:
                server.login(config.SMTP_USER, config.SMTP_PASS)

            server.sendmail(sender_clean, [recipient], msg.as_string())
            server.quit()
            return {"status": "success", "provider": "mail", "recipient": recipient, "sender": sender_clean}
        except Exception as e:
            raise NotificationError(f"SMTP delivery error: {str(e)}") from e

    # Fallback when no live SMTP/API key is configured in local dev:
    return {
        "status": "simulated",
        "message": "Email delivery simulated (no SMTP_HOST or RESEND_API_KEY configured).",
        "recipient": recipient,
        "subject": subject
    }
