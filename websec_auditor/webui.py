"""websec-auditor web UI (standard-library only, no external deps).

Endpoints:
  GET  /                       scan form + last results
  POST /scan                  body: target=URL   -> runs scanner + analyzer
  POST /fix-demo              hardens the bundled demo server, then re-scans it
  POST /download-fix          body: target=URL   -> builds remediation bundle,
                                                  returns it as a download

Security Features:
  * OWASP Security Headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
  * Strict Host & Origin/Referer verification on state-changing requests
  * Context-aware HTML escaping on all dynamic findings and parameters
"""
from __future__ import annotations
import hashlib
import hmac
import html
import json
import os
import secrets
import sys
import time
import threading
import urllib.parse
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from websec_auditor import config
from websec_auditor import netsafe
from websec_auditor import usage
from websec_auditor.scanner import engine
from websec_auditor.analyzer.analyze import analyze, summarize
from websec_auditor.fixgen import build_bundle, apply_demo_fix, demo_is_hardened
from websec_auditor import owasptop10
from websec_auditor.scanner.engine import ScanResult

DEMO_URL = "http://127.0.0.1:8099"

# Serverless-consistent rolling HMAC CSRF token (CWE-352 / OWASP A01).
# Uses a shared secret to ensure tokens remain valid across distributed
# serverless Lambda invocations while strictly blocking cross-site attackers.
_SERVER_SECRET = (os.environ.get("DATABASE_URL") or
                  os.environ.get("SECRET_KEY") or
                  os.environ.get("VERCEL_DEPLOYMENT_ID") or
                  "websec-auditor-serverless-token-key-2026")

def get_csrf_token() -> str:
    t = int(time.time() // 3600)
    return hmac.new(_SERVER_SECRET.encode(), str(t).encode(), hashlib.sha256).hexdigest()[:24]

CSRF_TOKEN = get_csrf_token()

def validate_csrf_token(token: str) -> bool:
    if not token or not isinstance(token, str) or len(token) < 16:
        return False
    if hmac.compare_digest(token, CSRF_TOKEN):
        return True
    t_curr = int(time.time() // 3600)
    for t in (t_curr, t_curr - 1, t_curr - 2):
        expected = hmac.new(_SERVER_SECRET.encode(), str(t).encode(), hashlib.sha256).hexdigest()[:24]
        if hmac.compare_digest(token, expected):
            return True
    return False

# Vercel sets VERCEL=1 (and AWS_LAMBDA_FUNCTION_NAME) in the serverless
# runtime. Local CLI runs never set them. When deployed, the UI must NOT
# allow scanning private/loopback address space (anti-SSRF, CWE-918); the
# demo/fix endpoints only make sense against the user's own machine.
DEPLOYED = bool(os.environ.get("VERCEL") == "1" or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

UI_RATE_WINDOW = 60
UI_RATE_MAX = 10
# Upper bound on tracked client IPs so a flood of spoofed X-Forwarded-For
# values cannot grow _UI_HITS unboundedly (memory DoS). Stale buckets are
# pruned below the cap.
_UI_HITS_MAX = 2048
_UI_HITS = defaultdict(list)
_UI_LOCK = threading.Lock()

SEV_COLOR = {
    "high": "#ef4444",
    "medium": "#f59e0b",
    "low": "#eab308",
    "info": "#10b981",
}

SEV_BG = {
    "high": "rgba(239, 68, 68, 0.12)",
    "medium": "rgba(245, 158, 11, 0.12)",
    "low": "rgba(234, 179, 8, 0.12)",
    "info": "rgba(16, 185, 129, 0.12)",
}

SEV_BORDER = {
    "high": "rgba(239, 68, 68, 0.4)",
    "medium": "rgba(245, 158, 11, 0.4)",
    "low": "rgba(234, 179, 8, 0.4)",
    "info": "rgba(16, 185, 129, 0.4)",
}

STORE = {"last": None, "target": "", "result": None}


def _findings_to_result(findings, label):
    res = ScanResult(target=label)
    for f in findings:
        res.add(f)
    return res


def kb_stats():
    """Return honest KB counts read from kb_index.json and kb_books.jsonl
    (never hardcoded)."""
    try:
        with open(config.INDEX_FILE, encoding="utf-8") as f:
            idx = json.load(f)
        total = idx.get("count", 0)
        std = idx.get("source_A", 0)
        books = idx.get("source_B", 0)
    except Exception:
        total = std = books = 0
    rules = 0
    try:
        with open(config.KB_FILE, encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                rules += len(rec.get("scan_rules") or [])
    except Exception:
        pass
    return {"total": total, "standards": std, "books": books, "rules": rules}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "style-src 'self' https://fonts.googleapis.com; "
        "style-src-attr 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "
        "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
}


def run_scan(target: str, crawl: bool = False, custom_headers: dict = None):
    # Deployed UI: keep netsafe's default (no private targets). Local runs
    # (127.0.0.1 demo) widen the guard to allow loopback only for the user's
    # own machine. private_allowed() only ever widens, so CLI scans inherit it.
    with netsafe.private_allowed(not DEPLOYED):
        if crawl:
            from websec_auditor.crawler import scan_site
            res = scan_site(target, custom_headers=custom_headers)
        else:
            res = engine.scan(target, custom_headers=custom_headers)
    en = analyze(res)
    STORE["last"] = en
    STORE["target"] = target
    STORE["result"] = res
    try:
        usage.increment()
    except Exception:
        pass
    return en


def render_remediation_modal(target: str, bundle: dict) -> str:
    if not bundle:
        return ""
    
    notes_html = "".join(f"<li>{html.escape(n)}</li>" for n in bundle.get("notes", []))
    
    return f"""
    <div class="card fix-bundle-card">
      <div class="card-header">
        <div class="card-title">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
          Generated Remediation Code & Configurations
        </div>
        <form method="post" action="/download-fix" style="margin:0" id="download-fix-form" data-target="{html.escape(target)}">
          <input type="hidden" name="_token" value="{CSRF_TOKEN}">
          <input type="hidden" name="action" value="download-fix">
          <input type="hidden" name="target" value="{html.escape(target)}">
          <button type="submit" class="btn btn-secondary btn-sm">
            <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Download websec-fix.txt
          </button>
        </form>
      </div>

      <div class="tab-buttons">
        <button type="button" class="tab-btn active" data-tab="nginx-tab">Nginx</button>
        <button type="button" class="tab-btn" data-tab="apache-tab">Apache</button>
        <button type="button" class="tab-btn" data-tab="flask-tab">Flask</button>
        <button type="button" class="tab-btn" data-tab="express-tab">Express</button>
      </div>

      <div id="nginx-tab" class="fix-tab-content active">
        <pre><code>{html.escape(bundle.get('nginx', ''))}</code></pre>
      </div>
      <div id="apache-tab" class="fix-tab-content">
        <pre><code>{html.escape(bundle.get('apache', ''))}</code></pre>
      </div>
      <div id="flask-tab" class="fix-tab-content">
        <pre><code>{html.escape(bundle.get('flask', ''))}</code></pre>
      </div>
      <div id="express-tab" class="fix-tab-content">
        <pre><code>{html.escape(bundle.get('express', ''))}</code></pre>
      </div>

      {f'<div class="remediation-notes"><b>Security Guidance:</b><ul>{notes_html}</ul></div>' if notes_html else ''}
    </div>
    """


def categorize_finding(finding: dict) -> tuple[str, str]:
    """Categorize finding into (Affected Area, Icon)."""
    check = (finding.get("check") or "").lower()
    name = (finding.get("name") or "").lower()
    
    if any(k in check for k in ("header", "csp", "hsts", "frame", "content_type", "cors", "cache", "info_disclosure")):
        return ("HTTP Security Headers & Gateway", "🌐")
    elif "cookie" in check or "cookie" in name or "sess" in check:
        return ("Cookie & Session Management", "🍪")
    elif any(k in check for k in ("tls", "scheme", "certificate", "ssl")):
        return ("Transport Layer Security (TLS/HTTPS)", "🔒")
    elif any(k in check for k in ("sqli", "xss", "traversal", "injection", "csrf")):
        return ("Input Validation & Application Code", "🛡️")
    elif any(k in check for k in ("sensitive", "method", "directory", "framework", "graphql", "security_txt", "stateful")):
        return ("Server Endpoints & API Architecture", "⚙️")
    elif any(k in check for k in ("rate", "ddos", "network", "stability", "flood")):
        return ("Traffic Throttling & Infrastructure", "🚦")
    elif "dependency" in check or "cve" in name:
        return ("Third-Party Dependencies & Supply Chain", "📦")
    elif "code" in check:
        return ("Source Code Security (SAST)", "💻")
    return ("General Web Security Posture", "🔍")


def render_action_checklist(en) -> str:
    """Render a dedicated, high-visibility Fix Checklist showing exactly what is wrong and how to fix it."""
    if not en:
        return ""
    
    issues = []
    for item in en:
        f = item.get("finding", {})
        sev = (f.get("severity") or "info").lower()
        status = (f.get("status") or "pass").lower()
        if sev in ("high", "medium", "low") or status in ("fail", "warn"):
            issues.append(f)
            
    if not issues:
        return """
        <div class="card" style="border-left: 4px solid var(--sev-info); background: rgba(16, 185, 129, 0.08); margin-bottom: 1.5rem;">
          <div style="display:flex; align-items:center; gap:0.75rem;">
            <span style="font-size:1.4rem;">🎉</span>
            <div>
              <b style="color:var(--sev-info); font-size:1.05rem;">No Critical Flaws Detected</b>
              <p style="margin-top:0.2rem; font-size:0.9rem; color:var(--text-secondary);">All evaluated security baseline controls and header configurations passed successfully.</p>
            </div>
          </div>
        </div>
        """
        
    SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorted_issues = sorted(issues, key=lambda x: SEV_ORDER.get(x.get("severity", "info").lower(), 4))
    
    cards_html = []
    for idx, f in enumerate(sorted_issues, 1):
        sev = (f.get("severity") or "info").lower()
        area_name, area_icon = categorize_finding(f)
        remediation = f.get("remediation") or "Audit and update server configuration according to security standard recommendations."
        
        badge_cls = f"sev-{sev}"
        badge_label = "HIGH PRIORITY" if sev == "high" else ("MEDIUM PRIORITY" if sev == "medium" else "RECOMMENDED HARDENING")
        border_col = "var(--sev-high)" if sev == "high" else ("var(--sev-med)" if sev == "medium" else "var(--sev-low)")
        bg_col = "rgba(239, 68, 68, 0.06)" if sev == "high" else ("rgba(245, 158, 11, 0.06)" if sev == "medium" else "rgba(234, 179, 8, 0.06)")
        
        cards_html.append(f"""
        <div class="checklist-item" style="border-left: 4px solid {border_col}; background:{bg_col}; padding:0.9rem 1.1rem; border-radius:6px; margin-bottom:0.75rem; border:1px solid rgba(255,255,255,0.06); border-left: 4px solid {border_col};">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.4rem;">
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <span class="sev-badge {badge_cls}" style="font-size:0.72rem; padding:0.15rem 0.5rem;">{badge_label}</span>
              <b style="font-size:0.95rem; color:var(--text-primary);">{html.escape(f.get('name', ''))}</b>
            </div>
            <span style="font-size:0.8rem; color:var(--text-muted); background:rgba(0,0,0,0.3); padding:0.2rem 0.6rem; border-radius:4px;">
              {area_icon} <b>Target Area:</b> {html.escape(area_name)}
            </span>
          </div>
          
          <div style="font-size:0.88rem; color:var(--text-secondary); margin-bottom:0.45rem;">
            <span style="color:#f87171; font-weight:600;">⚠️ Identified Issue:</span> {html.escape(f.get('detail', ''))}
          </div>
          
          <div style="font-size:0.88rem; color:var(--text-primary); background:rgba(0,0,0,0.25); padding:0.5rem 0.75rem; border-radius:4px; border:1px dashed rgba(255,255,255,0.15);">
            <b style="color:#10b981;">💡 Actionable Remediation:</b> <code>{html.escape(remediation)}</code>
          </div>
        </div>
        """)
        
    return f"""
    <div class="card action-checklist-card" style="border:1px solid rgba(59, 130, 246, 0.4); background:linear-gradient(135deg, rgba(30, 41, 59, 0.85), rgba(15, 23, 42, 0.95)); box-shadow:0 8px 30px rgba(0,0,0,0.3); margin-bottom:1.5rem;">
      <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:0.75rem; margin-bottom:1rem; flex-wrap:wrap; gap:0.5rem;">
        <div style="display:flex; align-items:center; gap:0.6rem;">
          <span style="font-size:1.4rem;">🎯</span>
          <div>
            <h3 style="margin:0; font-size:1.15rem; font-weight:700; color:var(--text-primary);">Priority Remediation Checklist & Affected Areas</h3>
            <p style="margin:0; font-size:0.85rem; color:var(--text-secondary);">Summary of detected vulnerabilities, affected components, and immediate steps required to secure the target.</p>
          </div>
        </div>
        <span style="background:rgba(239, 68, 68, 0.15); color:#f87171; border:1px solid rgba(239, 68, 68, 0.3); font-weight:600; padding:0.25rem 0.6rem; border-radius:6px; font-size:0.82rem;">
          {len(sorted_issues)} Items to Remediate
        </span>
      </div>
      <div class="checklist-items">
        {"".join(cards_html)}
      </div>
    </div>
    """


def render_results(en, target: str):
    if en is None:
        return ""
    if not en:
        return """
        <div class="card status-banner status-secure">
          <div class="status-icon">✓</div>
          <div>
            <h3>All Audit Checks Passed</h3>
            <p>No vulnerabilities or header misconfigurations detected for this target.</p>
          </div>
        </div>
        """

    counts = summarize(en)
    total_findings = len(en)
    has_issues = (counts["high"] + counts["medium"] + counts["low"]) > 0

    if counts["high"] > 0:
      health_status = "CRITICAL RISK"
      health_class = "status-danger"
    elif counts["medium"] > 0 or counts["low"] > 0:
      health_status = "NEEDS FIXES"
      health_class = "status-warning"
    else:
      health_status = "SECURE POSTURE"
      health_class = "status-secure"

    # Dashboard Metrics Cards
    metrics_html = f"""
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-title">Audit Status</div>
        <div class="metric-value {health_class}">{health_status}</div>
        <div class="metric-sub">{total_findings} control probe(s) evaluated</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">High Risk</div>
        <div class="metric-value text-high">{counts['high']}</div>
        <div class="metric-sub">Action required immediately</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Medium Risk</div>
        <div class="metric-value text-med">{counts['medium']}</div>
        <div class="metric-sub">Security hardening recommended</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Low / Info</div>
        <div class="metric-value text-low">{counts['low'] + counts['info']}</div>
        <div class="metric-sub">{counts['low']} low, {counts['info']} informational</div>
      </div>
    </div>
    """

    # Findings Cards with Citations (Sorted: HIGH -> MEDIUM -> LOW -> INFO)
    SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
    en_sorted = sorted(en, key=lambda x: SEV_ORDER.get(x["finding"].get("severity", "info").lower(), 4))

    rows = []
    for idx, e in enumerate(en_sorted, 1):
        f = e["finding"]
        sev = f.get("severity", "info").lower()
        color = SEV_COLOR.get(sev, "#94a3b8")
        bg_color = SEV_BG.get(sev, "rgba(148, 163, 184, 0.1)")
        border_color = SEV_BORDER.get(sev, "rgba(148, 163, 184, 0.3)")

        cits = ""
        if e.get("citations"):
            cit_items = []
            for c in e["citations"]:
                match_label = " &middot; ".join(c.get("match") or [])
                ctx_parts = []
                if c.get("tags"):
                    ctx_parts.append("tags: " + ", ".join(c["tags"][:4]))
                if c.get("att_ck"):
                    ctx_parts.append("ATT&amp;CK: " + ", ".join(c["att_ck"]))
                if c.get("capec"):
                    ctx_parts.append(", ".join(c["capec"]))
                cit_ctx = ""
                if ctx_parts or match_label:
                    cit_ctx = ('<div class="citation-meta">' +
                               ('<span class="citation-match">' + match_label + '</span>' if match_label else '') +
                               ('<span>' + " &middot; ".join(ctx_parts) + '</span>' if ctx_parts else '') +
                               '</div>')
                cit_items.append(f"""
                <div class="citation-box">
                  <div class="citation-head">
                    <span class="citation-title">{html.escape(c['title'])}</span>
                    <span class="citation-auth">{html.escape(c['authority'])}</span>
                    {'<a class="citation-link" href="' + html.escape(c['url']) + '" target="_blank" rel="noopener">Reference Link &rarr;</a>' if c.get('url') else ''}
                  </div>
                  {cit_ctx}
                  <p class="citation-passage">&ldquo;{html.escape(c['passage'])}&rdquo;</p>
                </div>
                """)
            cits = f'<div class="citations-wrapper"><b>Book & Standard Grounded References:</b>' + "".join(cit_items) + '</div>'

        cwe_tag = f.get('cwe', '')
        owasp_tag = f.get('owasp', '')
        tags_str = " / ".join(filter(None, [cwe_tag, owasp_tag]))
        conf = (f.get('confidence') or '').lower()
        conf_html = f'<span class="sev-badge conf-{conf}">Confidence: {conf}</span>' if conf in ("high", "medium", "low") else ''

        ctx_line = ""
        top = (e.get("citations") or [{}])[0]
        ctx_bits = []
        if top.get("att_ck"):
            ctx_bits.append("ATT&amp;CK " + ", ".join(top["att_ck"]))
        if top.get("capec"):
            ctx_bits.append(", ".join(top["capec"]))
        if top.get("impact"):
            ctx_bits.append("Impact: " + ", ".join(top["impact"][:3]))
        if ctx_bits:
            ctx_line = f'<div class="finding-context">{" &middot; ".join(ctx_bits)}</div>'

        rows.append(f"""
        <div class="finding-card" data-severity="{sev}" style="border-left: 5px solid {color};">
          <div class="finding-header">
            <span class="sev-badge sev-{sev}">{sev.upper()}</span>
            {conf_html}
            <h4 class="finding-title">{html.escape(f['name'])}</h4>
            {f'<span class="tags-badge">{html.escape(tags_str)}</span>' if tags_str else ''}
          </div>
          
          <div class="finding-detail">{html.escape(f['detail'])}</div>
          
          {ctx_line}
          
          {f'<div class="fix-box"><b>Remediation Guidance:</b> {html.escape(f.get("remediation", ""))}</div>' if f.get("remediation") else ''}
          
          {cits}
        </div>
        """)

    bundle = build_bundle(en) if has_issues else None
    fix_bundle_html = render_remediation_modal(target, bundle) if bundle else ""

    owasp_html = owasptop10.render_html(owasptop10.scorecard(en))

    high_btn = f'<button class="filter-btn" data-sev="high">High ({counts["high"]})</button>' if counts["high"] else ''
    med_btn = f'<button class="filter-btn" data-sev="medium">Medium ({counts["medium"]})</button>' if counts["medium"] else ''
    low_btn = f'<button class="filter-btn" data-sev="low">Low ({counts["low"]})</button>' if counts["low"] else ''
    info_btn = f'<button class="filter-btn" data-sev="info">Info ({counts["info"]})</button>' if counts["info"] else ''

    filter_toolbar = f"""
    <div class="filter-toolbar">
      <div class="filter-tabs">
        <button class="filter-btn active" data-sev="all">All ({total_findings})</button>
        {high_btn}
        {med_btn}
        {low_btn}
        {info_btn}
      </div>
      <input type="text" id="search-input" placeholder="Search findings, CWE, OWASP..." class="search-field">
    </div>
    """

    checklist_html = render_action_checklist(en)
    return metrics_html + checklist_html + owasp_html + fix_bundle_html + filter_toolbar + f'<div id="findings-list">{"".join(rows)}</div>'


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="kb-total" content="{KB_TOTAL_NUM}">
<meta name="csrf-token" content="{CSRF_TOKEN}">
<title>websec-auditor | Grounded Security Scanner</title>
<link rel="stylesheet" href="/static/styles.css">
</head>
<body>
<div class="container">
  <header>
    <div class="logo-group">
      <div class="logo-icon">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div>
        <h1>websec-auditor</h1>
        <div class="subtitle">Book-grounded web security scanner grounded in OWASP, CWE & ASVS</div>
      </div>
    </div>
    <div class="header-badges">
      <span class="badge">OWASP Top 10:2021</span>
      <span class="badge">MITRE CWE</span>
      <span class="badge">ASVS v4.0.1</span>
      <span class="badge">Safe Read-Only</span>
    </div>
  </header>

  <div class="app-layout">
    <main class="main-content">
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:1rem; margin-bottom:1.5rem;">
        <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid var(--accent-primary);">
          <div style="font-size:0.84rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Total KB References</div>
          <div style="font-size:1.7rem; font-weight:700; color:var(--text-primary); margin-top:0.2rem;">{KB_TOTAL}</div>
          <div style="font-size:0.84rem; color:var(--accent-primary); margin-top:0.1rem;">Grounded Security Passages</div>
        </div>
        <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid #10b981;">
          <div style="font-size:0.84rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Executable Audit Rules</div>
          <div style="font-size:1.7rem; font-weight:700; color:#10b981; margin-top:0.2rem;">{KB_RULES} Active</div>
          <div style="font-size:0.84rem; color:#10b981; margin-top:0.1rem;">Book-Grounded Scanner Probes</div>
        </div>
        <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid #8b5cf6;">
          <div style="font-size:0.84rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Standards & CWE Catalog</div>
          <div style="font-size:1.7rem; font-weight:700; color:#c084fc; margin-top:0.2rem;">{KB_STD}</div>
          <div style="font-size:0.84rem; color:#c084fc; margin-top:0.1rem;">OWASP, MITRE, NIST, ISO, RFCs</div>
        </div>
        <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid #f59e0b;">
          <div style="font-size:0.84rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Cybersecurity Books</div>
          <div style="font-size:1.7rem; font-weight:700; color:#fbbf24; margin-top:0.2rem;">{KB_BOOKS}</div>
          <div style="font-size:0.84rem; color:#fbbf24; margin-top:0.1rem;">Books & Ingested PDFs</div>
        </div>
        <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid #0ea5e9;">
          <div style="font-size:0.84rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Live Scan Usage</div>
          <div id="usage-count" style="font-size:1.7rem; font-weight:700; color:#38bdf8; margin-top:0.2rem;">{USAGE_COUNT}</div>
          <div style="font-size:0.84rem; color:#38bdf8; margin-top:0.1rem;">Real Scans Run on This Site</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="margin-bottom:1rem;">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          Audit Target URL & Authenticated Scan Options
        </div>
        <form class="scan-form" id="scan-form">
          <input type="hidden" name="_token" value="{CSRF_TOKEN}">
          <div style="display:flex; width:100%; gap:0.75rem; flex-wrap:wrap;">
            <input type="text" class="url-input" name="target" placeholder="https://target.example (only targets you OWN / authorize)" value="{TARGET}">
            <button type="submit" class="btn btn-primary" id="scan-submit-btn">Run Security Audit</button>
          </div>
          <div style="display:flex; width:100%; gap:0.75rem; flex-wrap:wrap; margin-top:0.75rem; align-items:center;">
            <input type="text" class="url-input" name="cookie" style="font-size:0.95rem; padding:0.55rem 0.8rem;" placeholder="Optional session Cookie (e.g. session=12345)" value="{COOKIE}">
            <input type="text" class="url-input" name="custom_header" style="font-size:0.95rem; padding:0.55rem 0.8rem;" placeholder="Optional Header (e.g. Authorization: Bearer token)" value="{HEADER}">
            <label class="checkbox-label" style="margin-left:auto;">
              <input type="checkbox" name="crawl" value="1"> Site-wide crawl
            </label>
          </div>
        </form>
      </div>

      {kb_rules_inspector}

      <!-- KB Self-Study & Self-Hardening Card -->
      <div class="card" style="border-left: 4px solid #8b5cf6;">
        <div class="card-header">
          <div class="card-title">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>
            KB Self-Study &amp; Self-Hardening
          </div>
          <span style="font-size:0.72rem; font-weight:700; padding:0.15rem 0.4rem; border-radius:4px; background:rgba(139, 92, 246, 0.2); color:#c084fc; border:1px solid rgba(139, 92, 246, 0.4);">DOG-FOODING</span>
        </div>
        <p style="font-size:0.93rem; color:var(--text-secondary); line-height:1.5; margin-bottom:0.75rem;">
          The auditor reads its own {KB_TOTAL} grounded references, audits <b>this app&rsquo;s own security posture</b> against
          every executable rule the books teach, applies the missing hardening to <code>vercel.json</code> &amp; <code>webui.py</code>,
          then re-audits to prove the fix loop.
        </p>
        <button type="button" class="btn btn-primary" id="self-harden-btn" style="background:linear-gradient(135deg, #8b5cf6, #7e22ce);">Apply KB Hardening &amp; Re-Audit</button>
        <div id="self-harden-result" style="margin-top:0.75rem;"></div>
      </div>

      {dev_block}

      {progress_card}

      {demo_block}

      <div id="report-heading">{report_heading}</div>

      <div id="results-wrapper">{results}</div>
    </main>

    <!-- SIDEBAR -->
    <aside class="sidebar">
      <!-- 💖 Support & Donate Card -->
      <div class="card donate-card">
        <div class="donate-title">
          <svg style="width:20px;height:20px;stroke:#ec4899;fill:none;" viewBox="0 0 24 24" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l8.78-8.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
          Support Websec-Auditor
        </div>
        <p style="font-size:0.93rem; color:var(--text-secondary); margin-top:0.4rem; line-height:1.45;">
          Help keep our {KB_TOTAL} OWASP & CWE security references <b>100% free & open-source</b>.
        </p>
        
        <div class="donate-options">
          <button type="button" class="donate-btn btn-paypal" data-modal="paypal">
            💙 PayPal
          </button>
        </div>
      </div>

    </aside>
  </div>

  <footer>
    <b>Notice & Policy:</b> Run scans exclusively against targets you own or have explicit authorization to audit. All probes are non-destructive and read-only.
  </footer>
</div>

<!-- Modal Popup -->
<div id="donate-modal" class="modal-overlay">
  <div class="modal-box">
    <button class="modal-close" data-modal-close>&times;</button>
    <div id="modal-content"></div>
  </div>
</div>

<script src="/static/app.js" defer></script>
</body>
</html>"""


# App styles served at /static/styles.css. Kept out of the HTML so the
# Content-Security-Policy can drop 'unsafe-inline' from style-src (OWASP-CSP).
STYLES_CSS = """ :root {
   --bg-dark: #0b0f19;
   --card-bg: #1e293b;
   --card-border: #334155;
   --text-primary: #f8fafc;
   --text-secondary: #94a3b8;
   --text-muted: #64748b;
   --accent-primary: #3b82f6;
   --accent-hover: #2563eb;
   --sev-high: #ef4444;
   --sev-med: #f59e0b;
   --sev-low: #eab308;
   --sev-info: #10b981;
   --radius: 10px;
 }
 * { box-sizing: border-box; margin:0; padding:0; }
 html { font-size: 18px; }
 body {
   font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
   font-size: 1.15rem;
   background-color: var(--bg-dark);
   color: var(--text-primary);
   line-height: 1.6;
   padding: 1.5rem 2rem;
 }
  .container {
    width: 100%;
    max-width: 1720px;
    margin: 0 auto;
  }
  .app-layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 360px;
    gap: 1.75rem;
    align-items: start;
  }
  @media (max-width: 992px) {
    .app-layout {
      grid-template-columns: 1fr;
    }
  }
  .sidebar {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }
  .donate-card {
    background: linear-gradient(135deg, rgba(30, 41, 59, 0.95), rgba(15, 23, 42, 0.95));
    border: 1px solid rgba(236, 72, 153, 0.3);
    border-top: 4px solid #ec4899;
    box-shadow: 0 4px 20px rgba(236, 72, 153, 0.15);
  }
  .donate-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: #f472b6;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .donate-options {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.5rem;
    margin-top: 0.8rem;
  }
  .donate-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.3rem;
    padding: 0.55rem 0.6rem;
    border-radius: 8px;
    font-size: 0.92rem;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid var(--card-border);
    transition: all 0.2s ease;
    text-decoration: none;
  }
  .btn-paypal { background: #003087; color: #fff; border: none; }
  .btn-paypal:hover { background: #001c54; transform: translateY(-2px); }

  .modal-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.75);
    backdrop-filter: blur(4px);
    z-index: 9999;
    align-items: center;
    justify-content: center;
  }
  .modal-box {
    background: #1e293b;
    border: 1px solid var(--card-border);
    border-radius: 12px;
    width: 90%;
    max-width: 440px;
    padding: 1.5rem;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    position: relative;
    color: var(--text-primary);
  }
  .modal-close {
    position: absolute;
    top: 1rem; right: 1rem;
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 1.4rem;
    cursor: pointer;
  }
 header {
   margin-bottom: 2rem;
   padding-bottom: 1.5rem;
   border-bottom: 1px solid var(--card-border);
   display: flex;
   justify-content: space-between;
   align-items: flex-start;
   flex-wrap: wrap;
   gap: 1rem;
 }
 .logo-group {
   display: flex;
   align-items: center;
   gap: 0.75rem;
 }
 .logo-icon {
   width: 38px;
   height: 38px;
   background: linear-gradient(135deg, #3b82f6, #6366f1);
   border-radius: 8px;
   display: flex;
   align-items: center;
   justify-content: center;
   box-shadow: 0 0 15px rgba(59, 130, 246, 0.4);
 }
 h1 {
   font-size: 1.7rem;
   font-weight: 700;
   letter-spacing: -0.02em;
   color: var(--text-primary);
 }
 .subtitle {
   color: var(--text-secondary);
   font-size: 1.0rem;
   margin-top: 0.2rem;
 }
 .header-badges {
   display: flex;
   gap: 0.5rem;
   flex-wrap: wrap;
 }
 .badge {
   font-size: 0.84rem;
   padding: 0.25rem 0.6rem;
   border-radius: 20px;
   background: rgba(51, 65, 85, 0.6);
   border: 1px solid var(--card-border);
   color: var(--text-secondary);
   font-weight: 500;
 }

 .card {
   background: var(--card-bg);
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.5rem;
   margin-bottom: 1.5rem;
   box-shadow: 0 4px 20px rgba(0,0,0,0.2);
 }
 .card-header {
   display: flex;
   justify-content: space-between;
   align-items: center;
   margin-bottom: 1rem;
   gap: 1rem;
   flex-wrap: wrap;
 }
 .card-title {
   font-size: 1.2rem;
   font-weight: 600;
   display: flex;
   align-items: center;
   gap: 0.5rem;
   color: var(--text-primary);
 }
 .icon { width: 20px; height: 20px; stroke: var(--accent-primary); }
 .icon-sm { width: 16px; height: 16px; margin-right: 0.3rem; vertical-align: middle; }

 form.scan-form {
   display: flex;
   gap: 0.75rem;
   flex-wrap: wrap;
   align-items: center;
 }
 input[type=text].url-input {
   flex: 1;
   min-width: 280px;
   padding: 0.75rem 1rem;
   font-size: 1.05rem;
   background: #0f172a;
   border: 1px solid var(--card-border);
   border-radius: 8px;
   color: var(--text-primary);
   outline: none;
   transition: border-color 0.2s, box-shadow 0.2s;
 }
 input[type=text].url-input:focus {
   border-color: var(--accent-primary);
   box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
 }
 .btn {
   padding: 0.75rem 1.25rem;
   border-radius: 8px;
   border: none;
   font-weight: 600;
   font-size: 1.05rem;
   cursor: pointer;
   display: inline-flex;
   align-items: center;
   justify-content: center;
   transition: background 0.2s, transform 0.1s, box-shadow 0.2s;
 }
 .btn-primary {
   background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
   color: #fff;
   box-shadow: 0 2px 10px rgba(59, 130, 246, 0.3);
 }
 .btn-primary:hover {
   background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
 }
 .btn-secondary {
   background: #334155;
   color: var(--text-primary);
 }
 .btn-secondary:hover { background: #475569; }
 .btn-success {
   background: linear-gradient(135deg, #10b981 0%, #059669 100%);
   color: #fff;
   box-shadow: 0 2px 10px rgba(16, 185, 129, 0.3);
 }
 .btn-success:hover { background: linear-gradient(135deg, #059669 0%, #047857 100%); }
 .btn-sm { padding: 0.4rem 0.8rem; font-size: 0.95rem; }

 .checkbox-label {
   display: flex;
   align-items: center;
   gap: 0.4rem;
   color: var(--text-secondary);
   font-size: 1.0rem;
   cursor: pointer;
   user-select: none;
   white-space: nowrap;
 }
 input[type=checkbox] {
   accent-color: var(--accent-primary);
   width: 16px;
   height: 16px;
 }

  .security-guarantee-card {
    background: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-left: 5px solid var(--sev-info);
  }
 .demo-card {
   background: rgba(30, 41, 59, 0.7);
   border: 1px solid rgba(245, 158, 11, 0.3);
   border-left: 4px solid var(--sev-med);
 }
 .demo-flex {
   display: flex;
   justify-content: space-between;
   align-items: center;
   flex-wrap: wrap;
   gap: 1rem;
 }

 .metrics-grid {
   display: grid;
   grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
   gap: 1rem;
   margin-bottom: 1.5rem;
 }
 .metric-card {
   background: var(--card-bg);
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.25rem;
 }
 .metric-title {
   font-size: 0.95rem;
   color: var(--text-secondary);
   text-transform: uppercase;
   letter-spacing: 0.05em;
   font-weight: 600;
 }
 .metric-value {
   font-size: 1.8rem;
   font-weight: 700;
   margin: 0.4rem 0 0.1rem 0;
 }
 .metric-sub {
   font-size: 0.89rem;
   color: var(--text-muted);
 }
 .status-danger { color: var(--sev-high); }
 .status-warning { color: var(--sev-med); }
 .status-secure { color: var(--sev-info); }
 .text-high { color: var(--sev-high); }
 .text-med { color: var(--sev-med); }
 .text-low { color: var(--sev-low); }

 .filter-toolbar {
   display: flex;
   justify-content: space-between;
   align-items: center;
   margin-bottom: 1rem;
   gap: 1rem;
   flex-wrap: wrap;
 }
 .filter-tabs {
   display: flex;
   gap: 0.4rem;
 }
 .filter-btn {
   background: #0f172a;
   border: 1px solid var(--card-border);
   color: var(--text-secondary);
   padding: 0.4rem 0.8rem;
   border-radius: 6px;
   font-size: 0.95rem;
   cursor: pointer;
   transition: all 0.2s;
 }
 .filter-btn.active, .filter-btn:hover {
   background: var(--accent-primary);
   color: #fff;
   border-color: var(--accent-primary);
 }
 .search-field {
   padding: 0.4rem 0.8rem;
   font-size: 0.95rem;
   background: #0f172a;
   border: 1px solid var(--card-border);
   border-radius: 6px;
   color: var(--text-primary);
   outline: none;
   width: 240px;
 }

 .finding-card {
   background: var(--card-bg);
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.25rem;
   margin-bottom: 1rem;
   transition: transform 0.15s, box-shadow 0.15s;
 }
 .finding-card:hover {
   box-shadow: 0 4px 15px rgba(0,0,0,0.3);
 }
 .finding-header {
   display: flex;
   align-items: center;
   gap: 0.6rem;
   flex-wrap: wrap;
   margin-bottom: 0.6rem;
 }
 .finding-title {
   font-size: 1.15rem;
   font-weight: 600;
   color: var(--text-primary);
   flex: 1;
 }
 .sev-badge {
   font-size: 0.78rem;
   font-weight: 700;
   padding: 0.2rem 0.5rem;
   border-radius: 4px;
   color: #fff;
   letter-spacing: 0.05em;
 }
  .sev-high { background: var(--sev-high); }
  .sev-medium { background: var(--sev-med); }
  .sev-low { background: var(--sev-low); color: #000; }
  .sev-info { background: var(--sev-info); }
  .conf-high { background: #059669; }
  .conf-medium { background: #d97706; }
  .conf-low { background: #64748b; }
  .tags-badge {
    font-size: 0.84rem;
    color: var(--text-muted);
    background: #0f172a;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    border: 1px solid var(--card-border);
  }
  .finding-context {
    font-size: 0.87rem;
    color: var(--accent-primary);
    margin-bottom: 0.75rem;
  }
  .citation-meta {
    font-size: 0.84rem;
    color: var(--text-muted);
    margin-top: 0.3rem;
  }
  .citation-match {
    color: #34d399;
    margin-right: 0.5rem;
  }

 .finding-detail {
   color: var(--text-secondary);
   font-size: 1.02rem;
   margin-bottom: 0.75rem;
 }
 .fix-box {
   background: rgba(16, 185, 129, 0.1);
   border: 1px solid rgba(16, 185, 129, 0.3);
   padding: 0.6rem 0.8rem;
   border-radius: 6px;
   font-size: 0.98rem;
   color: #a7f3d0;
   margin-bottom: 0.75rem;
 }

 .citations-wrapper {
   margin-top: 0.8rem;
   padding-top: 0.8rem;
   border-top: 1px dashed var(--card-border);
   font-size: 0.95rem;
   color: var(--text-muted);
 }
 .citation-box {
   background: #0f172a;
   border: 1px solid var(--card-border);
   border-radius: 6px;
   padding: 0.75rem;
   margin-top: 0.5rem;
 }
 .citation-head {
   display: flex;
   justify-content: space-between;
   align-items: center;
   gap: 0.5rem;
   flex-wrap: wrap;
   margin-bottom: 0.3rem;
 }
 .citation-title { font-weight: 600; color: var(--text-primary); }
 .citation-auth { font-size: 0.84rem; color: var(--accent-primary); }
 .citation-link { color: var(--accent-primary); text-decoration: none; font-size: 0.84rem; }
 .citation-link:hover { text-decoration: underline; }
 .citation-passage { font-style: italic; color: var(--text-secondary); font-size: 0.92rem; }

 .fix-bundle-card {
   border-color: var(--accent-primary);
 }
 .tab-buttons {
   display: flex;
   gap: 0.5rem;
   margin-bottom: 1rem;
   border-bottom: 1px solid var(--card-border);
   padding-bottom: 0.5rem;
 }
 .tab-btn {
   background: transparent;
   border: none;
   color: var(--text-secondary);
   padding: 0.4rem 0.8rem;
   font-size: 1.0rem;
   font-weight: 500;
   cursor: pointer;
   border-radius: 4px;
 }
 .tab-btn.active {
   background: var(--accent-primary);
   color: #fff;
 }
 .fix-tab-content { display: none; }
 .fix-tab-content.active { display: block; }
 pre {
   background: #070a11;
   padding: 1rem;
   border-radius: 6px;
   overflow-x: auto;
   font-family: monospace;
   font-size: 0.95rem;
   color: #e2e8f0;
   border: 1px solid var(--card-border);
 }
 .remediation-notes {
   margin-top: 1rem;
   font-size: 0.98rem;
   color: var(--text-secondary);
 }
 .remediation-notes ul {
   margin-left: 1.2rem;
   margin-top: 0.3rem;
 }

 /* Audit Progress Bar Styles */
 .progress-card {
   display: block;
   background: #0f172a;
   border: 1px solid var(--accent-primary);
   border-radius: var(--radius);
   padding: 1.5rem;
   margin-bottom: 1.5rem;
   box-shadow: 0 0 25px rgba(59, 130, 246, 0.25);
   animation: fadeIn 0.3s ease-in-out;
 }
 @keyframes fadeIn {
   from { opacity: 0; transform: translateY(-10px); }
   to { opacity: 1; transform: translateY(0); }
 }
 .progress-header {
   display: flex;
   justify-content: space-between;
   align-items: center;
   margin-bottom: 0.8rem;
   flex-wrap: wrap;
   gap: 0.5rem;
 }
 .progress-title-group {
   display: flex;
   align-items: center;
   gap: 0.75rem;
 }
 .progress-spinner {
   width: 22px;
   height: 22px;
   border: 3px solid rgba(59, 130, 246, 0.25);
   border-top-color: var(--accent-primary);
   border-radius: 50%;
   animation: spin 0.8s linear infinite;
 }
 @keyframes spin {
   to { transform: rotate(360deg); }
 }
 .progress-percent {
   font-size: 2rem;
   font-weight: 700;
   color: var(--accent-primary);
   font-variant-numeric: tabular-nums;
 }
 .progress-bar-track {
   width: 100%;
   height: 12px;
   background: #1e293b;
   border-radius: 20px;
   overflow: hidden;
   margin-bottom: 1.25rem;
   border: 1px solid var(--card-border);
 }
 .progress-bar-fill {
   height: 100%;
   width: 0%;
   background: linear-gradient(90deg, #3b82f6 0%, #6366f1 50%, #10b981 100%);
   border-radius: 20px;
   transition: width 0.15s linear;
   box-shadow: 0 0 12px rgba(59, 130, 246, 0.6);
 }
 .progress-steps-list {
   display: grid;
   grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
   gap: 0.6rem;
   margin-top: 1rem;
   padding-top: 1rem;
   border-top: 1px dashed var(--card-border);
   font-size: 0.93rem;
 }
 .step-item {
   display: flex;
   align-items: center;
   gap: 0.4rem;
   color: var(--text-muted);
   transition: color 0.3s ease;
 }
 .step-item.active {
   color: var(--accent-primary);
   font-weight: 600;
 }
 .step-item.completed {
   color: var(--sev-info);
   font-weight: 500;
 }
 .step-badge {
   width: 18px;
   height: 18px;
   border-radius: 50%;
   background: #1e293b;
   border: 1px solid var(--card-border);
   display: inline-flex;
   align-items: center;
   justify-content: center;
   font-size: 0.78rem;
 }
 .step-item.completed .step-badge {
   background: var(--sev-info);
   color: #000;
   border-color: var(--sev-info);
 }

 footer {
   margin-top: 3rem;
   text-align: center;
   color: var(--text-muted);
   font-size: 0.89rem;
   border-top: 1px solid var(--card-border);
   padding-top: 1.5rem;
 }"""


# Code Review / Dependency Scan / Test Gen card styles (appended to STYLES_CSS).
_DEV_CSS = """
 .dev-card {
   border-left: 4px solid var(--accent-primary);
 }
 .dev-grid {
   display: grid;
   grid-template-columns: 1fr 1fr;
   gap: 1rem;
   margin-top: 0.75rem;
 }
 @media (max-width: 992px) {
   .dev-grid { grid-template-columns: 1fr; }
 }
 .dev-box {
   background: #0f172a;
   border: 1px solid var(--card-border);
   border-radius: 8px;
   padding: 0.9rem;
 }
 .dev-box h5 {
   color: var(--text-primary);
   font-size: 1.0rem;
   margin-bottom: 0.5rem;
   display: flex;
   align-items: center;
   gap: 0.4rem;
 }
 textarea.code-textarea {
   width: 100%;
   min-height: 130px;
   max-height: 260px;
   resize: vertical;
   background: #070a11;
   border: 1px solid var(--card-border);
   border-radius: 6px;
   color: #e2e8f0;
   font-family: ui-monospace, Consolas, 'Courier New', monospace;
   font-size: 0.92rem;
   padding: 0.6rem;
   outline: none;
   box-sizing: border-box;
 }
 textarea.code-textarea:focus {
   border-color: var(--accent-primary);
 }
 .dev-box input.dev-filename {
   width: 100%;
   margin-top: 0.4rem;
   background: #0f172a;
   border: 1px solid var(--card-border);
   border-radius: 6px;
   color: var(--text-primary);
   font-size: 0.92rem;
   padding: 0.4rem 0.6rem;
   outline: none;
   box-sizing: border-box;
 }
 .dev-actions {
   display: flex;
   align-items: center;
   gap: 0.6rem;
   margin-top: 0.6rem;
   flex-wrap: wrap;
 }
 .dev-actions .btn-sm { font-size: 0.95rem; }
 .dev-note {
   color: var(--text-muted);
   font-size: 0.82rem;
   margin-top: 0.5rem;
 }
"""


STYLES_CSS += owasptop10.owasp_css() + _DEV_CSS



# External UI runtime served at /static/app.js. Kept out of the HTML so the
# Content-Security-Policy can drop 'unsafe-inline' from script-src (OWASP-CSP).
APP_JS = """/* websec-auditor UI runtime (external file so CSP can drop 'unsafe-inline'). */
var KB_TOTAL_JS = 0;
(function () {
  var meta = document.querySelector('meta[name="kb-total"]');
  if (meta) KB_TOTAL_JS = parseInt(meta.getAttribute('content'), 10) || 0;
})();

function startScanProgress(evt) {
  if (evt) evt.preventDefault();
  var form = document.querySelector('form.scan-form');
  var urlInput = document.querySelector('input[name="target"]');
  if (!urlInput || !urlInput.value.trim()) {
    alert('Please enter a target URL.');
    return false;
  }
  var crawlEl = document.querySelector('input[name="crawl"]');
  var isCrawl = crawlEl ? crawlEl.checked : false;

  var card = document.getElementById('progress-card');
  var fill = document.getElementById('progress-bar-fill');
  var num = document.getElementById('progress-percent-num');
  var stageText = document.getElementById('progress-stage-text');
  var mainTitle = document.getElementById('progress-main-title');
  var spinner = document.getElementById('progress-spinner-icon');
  var step1 = document.getElementById('step-1');
  var step2 = document.getElementById('step-2');
  var step3 = document.getElementById('step-3');
  var step4 = document.getElementById('step-4');
  var step5 = document.getElementById('step-5');

  if (card) card.style.display = 'block';
  if (spinner) spinner.style.display = 'inline-block';
  if (mainTitle) { mainTitle.textContent = 'Security Audit & Crawl in Progress'; mainTitle.style.color = 'var(--text-primary)'; }
  if (num) { num.textContent = '1%'; num.style.color = 'var(--accent-primary)'; }
  if (fill) { fill.style.width = '1%'; fill.style.background = 'linear-gradient(90deg, #3b82f6 0%, #6366f1 50%, #10b981 100%)'; }
  if (stageText) stageText.textContent = 'Connecting to target & checking TLS...';

  if (step1) { step1.className = 'step-item active'; var b1 = step1.querySelector('.step-badge'); if (b1) b1.textContent = '1'; }
  if (step2) { step2.className = 'step-item'; var b2 = step2.querySelector('.step-badge'); if (b2) b2.textContent = '2'; }
  if (step3) { step3.className = 'step-item'; var b3 = step3.querySelector('.step-badge'); if (b3) b3.textContent = '3'; }
  if (step4) { step4.className = 'step-item'; var b4 = step4.querySelector('.step-badge'); if (b4) b4.textContent = '4'; }
  if (step5) { step5.className = 'step-item'; var b5 = step5.querySelector('.step-badge'); if (b5) b5.textContent = '5'; }

  if (card) {
    try { card.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) {}
  }

  var btn = document.getElementById('scan-submit-btn');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="progress-spinner" style="width:14px;height:14px;margin-right:0.4rem;display:inline-block;vertical-align:middle;"></span> Auditing...';
  }

  var currentPercent = 1;
  var targetPercent = 99;
  var responseHtml = null;
  var fetchDone = false;

  var timer = setInterval(function () {
    if (currentPercent < targetPercent) {
      currentPercent += 1;
    } else if (fetchDone && currentPercent >= 99) {
      currentPercent = 100;
    }
    if (fill) fill.style.width = currentPercent + '%';
    if (num) num.textContent = currentPercent + '%';

    if (currentPercent >= 15 && step1) {
      step1.className = 'step-item completed';
      var b1 = step1.querySelector('.step-badge'); if (b1) b1.textContent = '\\u2713';
      if (step2 && !step2.classList.contains('completed')) step2.className = 'step-item active';
      if (stageText) stageText.textContent = 'Executing security assessment probes...';
    }
    if (currentPercent >= 40 && step2) {
      step2.className = 'step-item completed';
      var b2 = step2.querySelector('.step-badge'); if (b2) b2.textContent = '\\u2713';
      if (step3 && !step3.classList.contains('completed')) step3.className = 'step-item active';
      if (stageText) stageText.textContent = isCrawl ? 'Crawling site-wide execution paths & entry points...' : 'Inspecting HTTP headers & session cookies...';
    }
    if (currentPercent >= 65 && step3) {
      step3.className = 'step-item completed';
      var b3 = step3.querySelector('.step-badge'); if (b3) b3.textContent = '\\u2713';
      if (step4 && !step4.classList.contains('completed')) step4.className = 'step-item active';
      if (stageText) stageText.textContent = 'Grounding findings against ' + KB_TOTAL_JS + ' OWASP/CWE references...';
    }
    if (currentPercent >= 88 && step4) {
      step4.className = 'step-item completed';
      var b4 = step4.querySelector('.step-badge'); if (b4) b4.textContent = '\\u2713';
      if (step5 && !step5.classList.contains('completed')) step5.className = 'step-item active';
      if (stageText) stageText.textContent = 'Generating remediation bundle & final dashboard...';
    }

    if (currentPercent >= 100) {
      clearInterval(timer);
      if (fill) { fill.style.width = '100%'; fill.style.background = '#10b981'; }
      if (num) { num.textContent = '100%'; num.style.color = '#10b981'; }
      if (spinner) spinner.style.display = 'none';
      if (mainTitle) { mainTitle.textContent = '\\u2713 Security Audit & Grounding Completed'; mainTitle.style.color = '#10b981'; }
      if (stageText) stageText.textContent = 'Audit completed & grounded against ' + KB_TOTAL_JS + ' OWASP/CWE references.';
      [step1, step2, step3, step4, step5].forEach(function (st) {
        if (st) {
          st.className = 'step-item completed';
          var b = st.querySelector('.step-badge');
          if (b) b.textContent = '\\u2713';
        }
      });
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = 'Run Security Audit';
      }
      if (responseHtml) {
        var tempDiv = document.createElement('div');
        tempDiv.innerHTML = responseHtml;
        var newResults = tempDiv.querySelector('#results-wrapper');
        var wrapper = document.getElementById('results-wrapper');
        if (wrapper && newResults) {
          wrapper.innerHTML = newResults.innerHTML;
          try { wrapper.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) {}
        }
        var newHeading = tempDiv.querySelector('#report-heading');
        var headingEl = document.getElementById('report-heading');
        if (headingEl && newHeading) headingEl.innerHTML = newHeading.innerHTML;
        var newUsage = tempDiv.querySelector('#usage-count');
        var usageEl = document.getElementById('usage-count');
        if (usageEl && newUsage) usageEl.innerHTML = newUsage.innerHTML;
      }
    }
  }, isCrawl ? 35 : 20);

  var formData = new FormData(form);
  var controller = null;
  if (typeof AbortController !== 'undefined') { controller = new AbortController(); }
  var fetchTimeout = setTimeout(function () {
    if (controller) { try { controller.abort(); } catch (e) {} }
  }, 70000);

  fetch('/scan', {
    method: 'POST',
    body: new URLSearchParams(formData),
    signal: controller ? controller.signal : undefined
  })
    .then(function (res) {
      return res.text().then(function (text) { return { status: res.status, text: text }; });
    })
    .then(function (r) {
      clearTimeout(fetchTimeout);
      if (r.status === 403) {
        clearInterval(timer);
        if (btn) { btn.disabled = false; btn.innerHTML = 'Run Security Audit'; }
        if (fill) fill.style.width = '0%';
        if (num) num.textContent = '0%';
        if (spinner) spinner.style.display = 'none';
        if (mainTitle) { mainTitle.textContent = 'Session Expired / Security Check'; mainTitle.style.color = '#ef4444'; }
        if (stageText) stageText.textContent = 'CSRF token or origin verification refreshed. Please reload the page and try again.';
        return;
      }
      if (r.status === 429) {
        clearInterval(timer);
        if (btn) { btn.disabled = false; btn.innerHTML = 'Run Security Audit'; }
        if (fill) fill.style.width = '0%';
        if (num) num.textContent = '0%';
        if (spinner) spinner.style.display = 'none';
        if (mainTitle) { mainTitle.textContent = 'Rate Limit Reached'; mainTitle.style.color = '#f59e0b'; }
        if (stageText) stageText.textContent = 'Please wait 60 seconds before initiating another audit scan.';
        return;
      }
      if (r.status >= 500 || /GATEWAY_TIMEOUT|FUNCTION_INVOCATION_TIMEOUT|504|502/.test(r.text.slice(0, 4000))) {
        clearInterval(timer);
        if (btn) { btn.disabled = false; btn.innerHTML = 'Run Security Audit'; }
        if (fill) fill.style.width = '0%';
        if (num) num.textContent = '0%';
        if (spinner) spinner.style.display = 'none';
        if (mainTitle) { mainTitle.textContent = 'Scan timed out on the server'; mainTitle.style.color = '#f59e0b'; }
        if (stageText) stageText.textContent = 'The target was too slow or is blocking automated scans, so the scan hit the server time limit. Try again, or use a single page scan instead of site-wide crawl.';
        return;
      }
      if (r.status >= 400) {
        clearInterval(timer);
        if (btn) { btn.disabled = false; btn.innerHTML = 'Run Security Audit'; }
        if (fill) fill.style.width = '0%';
        if (num) num.textContent = '0%';
        if (spinner) spinner.style.display = 'none';
        if (mainTitle) { mainTitle.textContent = 'Scan request error (' + r.status + ')'; mainTitle.style.color = '#ef4444'; }
        if (stageText) stageText.textContent = 'The server encountered an error processing the scan request. Please verify the URL.';
        return;
      }
      responseHtml = r.text;
      fetchDone = true;
      targetPercent = 100;
    })
    .catch(function (err) {
      clearTimeout(fetchTimeout);
      clearInterval(timer);
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = 'Run Security Audit';
      }
      if (fill) fill.style.width = '0%';
      if (num) num.textContent = '0%';
      if (spinner) spinner.style.display = 'none';
      if (mainTitle) { mainTitle.textContent = 'Scan did not finish'; mainTitle.style.color = '#f59e0b'; }
      if (stageText) {
        stageText.textContent = (err && err.name === 'AbortError')
          ? 'The scan took too long and was stopped. The target may be very slow or blocking automated scans. Try a single page scan instead of site-wide crawl.'
          : 'Scan error: ' + (err && err.message ? err.message : err);
      }
    });

  return false;
}

function switchFixTab(evt, tabId) {
  var contents = document.querySelectorAll('.fix-tab-content');
  contents.forEach(function (c) { c.classList.remove('active'); });
  var btns = document.querySelectorAll('.tab-btn');
  btns.forEach(function (b) { b.classList.remove('active'); });
  var tab = document.getElementById(tabId);
  if (tab) tab.classList.add('active');
  if (evt && evt.currentTarget) evt.currentTarget.classList.add('active');
}

function downloadFixFile(evt, target) {
  evt.preventDefault();
  var nginx = document.querySelector('#nginx-tab pre') ? document.querySelector('#nginx-tab pre').innerText : '';
  var apache = document.querySelector('#apache-tab pre') ? document.querySelector('#apache-tab pre').innerText : '';
  var flask = document.querySelector('#flask-tab pre') ? document.querySelector('#flask-tab pre').innerText : '';
  var express = document.querySelector('#express-tab pre') ? document.querySelector('#express-tab pre').innerText : '';

  var text = '# websec-auditor remediation bundle for ' + target + '\\n\\n' +
             '## Nginx\\n' + nginx + '\\n\\n' +
             '## Apache\\n' + apache + '\\n\\n' +
             '## Flask\\n' + flask + '\\n\\n' +
             '## Express\\n' + express + '\\n';

  var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'websec-fix.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function filterFindings(sev, btn) {
  var cards = document.querySelectorAll('.finding-card');
  var btns = document.querySelectorAll('.filter-btn');
  btns.forEach(function (b) { b.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  cards.forEach(function (card) {
    if (sev === 'all' || card.getAttribute('data-severity') === sev) {
      card.style.display = 'block';
    } else {
      card.style.display = 'none';
    }
  });
}

function searchFindings() {
  var input = document.getElementById('search-input');
  var query = input ? input.value.toLowerCase() : '';
  var cards = document.querySelectorAll('.finding-card');
  cards.forEach(function (card) {
    var text = card.innerText.toLowerCase();
    if (text.indexOf(query) !== -1) {
      card.style.display = 'block';
    } else {
      card.style.display = 'none';
    }
  });
}

function openDonateModal(type) {
  var modal = document.getElementById('donate-modal');
  var content = document.getElementById('modal-content');
  if (!modal || !content) return;
  var htmlStr = '';
  if (type === 'paypal') {
    htmlStr = '<h3 style="color:#3b82f6; margin-bottom:0.6rem;">\\uD83D\\uDC99 PayPal / Credit Card</h3>' +
              '<p style="font-size:0.98rem; color:var(--text-secondary);">Donate securely via PayPal or Credit/Debit Card to <b>@ChristineANGELIZate</b>:</p>' +
              '<div style="margin-top:1.2rem; text-align:center;">' +
              '<a href="https://paypal.me/ChristineANGELIZate" target="_blank" rel="noopener" class="btn btn-primary" style="display:inline-block; padding:0.6rem 1.2rem; text-decoration:none; background:#003087;">Donate via PayPal &rarr;</a>' +
              '</div>';
  }
  content.innerHTML = htmlStr;
  modal.style.display = 'flex';
}

function closeDonateModal() {
  var modal = document.getElementById('donate-modal');
  if (modal) modal.style.display = 'none';
}

function getCsrfToken() {
  var m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.getAttribute('content') : '';
}

function selfHarden() {
  var btn = document.getElementById('self-harden-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Hardening...'; }
  var wrapper = document.getElementById('self-harden-result');
  if (wrapper) wrapper.innerHTML = '<div class="card"><p>Applying KB-grounded hardening and re-auditing...</p></div>';
  var body = new URLSearchParams();
  body.set('_token', getCsrfToken());
  fetch('/self-harden', { method: 'POST', body: body })
    .then(function (res) { return res.text(); })
    .then(function (htmlText) {
      var temp = document.createElement('div');
      temp.innerHTML = htmlText;
      var newResults = temp.querySelector('#results-wrapper');
      var mainResults = document.getElementById('results-wrapper');
      if (mainResults && newResults) mainResults.innerHTML = newResults.innerHTML;
      var newHeading = temp.querySelector('#report-heading');
      var headingEl = document.getElementById('report-heading');
      if (headingEl && newHeading) headingEl.innerHTML = newHeading.innerHTML;
      if (wrapper) wrapper.innerHTML = '';
      if (btn) { btn.disabled = false; btn.textContent = 'Apply KB Hardening & Re-Audit'; }
      try { mainResults.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) {}
    })
    .catch(function (err) {
      if (wrapper) wrapper.innerHTML = '<div class="card"><p style="color:#ef4444">Error: ' + err.message + '</p></div>';
      if (btn) { btn.disabled = false; btn.textContent = 'Apply KB Hardening & Re-Audit'; }
    });
}

function codeReview() {
  var input = document.getElementById('code-review-input');
  var status = document.getElementById('code-review-status');
  if (!input || !input.value.trim()) { alert('Paste source code to review first.'); return; }
  var filename = document.getElementById('code-review-filename');
  var btn = document.getElementById('code-review-btn');
  if (btn) btn.disabled = true;
  if (status) status.textContent = 'Running KB-grounded code review...';
  var body = new URLSearchParams();
  body.set('code', input.value);
  body.set('filename', filename ? filename.value : '');
  body.set('_token', getCsrfToken());
  fetch('/code-review', { method: 'POST', body: body })
    .then(function (res) { return res.text(); })
    .then(function (htmlText) {
      var temp = document.createElement('div');
      temp.innerHTML = htmlText;
      var wrapper = document.getElementById('results-wrapper');
      var newResults = temp.querySelector('#results-wrapper');
      if (wrapper && newResults) {
        wrapper.innerHTML = newResults.innerHTML;
        var heading = document.getElementById('report-heading');
        var newHeading = temp.querySelector('#report-heading');
        if (heading && newHeading) heading.innerHTML = newHeading.innerHTML;
        try { wrapper.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) {}
      }
      if (status) status.textContent = '';
      if (btn) btn.disabled = false;
    })
    .catch(function (err) {
      if (status) status.textContent = 'Error: ' + err.message;
      if (btn) btn.disabled = false;
    });
}

function depsScan() {
  var input = document.getElementById('deps-input');
  var status = document.getElementById('deps-status');
  if (!input || !input.value.trim()) { alert('Paste a dependency manifest first.'); return; }
  var filename = document.getElementById('deps-filename');
  var btn = document.getElementById('deps-btn');
  if (btn) btn.disabled = true;
  if (status) status.textContent = 'Checking against local advisory seed...';
  var body = new URLSearchParams();
  body.set('manifest', input.value);
  body.set('filename', filename ? filename.value : 'requirements.txt');
  body.set('_token', getCsrfToken());
  fetch('/deps-scan', { method: 'POST', body: body })
    .then(function (res) { return res.text(); })
    .then(function (htmlText) {
      var temp = document.createElement('div');
      temp.innerHTML = htmlText;
      var wrapper = document.getElementById('results-wrapper');
      var newResults = temp.querySelector('#results-wrapper');
      if (wrapper && newResults) {
        wrapper.innerHTML = newResults.innerHTML;
        var heading = document.getElementById('report-heading');
        var newHeading = temp.querySelector('#report-heading');
        if (heading && newHeading) heading.innerHTML = newHeading.innerHTML;
        try { wrapper.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) {}
      }
      if (status) status.textContent = '';
      if (btn) btn.disabled = false;
    })
    .catch(function (err) {
      if (status) status.textContent = 'Error: ' + err.message;
      if (btn) btn.disabled = false;
    });
}

function downloadTests() {
  var body = new URLSearchParams();
  body.set('action', 'download-tests');
  body.set('_token', getCsrfToken());
  fetch('/download-tests', { method: 'POST', body: body })
    .then(function (res) { return res.text(); })
    .then(function (text) {
      var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'websec-tests.txt';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    })
    .catch(function (err) { alert('Test generation error: ' + err.message); });
}

document.addEventListener('DOMContentLoaded', function () {
  var scanForm = document.getElementById('scan-form');
  if (scanForm) scanForm.addEventListener('submit', function (evt) { startScanProgress(evt); });

  document.querySelectorAll('[data-sev]').forEach(function (b) {
    b.addEventListener('click', function (evt) { filterFindings(evt.currentTarget.getAttribute('data-sev'), evt.currentTarget); });
  });
  var searchInput = document.getElementById('search-input');
  if (searchInput) searchInput.addEventListener('keyup', searchFindings);

  document.querySelectorAll('[data-tab]').forEach(function (b) {
    b.addEventListener('click', function (evt) { switchFixTab(evt, evt.currentTarget.getAttribute('data-tab')); });
  });

  document.querySelectorAll('[data-modal]').forEach(function (b) {
    b.addEventListener('click', function (evt) { openDonateModal(evt.currentTarget.getAttribute('data-modal')); });
  });

  var modal = document.getElementById('donate-modal');
  if (modal) modal.addEventListener('click', function (evt) { if (evt.target === this) closeDonateModal(); });
  var modalClose = document.querySelector('.modal-close');
  if (modalClose) modalClose.addEventListener('click', closeDonateModal);

  var fixForm = document.getElementById('download-fix-form');
  if (fixForm) fixForm.addEventListener('submit', function (evt) {
    downloadFixFile(evt, fixForm.getAttribute('data-target'));
  });

  var shBtn = document.getElementById('self-harden-btn');
  if (shBtn) shBtn.addEventListener('click', function (evt) { selfHarden(); });

  var crBtn = document.getElementById('code-review-btn');
  if (crBtn) crBtn.addEventListener('click', codeReview);
  var depsBtn = document.getElementById('deps-btn');
  if (depsBtn) depsBtn.addEventListener('click', depsScan);
  var dtBtn = document.getElementById('download-tests-btn');
  if (dtBtn) dtBtn.addEventListener('click', downloadTests);
});
"""


def render_kb_rules_inspector() -> str:
    from websec_auditor.scanner.engine import load_kb_rules
    rules = load_kb_rules()
    if not rules:
        return ""
    
    items_html = []
    for r in rules:
        rtype = html.escape(str(r.get("type", "")))
        rname = html.escape(str(r.get("name") or r.get("flag") or r.get("source_id", "")))
        sev = html.escape(str(r.get("severity", "info")))
        cwe = html.escape(str(r.get("cwe", "")))
        owasp = html.escape(str(r.get("owasp", "")))
        source_id = html.escape(str(r.get("source_id", "")))
        
        items_html.append(f"""
        <div style="background:#0f172a; border:1px solid var(--card-border); border-radius:6px; padding:0.6rem 0.8rem; font-size:0.92rem; display:flex; justify-content:space-between; align-items:center; gap:0.5rem;">
          <div>
            <span class="sev-badge sev-{sev}" style="padding:0.15rem 0.4rem; font-size:0.78rem;">{sev.upper()}</span>
            <b style="color:var(--text-primary); margin-left:0.3rem;">{rname}</b>
            <span style="color:var(--text-muted); margin-left:0.4rem;">({rtype})</span>
          </div>
          <div style="color:var(--text-secondary); font-size:0.84rem;">
            <span class="badge" style="font-size:0.78rem; padding:0.1rem 0.4rem;">{source_id}</span>
            {f'<span class="badge" style="font-size:0.78rem; padding:0.1rem 0.4rem;">{cwe}</span>' if cwe else ''}
          </div>
        </div>
        """)
        
    kb_count = kb_stats()["total"]

    return f"""
    <details class="card" style="cursor:pointer; margin-bottom:1.5rem;">
      <summary style="font-weight:600; color:var(--accent-primary); outline:none; display:flex; align-items:center; justify-content:space-between;">
        <span>
          <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>
          <b>Knowledge Base Audit Engine &bull; {kb_count:,} References & {len(rules)} Active Book-Grounded Rules Loaded</b>
        </span>
        <span style="font-size:0.89rem; color:var(--text-secondary);">Click to view dynamic KB rules &rarr;</span>
      </summary>
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:0.6rem; margin-top:1rem;">
        {"".join(items_html)}
      </div>
    </details>
    """


def demo_block_html(kb_total: int = 0) -> str:
    return f"""
    <div class="card security-guarantee-card">
      <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.4rem;">
        <svg style="width:22px;height:22px;stroke:#10b981;fill:none;" viewBox="0 0 24 24" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 11 12 14 22 4"/></svg>
        <b style="color: #10b981; font-size: 1.15rem;">100% Safe &amp; Authorized Audit Guarantee &bull; Powered by {kb_total:,} Security References</b>
      </div>
      <p style="color: var(--text-secondary); font-size: 0.98rem; line-height:1.5;">
        Guaranteed <b>100% safe, non-destructive, read-only probes</b> with zero data modification or harmful payloads. Every security check, explanation, and remediation bundle is strictly grounded in <b>{kb_total:,} authoritative security standards &amp; curated cybersecurity books</b> (OWASP Top 10s, MITRE CWE Catalog, ASVS v4.0.3, NIST SP 800-53/160, ISO 27001:2022, PCI DSS v4.0, CIS Benchmarks, IETF RFCs).
      </p>
    </div>
    """


def dev_block_html() -> str:
    return """
    <div class="card dev-card">
      <div class="card-header">
        <div class="card-title">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          Code Review, Dependency Scan &amp; Security Test Generation
        </div>
        <span style="font-size:0.72rem; font-weight:700; padding:0.15rem 0.4rem; border-radius:4px; background:rgba(59,130,246,0.2); color:#60a5fa; border:1px solid rgba(59,130,246,0.4);">KB-GROUNDED</span>
      </div>
      <p style="font-size:0.93rem; color:var(--text-secondary); line-height:1.5; margin-bottom:0.75rem;">
        Static code review (SQLi, XSS, SSRF, insecure auth, deserialization, weak crypto...), dependency/advisory
        scanning (Log4Shell, prototype pollution, and other known CVEs), and generation of
        Burp Intruder / fuzzer / curl regression tests - all driven by the same knowledge-base rules.
      </p>
      <div class="dev-grid">
        <div class="dev-box">
          <h5>
            <svg style="width:16px;height:16px;stroke:#3b82f6;fill:none;" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            Static Code Review
          </h5>
          <textarea id="code-review-input" class="code-textarea" spellcheck="false"
            placeholder="Paste application source code here... (e.g. Python/JS/PHP/Java). Finds SQL injection, XSS sinks, SSRF, eval/exec, hardcoded credentials, pickle.loads, weak crypto, ..."></textarea>
          <input id="code-review-filename" class="dev-filename" type="text" placeholder="Filename hint (e.g. app.py) - optional">
          <div class="dev-actions">
            <button type="button" class="btn btn-secondary btn-sm" id="code-review-btn">Run Code Review</button>
            <span id="code-review-status" class="dev-note"></span>
          </div>
        </div>
        <div class="dev-box">
          <h5>
            <svg style="width:16px;height:16px;stroke:#3b82f6;fill:none;" viewBox="0 0 24 24" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>
            Dependency &amp; Advisory Scan
          </h5>
          <textarea id="deps-input" class="code-textarea" spellcheck="false"
            placeholder="Paste a manifest: requirements.txt, package.json, Gemfile.lock, pom.xml, go.mod, composer.json, ..."></textarea>
          <input id="deps-filename" class="dev-filename" type="text" value="requirements.txt">
          <div class="dev-actions">
            <button type="button" class="btn btn-secondary btn-sm" id="deps-btn">Scan Dependencies</button>
            <button type="button" class="btn btn-primary btn-sm" id="download-tests-btn" style="margin-left:auto;">
              <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Download Security Tests (Burp/Fuzz) for last scan
            </button>
            <span id="deps-status" class="dev-note"></span>
          </div>
        </div>
      </div>
    </div>
    """


def report_heading_html(target: str, kb_total: int = 0) -> str:
    if not target:
        return ""
    safe = html.escape(target)
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    return f"""
    <div class="card report-heading-card">
      <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
        <svg style="width:22px;height:22px;stroke:#3b82f6;fill:none; flex-shrink:0;" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        <b style="font-size:1.2rem; color:var(--text-primary);">Scan Report of:</b>
        <code style="font-size:1.05rem; color:#60a5fa; background:rgba(59,130,246,0.12); border:1px solid rgba(59,130,246,0.35); padding:0.2rem 0.6rem; border-radius:6px; word-break:break-all;">{safe}</code>
      </div>
      <p style="color:var(--text-secondary); font-size:0.95rem; margin:0;">
        The findings below are for this audited target &bull; grounded against <b>{kb_total:,}</b> security references &bull; <span style="color:var(--text-muted);">{ts}</span>
      </p>
    </div>
    """


def render_progress_card(has_results: bool = False, kb_total: int = 120) -> str:
    display_style = "display: block;"
    main_title = "✓ Security Audit & Grounding Completed" if has_results else "Security Audit Progress & Grounding Engine"
    stage_text = f"Audit probes executed & grounded against {kb_total:,} OWASP/CWE references." if has_results else "Ready to audit. Enter a target URL above and click Run Security Audit."
    percent_str = "100%" if has_results else "0%"
    fill_style = "width: 100%; background: #10b981; box-shadow: 0 0 12px rgba(16, 185, 129, 0.6);" if has_results else "width: 0%;"
    step_cls = "step-item completed" if has_results else "step-item"
    step1_cls = "step-item completed" if has_results else "step-item active"
    badge_txt = "✓" if has_results else ""
    title_color = "#10b981" if has_results else "var(--text-primary)"
    num_color = "#10b981" if has_results else "var(--accent-primary)"
    spinner_style = "display:none;"

    return f"""
    <!-- Security Audit Progress Bar Card -->
    <div id="progress-card" class="card progress-card" style="{display_style}">
      <div class="progress-header">
        <div class="progress-title-group">
          <div class="progress-spinner" id="progress-spinner-icon" style="{spinner_style}"></div>
          <div>
            <h3 style="font-size:1.2rem; font-weight:600; color:{title_color};" id="progress-main-title">{main_title}</h3>
            <div id="progress-stage-text" style="font-size:0.98rem; color:var(--text-secondary);">{stage_text}</div>
          </div>
        </div>
        <div class="progress-percent" id="progress-percent-num" style="color:{num_color};">{percent_str}</div>
      </div>

      <div class="progress-bar-track">
        <div id="progress-bar-fill" class="progress-bar-fill" style="{fill_style}"></div>
      </div>

      <div class="progress-steps-list">
        <div id="step-1" class="{step1_cls}">
          <span class="step-badge">{'✓' if has_results else '1'}</span> TLS & Domain Check
        </div>
        <div id="step-2" class="{step_cls}">
          <span class="step-badge">{'✓' if has_results else '2'}</span> Security Probes
        </div>
        <div id="step-3" class="{step_cls}">
          <span class="step-badge">{'✓' if has_results else '3'}</span> Crawl & Entry Points
        </div>
        <div id="step-4" class="{step_cls}">
          <span class="step-badge">{'✓' if has_results else '4'}</span> {kb_total:,} References Grounding
        </div>
        <div id="step-5" class="{step_cls}">
          <span class="step-badge">{'✓' if has_results else '5'}</span> Remediation Bundle
        </div>
      </div>
    </div>
    """


def render_page(results="", target="", cookie="", header=""):
    stats = kb_stats()
    total = stats["total"]
    has_res = bool(results and "card" in results)
    token = get_csrf_token()
    return PAGE.format(
        TARGET=html.escape(target),
        COOKIE=html.escape(cookie),
        HEADER=html.escape(header),
        CSRF_TOKEN=token,
        KB_TOTAL=f"{total:,}",
        KB_STD=f"{stats['standards']:,}",
        KB_RULES=f"{stats['rules']:,}",
        KB_BOOKS=f"{stats['books']:,}",
        USAGE_COUNT=f"{usage.get_count():,}",
        KB_TOTAL_NUM=total,
        results=results,
        demo_block=demo_block_html(total),
        dev_block=dev_block_html(),
        report_heading=report_heading_html(target, total),
        kb_rules_inspector=render_kb_rules_inspector(),
        progress_card=render_progress_card(has_res, total)
    )


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, ctype="text/html", code=200, extra=None):
        try:
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            
            # Security headers
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)

            # RateLimit-* headers advertise the enforced policy (OWASP RATELIMIT)
            remaining = self._rate_remaining()
            self.send_header("RateLimit-Limit", str(UI_RATE_MAX))
            self.send_header("RateLimit-Remaining", str(remaining))
            self.send_header("RateLimit-Reset", str(int(time.time()) + UI_RATE_WINDOW))
            if code == 429:
                self.send_header("Retry-After", str(UI_RATE_WINDOW))

            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def _validate_origin(self) -> bool:
        # Allow the request only when Origin/Referer matches the request Host
        # (same-origin) or an explicitly configured trusted origin.
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        fwd_host = (self.headers.get("X-Forwarded-Host") or "").split(",")[0].split(":")[0].strip().lower()
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True
        parsed = urllib.parse.urlparse(origin)
        origin_host = (parsed.hostname or "").lower()
        if not origin_host:
            return True
        if origin_host == host or (fwd_host and origin_host == fwd_host):
            return True
        allowed = [o.lower() for o in getattr(config, "ALLOWED_ORIGINS", [])]
        if origin_host in allowed:
            return True
        return False

    def _client_ip(self):
        # Trust platform-set headers first (Vercel sets x-vercel-proxied-for /
        # x-real-ip to the real peer IP); they cannot be spoofed by the client
        # behind the edge. Never trust the FIRST X-Forwarded-For value: a client
        # can send a spoofed XFF header, so take the rightmost entry, which is
        # appended by the last hop of the trusted proxy (RFC 7239).
        for hname in ("x-vercel-proxied-for", "x-real-ip"):
            v = (self.headers.get(hname) or "").strip()
            if v:
                return v.split(",")[-1].strip()
        fwd = self.headers.get("x-forwarded-for", "")
        if fwd:
            entries = [p.strip() for p in fwd.split(",") if p.strip()]
            if entries:
                return entries[-1]
        return getattr(self, "client_address", ("?",))[0]

    def _looks_like_url(self, value):
        if not value:
            return False
        if any(ord(c) < 33 for c in value):
            return False
        if " " in value or "\t" in value or "\n" in value:
            return False
        if value.lower().count("http") > 1:
            return False
        if any(w in value for w in ("Could not reach", "Target unreachable", "seen on",
                                    "not supported between instances")):
            return False
        v = value.lower()
        return v.startswith(("http://", "https://"))

    def _prune_hits(self, now):
        stale = []
        for ip, hits in _UI_HITS.items():
            live = [t for t in hits if now - t < UI_RATE_WINDOW]
            if not live:
                stale.append(ip)
            else:
                _UI_HITS[ip] = live
        for ip in stale:
            del _UI_HITS[ip]
        while len(_UI_HITS) > _UI_HITS_MAX:
            # Evict the least-recently-active bucket to keep the map bounded.
            lru = min(_UI_HITS.items(), key=lambda kv: max(kv[1], default=0))[0]
            del _UI_HITS[lru]

    def _rate_remaining(self):
        ip = self._client_ip()
        now = time.time()
        with _UI_LOCK:
            self._prune_hits(now)
            window = [t for t in _UI_HITS[ip] if now - t < UI_RATE_WINDOW]
        return max(0, UI_RATE_MAX - len(window))

    def _rate_limited(self):
        ip = self._client_ip()
        now = time.time()
        with _UI_LOCK:
            self._prune_hits(now)
            window = [t for t in _UI_HITS[ip] if now - t < UI_RATE_WINDOW]
            if len(window) >= UI_RATE_MAX:
                _UI_HITS[ip] = window
                return True
            window.append(now)
            _UI_HITS[ip] = window
        return False

    def do_GET(self):
        qs_all = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        raw_path = (self.headers.get("x-matched-path") or self.headers.get("x-rewrite-url") or self.path).lower()
        parsed_path = urllib.parse.urlparse(raw_path).path.lower()

        # On Vercel every request is rewritten to /api/index.py; the rewrite
        # injects ?__vercel_path=<original path> (captured WITHOUT the leading
        # slash), so recover the real path here.
        if qs_all.get("__vercel_path"):
            p = urllib.parse.urlparse(qs_all["__vercel_path"][0]).path.lower()
            if not p.startswith("/"):
                p = "/" + p
            parsed_path = p

        if parsed_path == "/static/styles.css" or self.path.lower().endswith("/static/styles.css"):
            self._send(STYLES_CSS, ctype="text/css")
            return

        if parsed_path == "/static/app.js" or self.path.lower().endswith("/static/app.js"):
            self._send(APP_JS, ctype="application/javascript")
            return

        for sp in config.SENSITIVE_PATHS:
            if sp in parsed_path or sp.lstrip("/") in parsed_path or sp in self.path.lower():
                self.send_error(404, "404 Not Found - Resource Restricted")
                return
        self._send(render_page(target=""))

    def do_POST(self):
        if not self._validate_origin():
            self._send(render_page(results="<p style='color:#ef4444'>Invalid origin or unauthorized cross-site request.</p>"), code=403)
            return

        if self._rate_limited():
            self._send("429 Too Many Requests - rate limit reached. Please wait a minute before scanning again.",
                       ctype="text/plain", code=429)
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "ignore")
        ctype = self.headers.get("Content-Type", "").lower()
        if "application/json" in ctype:
            try:
                form = json.loads(raw) if raw.strip() else {}
            except Exception:
                form = {}
        else:
            form = dict(urllib.parse.parse_qsl(raw))

        # CSRF validation (CWE-352): validate serverless rolling token
        token = form.get("_token", "") or self.headers.get("X-CSRF-Token", "") or self.headers.get("x-csrf-token", "")
        if not validate_csrf_token(token):
            self._send(render_page(results="<p style='color:#ef4444'>Missing or invalid CSRF token. Reload the page and try again.</p>"), code=403)
            return

        # Local-only endpoints: hardening rewrites this app's own source files
        # (webui.py / vercel.json) and /fix-demo hardens the bundled demo server
        # on 127.0.0.1. These must never run on the deployed Vercel instance
        # (read-only FS, and they only make sense on the user's own machine).
        if DEPLOYED and ("fix-demo" in self.path or "self-harden" in self.path):
            self._send(render_page(results="<p style='color:#ef4444'>This endpoint is local-only and is disabled in the deployed instance.</p>"), code=403)
            return

        if "fix-demo" in self.path:
            try:
                apply_demo_fix()
            except Exception as e:
                self._send(render_page(results=f"<div class='card'><p style='color:#ef4444'>Could not write demo fix state (read-only filesystem): {html.escape(str(e))}</p></div>"), code=500)
                return
            en = run_scan(DEMO_URL, crawl=True)
            msg = ('<div class="card" style="border-left: 4px solid var(--sev-info); background: rgba(16, 185, 129, 0.1);">'
                   '<b style="color:var(--sev-info)">Demo site hardened and re-scanned!</b> '
                   'Remaining flags below are updated.</div>')
            self._send(render_page(results=msg + render_results(en, DEMO_URL), target=DEMO_URL))
            return

        if "self-harden" in self.path or form.get("action") == "self-harden":
            import websec_auditor.selfharden as sh
            before = sh.audit_state()
            summary = sh.apply_hardening()
            after = sh.verify_state()
            report = sh.render_report(before, summary, after)
            self._send(render_page(results=report, target=""))
            return

        if "code-review" in self.path:
            code = form.get("code", "")[:200000]
            filename = form.get("filename", "").strip()[:200] or "<paste>"
            if not code.strip():
                self._send(render_page(results="<div class='card'><p>Please paste source code to review.</p></div>"))
                return
            try:
                from websec_auditor import codereview
                findings = codereview.review_text(code, filename)
                en = analyze(_findings_to_result(findings, f"code review: {filename}"))
                res_html = render_results(en, f"Code Review: {filename}")
                if not findings:
                    res_html = ("<div class='card status-banner status-secure'>"
                                "<div class='status-icon'>\u2713</div><div><h3>No code-review patterns matched</h3>"
                                "<p>The pasted snippet did not trigger any KB-grounded static code-review rule.</p></div></div>")
            except Exception as e:
                res_html = f"<div class='card'><p>Code review error: {html.escape(str(e))}</p></div>"
            self._send(render_page(results=res_html, target=f"Code Review: {filename}"))
            return

        if "deps-scan" in self.path:
            manifest = form.get("manifest", "")[:200000]
            filename = form.get("filename", "").strip()[:200] or "requirements.txt"
            if not manifest.strip():
                self._send(render_page(results="<div class='card'><p>Please paste a dependency manifest to scan.</p></div>"))
                return
            try:
                from websec_auditor import dependscan
                findings = dependscan.scan_text(manifest, filename)
                en = analyze(_findings_to_result(findings, f"dependency scan: {filename}"))
                res_html = render_results(en, f"Dependency Scan: {filename}")
                if not findings:
                    res_html = ("<div class='card status-banner status-secure'>"
                                "<div class='status-icon'>\u2713</div><div><h3>No known-vulnerable dependencies matched</h3>"
                                "<p>No advisory in the local seed matched the pasted manifest. The seed is a curated subset "
                                "of high-profile CVEs; run <code>websec_cli.py depscan</code> on a full lockfile for a deeper check.</p></div></div>")
            except Exception as e:
                res_html = f"<div class='card'><p>Dependency scan error: {html.escape(str(e))}</p></div>"
            self._send(render_page(results=res_html, target=f"Dependency Scan: {filename}"))
            return

        if "download-tests" in self.path or form.get("action") == "download-tests":
            target = (form.get("target") or STORE.get("target") or "").strip()
            if not STORE.get("last"):
                if not target:
                    self._send(render_page(results="<div class='card'><p>Run a scan first - "
                                                   "test generation needs the scan's entry points and findings.</p></div>"))
                    return
                run_scan(target)
            res = STORE.get("result")
            from websec_auditor import testgen
            artifacts = testgen.generate(target, findings=res, enriched=STORE.get("last") or [])
            text = testgen.bundle_text(artifacts)
            self._send(text, ctype="text/plain",
                       extra={"Content-Disposition": 'attachment; filename="websec-tests.txt"'})
            return

        if "download-fix" in self.path or form.get("action") == "download-fix":
            target = form.get("target", "").strip()
            if not STORE.get("last") or STORE.get("target") != target:
                run_scan(target)
            en = STORE["last"]
            bundle = build_bundle(en)
            text = (f"# websec-auditor remediation bundle for {target}\n\n"
                    + "\n\n".join(f"## {k}\n{bundle[k]}" for k in
                                  ("nginx", "apache", "flask", "express"))
                    + "\n\n## Notes\n" + "\n".join("- " + n for n in bundle["notes"]))
            self._send(text, ctype="text/plain",
                       extra={"Content-Disposition": 'attachment; filename="websec-fix.txt"'})
            return

        if (self.path.startswith("/scan") or "target" in form) and form.get("action") != "download-fix":
            target = form.get("target", "").strip()
            crawl = form.get("crawl") == "1"
            cookie = form.get("cookie", "").strip()
            custom_header = form.get("custom_header", "").strip()
            
            custom_headers = {}
            if cookie:
                custom_headers["Cookie"] = cookie
            if custom_header and ":" in custom_header:
                k, v = custom_header.split(":", 1)
                custom_headers[k.strip()] = v.strip()
                
            if not target:
                self._send(render_page(results="<div class='card'><p>Please enter a target URL.</p></div>", cookie=cookie, header=custom_header))
                return
            if not self._looks_like_url(target):
                hint = ("<div class='card' style='border-left: 4px solid var(--sev-high);'>"
                        "<p><b>The value entered does not look like a web address.</b> "
                        "Enter only the site's URL, e.g. <code>https://www.example.com/page</code>. "
                        "It looks like report text or an error message may have been pasted into the box.</p></div>")
                self._send(render_page(results=hint, target="", cookie=cookie, header=custom_header))
                return
            try:
                en = run_scan(target, crawl=crawl, custom_headers=custom_headers)
                res_html = render_results(en, target)
            except Exception as e:
                res_html = f"<div class='card' style='border-left: 4px solid var(--sev-high);'><p>Scan error: {html.escape(str(e))}</p></div>"
            
            self._send(render_page(results=res_html, target=target, cookie=cookie, header=custom_header))
            return

        self._send(render_page())

    def log_message(self, *a):
        pass


def serve(port=8000):
    print(f"websec-auditor UI  ->  http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8000)
