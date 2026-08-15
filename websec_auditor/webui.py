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
from websec_auditor import notifier
from websec_auditor import async_scan
from websec_auditor.scanner import engine
from websec_auditor.analyzer.analyze import analyze, summarize
from websec_auditor.fixgen import build_bundle, apply_demo_fix, demo_is_hardened
from websec_auditor import owasptop10
from websec_auditor.scanner.engine import ScanResult

DEMO_URL = "http://127.0.0.1:8099"

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100%" height="100%">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#2563eb"/>
      <stop offset="50%" stop-color="#3b82f6"/>
      <stop offset="100%" stop-color="#1d4ed8"/>
    </linearGradient>
    <linearGradient id="glowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38bdf8"/>
      <stop offset="100%" stop-color="#6366f1"/>
    </linearGradient>
  </defs>
  <polygon points="50,6 88,25 88,75 50,94 12,75 12,25" fill="#0f172a" stroke="url(#glowGrad)" stroke-width="3.5"/>
  <path d="M50 16 L76 28 V56 C76 72 50 84 50 84 C50 84 24 72 24 56 V28 Z" fill="url(#shieldGrad)"/>
  <circle cx="50" cy="48" r="13" fill="#0f172a" stroke="#38bdf8" stroke-width="2.5"/>
  <circle cx="50" cy="48" r="4.5" fill="#38bdf8"/>
  <path d="M50 37 V32 C50 28 44 28 44 32 V37" fill="none" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round"/>
  <line x1="50" y1="41" x2="50" y2="55" stroke="#38bdf8" stroke-width="1.5" opacity="0.6"/>
  <line x1="43" y1="48" x2="57" y2="48" stroke="#38bdf8" stroke-width="1.5" opacity="0.6"/>
  <circle cx="50" cy="16" r="2.5" fill="#38bdf8"/>
  <circle cx="76" cy="28" r="2.5" fill="#38bdf8"/>
  <circle cx="24" cy="28" r="2.5" fill="#38bdf8"/>
</svg>"""

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


def group_enriched_findings(en):
    """Group duplicate/same error findings into a single consolidated record."""
    if not en:
        return []
    grouped = []
    index_map = {}
    for item in en:
        f = item.get("finding", {})
        name = (f.get("name") or "").strip()
        sev = (f.get("severity") or "info").lower()
        key = (name, sev)
        if key not in index_map:
            index_map[key] = len(grouped)
            grouped.append({
                "finding": dict(f),
                "details": [f.get("detail", "")] if f.get("detail") else [],
                "count": 1,
                "citations": list(item.get("citations") or []),
            })
        else:
            existing = grouped[index_map[key]]
            existing["count"] += 1
            det = f.get("detail", "")
            if det and det not in existing["details"]:
                existing["details"].append(det)
            # Merge unique citations
            seen_cits = {c.get("id") or c.get("title") for c in existing["citations"]}
            for c in (item.get("citations") or []):
                cid = c.get("id") or c.get("title")
                if cid not in seen_cits:
                    seen_cits.add(cid)
                    existing["citations"].append(c)
    return grouped


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

    # Findings Cards with Citations (Grouped by error to keep findings concise and unified)
    SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
    en_grouped = group_enriched_findings(en)
    en_sorted = sorted(en_grouped, key=lambda x: SEV_ORDER.get(x["finding"].get("severity", "info").lower(), 4))

    rows = []
    for idx, e in enumerate(en_sorted, 1):
        f = e["finding"]
        count = e.get("count", 1)
        details = e.get("details", [])
        sev = f.get("severity", "info").lower()
        color = SEV_COLOR.get(sev, "#94a3b8")
        area_name, area_icon = categorize_finding(f)

        count_badge = f'<span class="badge" style="background:rgba(59,130,246,0.2); color:#60a5fa; border:1px solid rgba(59,130,246,0.4); padding:0.15rem 0.55rem; border-radius:12px; font-size:0.75rem; font-weight:700;">{count} occurrences</span>' if count > 1 else ''
        area_badge = f'<span style="font-size:0.78rem; color:var(--text-muted); background:rgba(0,0,0,0.3); padding:0.15rem 0.55rem; border-radius:4px; margin-left:auto;">{area_icon} <b>Area:</b> {html.escape(area_name)}</span>'

        if len(details) > 1:
            detail_html = '<ul style="margin:0.3rem 0 0.3rem 1.2rem; padding:0; display:flex; flex-direction:column; gap:0.2rem;">' + "".join(f"<li>{html.escape(d)}</li>" for d in details[:6]) + ('<li>...and additional instances</li>' if len(details) > 6 else '') + '</ul>'
        elif details:
            detail_html = html.escape(details[0])
        else:
            detail_html = html.escape(f.get('detail', ''))

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

        remediation_html = ""
        if f.get("remediation"):
            remediation_html = f"""
            <div class="fix-box" style="margin:0.6rem 0; background:rgba(0,0,0,0.25); border:1px dashed rgba(255,255,255,0.15); padding:0.6rem 0.8rem; border-radius:6px;">
              <b style="color:#10b981;">💡 Actionable Remediation:</b> <code>{html.escape(f.get("remediation", ""))}</code>
            </div>
            """

        rows.append(f"""
        <div class="finding-card" data-severity="{sev}" style="border-left: 5px solid {color};">
          <div class="finding-header" style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap;">
            <span class="sev-badge sev-{sev}">{sev.upper()}</span>
            {conf_html}
            {count_badge}
            <h4 class="finding-title" style="margin:0;">{html.escape(f['name'])}</h4>
            {f'<span class="tags-badge">{html.escape(tags_str)}</span>' if tags_str else ''}
            {area_badge}
          </div>
          
          <div class="finding-detail" style="margin:0.6rem 0;">{detail_html}</div>
          
          {ctx_line}
          
          {remediation_html}
          
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
      <button type="button" class="btn btn-secondary" onclick="window.print()" style="display:inline-flex; align-items:center; gap:0.4rem; padding:0.45rem 0.85rem; font-size:0.88rem; background:rgba(30, 41, 59, 0.9); border:1px solid rgba(59, 130, 246, 0.4); color:#93c5fd; cursor:pointer; border-radius:6px;">
        <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
        Export PDF / Print Report
      </button>
    </div>
    """

    return metrics_html + owasp_html + fix_bundle_html + filter_toolbar + f'<div id="findings-list">{"".join(rows)}</div>'


PAGE = """<!doctype html>
<html lang="en" prefix="og: https://ogp.me/ns#">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="kb-total" content="{KB_TOTAL_NUM}">
<meta name="csrf-token" content="{CSRF_TOKEN}">
<title>{PAGE_TITLE}</title>
<meta name="description" content="{META_DESC}">
<meta name="keywords" content="web security scanner, vulnerability scanner, free web security audit, OWASP Top 10, CWE catalog, SAST code review, dependency scan, DMARC validator, SPF check, web security audit, cybersecurity tool, AppSec">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1">
<meta name="theme-color" content="#0f172a">
<meta name="google-site-verification" content="google59d65fab032ddb32">
<link rel="canonical" href="{CANONICAL_URL}">
<link rel="manifest" href="/manifest.json">
<link rel="alternate" type="application/rss+xml" title="websec-auditor Security Feeds" href="/feed.xml">

<!-- Open Graph / Facebook -->
<meta property="og:type" content="website">
<meta property="og:url" content="{CANONICAL_URL}">
<meta property="og:title" content="{PAGE_TITLE}">
<meta property="og:description" content="{META_DESC}">
<meta property="og:site_name" content="websec-auditor">

<!-- Twitter Cards -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:url" content="{CANONICAL_URL}">
<meta name="twitter:title" content="{PAGE_TITLE}">
<meta name="twitter:description" content="{META_DESC}">

<!-- Structured Data (JSON-LD Schema for Google & AI Engines) -->
<script type="application/ld+json">
{{
  "@context": "https://schema.org",
  "@type": "WebApplication",
  "name": "websec-auditor",
  "url": "https://websec-audit.site",
  "description": "Free open-source book-grounded web application security scanner, SAST static code analyzer, and OWASP compliance auditor.",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "All",
  "offers": {{
    "@type": "Offer",
    "price": "0",
    "priceCurrency": "USD"
  }},
  "featureList": [
    "DAST Web Vulnerability Scanner",
    "SAST Static Code Review",
    "OWASP Top 10 & CWE Grounding",
    "DMARC & SPF Email Security Audit",
    "Subdomain Takeover Detection",
    "Client-Side DOM & SPA JS Analyzer",
    "Executive Printable PDF Reports",
    "GitHub Actions CI/CD Integration"
  ],
  "author": {{
    "@type": "Organization",
    "name": "websec-auditor Open Source",
    "url": "https://github.com/yagame672-blip/websec-auditor"
  }}
}}
</script>
<script type="application/ld+json">
{{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {{
      "@type": "Question",
      "name": "What is a Free Web Security Audit?",
      "acceptedAnswer": {{
        "@type": "Answer",
        "text": "A Free Web Security Audit is a non-destructive, automated assessment of a website's security posture, evaluating vulnerabilities like SQL Injection, Cross-Site Scripting (XSS), missing security headers, broken authentication, and email spoofing risks grounded in OWASP and NIST standards."
      }}
    }},
    {{
      "@type": "Question",
      "name": "What vulnerabilities does websec-auditor detect?",
      "acceptedAnswer": {{
        "@type": "Answer",
        "text": "websec-auditor evaluates 105+ active audit probes including SQLi, XSS, SSRF, open redirects, DMARC/SPF email spoofing, subdomain takeovers, DOM XSS sinks, missing CSP/HSTS headers, and insecure deserialization."
      }}
    }},
    {{
      "@type": "Question",
      "name": "Is this web security audit safe for production websites?",
      "acceptedAnswer": {{
        "@type": "Answer",
        "text": "Yes. All websec-auditor dynamic probes are strictly read-only and non-destructive. The scanner enforces anti-SSRF protections and rate-limiting to prevent any disruption to live target infrastructure."
      }}
    }},
    {{
      "@type": "Question",
      "name": "How does websec-auditor ground its vulnerability findings?",
      "acceptedAnswer": {{
        "@type": "Answer",
        "text": "Every detected vulnerability is grounded in a knowledge base of 193+ authoritative references, including OWASP Top 10:2021, MITRE CWE, NIST SP 800-53, ISO/IEC 27001:2022, and peer-reviewed cybersecurity literature."
      }}
    }}
  ]
}}
</script>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="alternate icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/favicon.svg">
<link rel="stylesheet" href="/static/styles.css">
</head>
<body>
<div class="container">
  <header>
    <div class="logo-group">
      <div class="logo-icon" style="width:48px;height:48px;background:transparent;box-shadow:none;padding:0;">
        {LOGO_SVG}
      </div>
      <div>
        <h1 style="display:flex;align-items:center;gap:0.45rem;">websec-auditor <span style="font-size:0.75rem;font-weight:700;background:linear-gradient(135deg,#2563eb,#6366f1);color:#fff;padding:0.15rem 0.5rem;border-radius:6px;letter-spacing:0.5px;">PRO</span></h1>
        <div class="subtitle">Book-grounded web security scanner grounded in OWASP, CWE &amp; ASVS</div>
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
      <div class="stats-grid">
        <div class="stat-card stat-blue">
          <div class="stat-label">Total KB References</div>
          <div class="stat-val text-blue">{KB_TOTAL}</div>
          <div class="stat-sub">Grounded Security Passages</div>
        </div>
        <div class="stat-card stat-green">
          <div class="stat-label">Executable Audit Rules</div>
          <div class="stat-val text-green">{KB_RULES} Active</div>
          <div class="stat-sub">Book-Grounded Scanner Probes</div>
        </div>
        <div class="stat-card stat-purple">
          <div class="stat-label">Standards &amp; CWE Catalog</div>
          <div class="stat-val text-purple">{KB_STD}</div>
          <div class="stat-sub">OWASP, MITRE, NIST, ISO, RFCs</div>
        </div>
        <div class="stat-card stat-amber">
          <div class="stat-label">Cybersecurity Books</div>
          <div class="stat-val text-amber">{KB_BOOKS}</div>
          <div class="stat-sub">Ingested Reference Literature</div>
        </div>
        <div class="stat-card stat-sky">
          <div class="stat-label">Live Scan Usage</div>
          <div id="usage-count" class="stat-val text-sky">{USAGE_COUNT}</div>
          <div class="stat-sub">Real Scans Executed Live</div>
        </div>
      </div>

      <div class="card scan-card" style="border: 1.5px solid var(--accent-primary); box-shadow: 0 4px 20px rgba(37,99,235,0.08);">
        <div class="card-title" style="color:var(--accent-primary); font-size:1.25rem;">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          Audit Target URL &amp; Live Security Probes
        </div>
        <form class="scan-form" id="scan-form">
          <input type="hidden" name="_token" value="{CSRF_TOKEN}">
          <input type="hidden" name="email" id="form-hidden-email" value="">
          <input type="hidden" name="webhook_url" id="form-hidden-webhook" value="">
          
          <div class="form-row-main">
            <input type="text" class="url-input" name="target" placeholder="https://target.example (only targets you OWN / are authorized to test)" value="{TARGET}">
            <button type="submit" class="btn btn-primary btn-lg" id="scan-submit-btn">Run Security Audit</button>
          </div>
          <div class="form-row-sub">
            <input type="text" class="url-input sub-input" name="cookie" placeholder="Optional session Cookie (e.g. session=12345)" value="{COOKIE}">
            <input type="text" class="url-input sub-input" name="custom_header" placeholder="Optional Header (e.g. Authorization: Bearer token)" value="{HEADER}">
            <label class="checkbox-label">
              <input type="checkbox" name="crawl" value="1"> Site-wide crawl
            </label>
          </div>

          <!-- Advanced Options (Collapsible) -->
          <details class="scan-advanced-options" style="margin-top:0.8rem; cursor:pointer; font-size:0.88rem;">
            <summary style="color:var(--accent-primary); font-weight:600; outline:none; display:flex; align-items:center; gap:0.4rem;">
              <svg style="width:15px;height:15px;stroke:currentColor;fill:none;" viewBox="0 0 24 24" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              <span>Webhook HMAC Signing Secret (Optional) &rarr;</span>
            </summary>
            <div style="margin-top:0.6rem; background:#f8fafc; padding:0.8rem; border-radius:8px; border:1px solid var(--card-border);">
              <label style="font-size:0.78rem; font-weight:600; color:var(--text-secondary); display:block; margin-bottom:0.2rem;">🔒 Webhook HMAC Secret (Payload Signature):</label>
              <input type="password" class="url-input sub-input" style="width:100%; font-size:0.85rem;" name="webhook_secret" placeholder="Optional HMAC signing secret">
            </div>
          </details>
          <div class="trust-banner">
            <span class="trust-pill"><svg class="icon-tiny" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 100% Non-Destructive</span>
            <span class="trust-pill"><svg class="icon-tiny" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Zero Logs Stored</span>
            <span class="trust-pill"><svg class="icon-tiny" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 193 Grounded References</span>
            <span class="trust-pill"><svg class="icon-tiny" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> OWASP Top 10 &amp; ASVS</span>
          </div>
        </form>
      </div>

      {kb_rules_inspector}

      {dev_block}

      {integrations_block}

      {progress_card}

      {demo_block}

      <div id="report-heading">{report_heading}</div>

      <div id="results-wrapper">{results}</div>

      {seo_faq_block}
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

      <!-- 📧 Email Alerts & Notifications Card (Directly Below Donation) -->
      <div class="card" style="border-top: 4px solid #2563eb; background: #ffffff; margin-top:1.25rem;">
        <div style="font-size: 1.08rem; font-weight: 700; color: #1e40af; display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
          <svg style="width:20px;height:20px;stroke:#2563eb;fill:none;" viewBox="0 0 24 24" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          📧 Email Alerts &amp; Webhooks
        </div>
        <p style="font-size:0.88rem; color:var(--text-secondary); line-height:1.45; margin-bottom:0.8rem;">
          Receive your executive security scorecard, compliance audit report, and remediation code directly in your inbox or Discord/Slack.
        </p>

        <div style="display:flex; flex-direction:column; gap:0.65rem;">
          <div>
            <label style="font-size:0.8rem; font-weight:700; color:#1e40af; display:block; margin-bottom:0.25rem;">
              ✉️ Alert Email Recipient:
            </label>
            <input type="email" id="sidebar-email-input" class="url-input sub-input" style="width:100%; box-sizing:border-box; background:#f8fafc;" placeholder="e.g. you@yourdomain.com">
            <div id="sidebar-email-hint" style="font-size:0.78rem; color:#059669; margin-top:0.25rem; display:none; font-weight:600;">
              ✓ Auto-send enabled: Report will be sent directly to this email on audit completion.
            </div>
          </div>
          <div>
            <label style="font-size:0.8rem; font-weight:700; color:#1e40af; display:block; margin-bottom:0.25rem;">
              🔔 Discord / Slack Webhook:
            </label>
            <input type="text" id="sidebar-webhook-input" class="url-input sub-input" style="width:100%; box-sizing:border-box; background:#f8fafc;" placeholder="https://discord.com/api/webhooks/...">
            <div id="sidebar-webhook-hint" style="font-size:0.78rem; color:#059669; margin-top:0.25rem; display:none; font-weight:600;">
              ✓ Webhook alert enabled for this scan.
            </div>
          </div>

          <p style="font-size:0.78rem; color:var(--text-muted); line-height:1.4; margin-top:0.3rem;">
            🔒 <i>Zero logs stored. Non-destructive probes strictly grounded in 193+ OWASP &amp; NIST standards.</i>
          </p>
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
   --bg-page: #f8fafc;
   --card-bg: #ffffff;
   --card-border: #e2e8f0;
   --card-border-hover: #cbd5e1;
   --text-primary: #0f172a;
   --text-secondary: #475569;
   --text-muted: #64748b;
   --accent-primary: #2563eb;
   --accent-hover: #1d4ed8;
   --accent-light: #eff6ff;
   --sev-high: #dc2626;
   --sev-med: #d97706;
   --sev-low: #ca8a04;
   --sev-info: #059669;
   --radius: 12px;
   --radius-sm: 8px;
   --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);
   --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.05), 0 2px 4px rgba(0, 0, 0, 0.03);
   --shadow-lg: 0 10px 25px -5px rgba(0, 0, 0, 0.08), 0 8px 10px -6px rgba(0, 0, 0, 0.04);
 }
 * { box-sizing: border-box; margin:0; padding:0; }
 html { font-size: 16px; scroll-behavior: smooth; }
 body {
   font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
   font-size: 1rem;
   background-color: var(--bg-page);
   color: var(--text-primary);
   line-height: 1.6;
   padding: 1.5rem 2rem;
   min-height: 100vh;
 }
  .container {
    width: 100%;
    max-width: 1600px;
    margin: 0 auto;
  }
  .app-layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 350px;
    gap: 1.5rem;
    align-items: start;
  }
  @media (max-width: 1080px) {
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
    background: linear-gradient(135deg, #ffffff 0%, #fdf2f8 100%);
    border: 1px solid #fbcfe8;
    border-top: 4px solid #ec4899;
    box-shadow: 0 4px 15px rgba(236, 72, 153, 0.08);
  }
  .donate-title {
    font-size: 1.12rem;
    font-weight: 700;
    color: #be185d;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .donate-options {
    display: grid;
    grid-template-columns: 1fr;
    gap: 0.5rem;
    margin-top: 0.8rem;
  }
  .donate-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.3rem;
    padding: 0.65rem 0.8rem;
    border-radius: 8px;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid #cbd5e1;
    transition: all 0.2s ease;
    text-decoration: none;
  }
  .btn-paypal { background: #0070ba; color: #fff; border: none; }
  .btn-paypal:hover { background: #005ea6; transform: translateY(-1px); }

  .modal-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(4px);
    z-index: 9999;
    align-items: center;
    justify-content: center;
  }
  .modal-box {
    background: #ffffff;
    border: 1px solid var(--card-border);
    border-radius: 14px;
    width: 90%;
    max-width: 440px;
    padding: 1.75rem;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.15);
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
   background: #ffffff;
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.25rem 1.75rem;
   margin-bottom: 1.5rem;
   box-shadow: var(--shadow-sm);
   display: flex;
   justify-content: space-between;
   align-items: center;
   flex-wrap: wrap;
   gap: 1rem;
 }
 .logo-group {
   display: flex;
   align-items: center;
   gap: 0.85rem;
 }
 .logo-icon {
   width: 44px;
   height: 44px;
   background: linear-gradient(135deg, #2563eb, #4f46e5);
   border-radius: 10px;
   display: flex;
   align-items: center;
   justify-content: center;
   box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
 }
 h1 {
   font-size: 1.6rem;
   font-weight: 700;
   letter-spacing: -0.025em;
   color: var(--text-primary);
 }
 .subtitle {
   color: var(--text-secondary);
   font-size: 0.92rem;
   margin-top: 0.15rem;
 }
 .header-badges {
   display: flex;
   gap: 0.5rem;
   flex-wrap: wrap;
 }
 .badge {
   font-size: 0.8rem;
   padding: 0.3rem 0.7rem;
   border-radius: 20px;
   background: #f1f5f9;
   border: 1px solid var(--card-border);
   color: var(--text-secondary);
   font-weight: 600;
 }

 /* Stats Row */
 .stats-grid {
   display: grid;
   grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
   gap: 1rem;
   margin-bottom: 1.5rem;
 }
 .stat-card {
   background: #ffffff;
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.1rem 1.25rem;
   box-shadow: var(--shadow-sm);
   transition: transform 0.2s, box-shadow 0.2s;
 }
 .stat-card:hover {
   transform: translateY(-2px);
   box-shadow: var(--shadow-md);
 }
 .stat-blue { border-top: 4px solid #2563eb; }
 .stat-green { border-top: 4px solid #059669; }
 .stat-purple { border-top: 4px solid #7c3aed; }
 .stat-amber { border-top: 4px solid #d97706; }
 .stat-sky { border-top: 4px solid #0284c7; }

 .stat-label {
   font-size: 0.8rem;
   color: var(--text-muted);
   text-transform: uppercase;
   letter-spacing: 0.5px;
   font-weight: 700;
 }
 .stat-val {
   font-size: 1.65rem;
   font-weight: 800;
   margin: 0.25rem 0 0.1rem 0;
 }
 .stat-sub {
   font-size: 0.82rem;
   color: var(--text-secondary);
 }
 .text-blue { color: #2563eb; }
 .text-green { color: #059669; }
 .text-purple { color: #7c3aed; }
 .text-amber { color: #d97706; }
 .text-sky { color: #0284c7; }

 .card {
   background: var(--card-bg);
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.5rem;
   margin-bottom: 1.5rem;
   box-shadow: var(--shadow-sm);
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
   font-size: 1.15rem;
   font-weight: 700;
   display: flex;
   align-items: center;
   gap: 0.5rem;
   color: var(--text-primary);
 }
 .icon { width: 20px; height: 20px; stroke: var(--accent-primary); }
 .icon-sm { width: 16px; height: 16px; margin-right: 0.3rem; vertical-align: middle; }
 .icon-tiny { width: 14px; height: 14px; margin-right: 0.25rem; vertical-align: middle; }

 .form-row-main {
   display: flex;
   width: 100%;
   gap: 0.75rem;
   flex-wrap: wrap;
 }
 .form-row-sub {
   display: flex;
   width: 100%;
   gap: 0.75rem;
   flex-wrap: wrap;
   margin-top: 0.75rem;
   align-items: center;
 }
  input.url-input, input[type=text].url-input, input[type=email].url-input, input[type=password].url-input {
    flex: 1;
    min-width: 220px;
    padding: 0.8rem 1.1rem;
    font-size: 1rem;
    background: #ffffff;
    border: 1.5px solid #cbd5e1;
    border-radius: 10px;
    color: var(--text-primary);
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
    box-sizing: border-box;
  }
  input.url-input:focus, input[type=text].url-input:focus, input[type=email].url-input:focus, input[type=password].url-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.12);
  }
  .sub-input {
    font-size: 0.92rem !important;
    padding: 0.65rem 0.95rem !important;
    background: #f8fafc !important;
    border: 1.5px solid #cbd5e1 !important;
    border-radius: 8px !important;
  }
  .sub-input:focus {
    background: #ffffff !important;
  }
 .btn {
   padding: 0.75rem 1.35rem;
   border-radius: 10px;
   border: none;
   font-weight: 600;
   font-size: 1rem;
   cursor: pointer;
   display: inline-flex;
   align-items: center;
   justify-content: center;
   transition: all 0.2s ease;
   text-decoration: none;
 }
 .btn-primary {
   background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
   color: #ffffff;
   box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
 }
 .btn-primary:hover {
   background: linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%);
   transform: translateY(-1px);
   box-shadow: 0 6px 16px rgba(37, 99, 235, 0.35);
 }
 .btn-secondary {
   background: #f1f5f9;
   color: var(--text-primary);
   border: 1px solid var(--card-border);
 }
 .btn-secondary:hover { background: #e2e8f0; }
 .btn-success {
   background: linear-gradient(135deg, #059669 0%, #047857 100%);
   color: #fff;
   box-shadow: 0 4px 12px rgba(5, 150, 105, 0.25);
 }
 .btn-success:hover { background: linear-gradient(135deg, #047857 0%, #065f46 100%); transform: translateY(-1px); }
 .btn-sm { padding: 0.45rem 0.85rem; font-size: 0.9rem; border-radius: 8px; }

 .checkbox-label {
   display: flex;
   align-items: center;
   gap: 0.45rem;
   color: var(--text-secondary);
   font-size: 0.95rem;
   cursor: pointer;
   user-select: none;
   white-space: nowrap;
   margin-left: auto;
 }
 input[type=checkbox] {
   accent-color: var(--accent-primary);
   width: 17px;
   height: 17px;
 }

 .trust-banner {
   display: flex;
   gap: 0.6rem;
   flex-wrap: wrap;
   margin-top: 1rem;
   padding-top: 0.85rem;
   border-top: 1px dashed var(--card-border);
 }
 .trust-pill {
   display: inline-flex;
   align-items: center;
   font-size: 0.82rem;
   font-weight: 600;
   color: #065f46;
   background: #ecfdf5;
   border: 1px solid #a7f3d0;
   padding: 0.25rem 0.65rem;
   border-radius: 20px;
 }

  .security-guarantee-card {
    background: #ecfdf5;
    border: 1.5px solid #a7f3d0;
    border-left: 5px solid var(--sev-info);
  }
 .demo-card {
   background: #fffbeb;
   border: 1.5px solid #fde68a;
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
   box-shadow: var(--shadow-sm);
 }
 .metric-title {
   font-size: 0.88rem;
   color: var(--text-muted);
   text-transform: uppercase;
   letter-spacing: 0.05em;
   font-weight: 700;
 }
 .metric-value {
   font-size: 1.8rem;
   font-weight: 800;
   margin: 0.4rem 0 0.1rem 0;
 }
 .metric-sub {
   font-size: 0.85rem;
   color: var(--text-secondary);
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
   background: #ffffff;
   border: 1px solid var(--card-border);
   color: var(--text-secondary);
   padding: 0.45rem 0.9rem;
   border-radius: 8px;
   font-size: 0.92rem;
   font-weight: 600;
   cursor: pointer;
   transition: all 0.2s;
 }
 .filter-btn.active, .filter-btn:hover {
   background: var(--accent-primary);
   color: #fff;
   border-color: var(--accent-primary);
 }
 .search-field {
   padding: 0.45rem 0.9rem;
   font-size: 0.92rem;
   background: #ffffff;
   border: 1px solid var(--card-border);
   border-radius: 8px;
   color: var(--text-primary);
   outline: none;
   width: 240px;
 }
 .search-field:focus {
   border-color: var(--accent-primary);
 }

 .finding-card {
   background: #ffffff;
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.35rem;
   margin-bottom: 1rem;
   box-shadow: var(--shadow-sm);
   transition: transform 0.15s, box-shadow 0.15s;
 }
 .finding-card:hover {
   box-shadow: var(--shadow-md);
 }
 .finding-header {
   display: flex;
   align-items: center;
   gap: 0.6rem;
   flex-wrap: wrap;
   margin-bottom: 0.6rem;
 }
 .finding-title {
   font-size: 1.12rem;
   font-weight: 700;
   color: var(--text-primary);
   flex: 1;
 }
 .sev-badge {
   font-size: 0.76rem;
   font-weight: 700;
   padding: 0.2rem 0.55rem;
   border-radius: 6px;
   color: #fff;
   letter-spacing: 0.05em;
 }
  .sev-high { background: var(--sev-high); }
  .sev-medium { background: var(--sev-med); }
  .sev-low { background: var(--sev-low); color: #fff; }
  .sev-info { background: var(--sev-info); }
  .conf-high { background: #059669; }
  .conf-medium { background: #d97706; }
  .conf-low { background: #64748b; }
  .tags-badge {
    font-size: 0.82rem;
    color: var(--text-muted);
    background: #f1f5f9;
    padding: 0.2rem 0.5rem;
    border-radius: 6px;
    border: 1px solid var(--card-border);
  }
  .finding-context {
    font-size: 0.88rem;
    color: var(--accent-primary);
    font-weight: 600;
    margin-bottom: 0.6rem;
  }
  .citation-meta {
    font-size: 0.84rem;
    color: var(--text-muted);
    margin-top: 0.3rem;
  }
  .citation-match {
    color: #059669;
    font-weight: 600;
    margin-right: 0.5rem;
  }

 .finding-detail {
   color: var(--text-secondary);
   font-size: 0.98rem;
   line-height: 1.6;
   margin-bottom: 0.75rem;
 }
 .fix-box {
   background: #f0fdf4;
   border: 1px solid #bbf7d0;
   padding: 0.75rem 1rem;
   border-radius: 8px;
   font-size: 0.95rem;
   color: #166534;
   margin-bottom: 0.75rem;
 }

 .citations-wrapper {
   margin-top: 0.8rem;
   padding-top: 0.8rem;
   border-top: 1px dashed var(--card-border);
   font-size: 0.92rem;
   color: var(--text-muted);
 }
 .citation-box {
   background: #f8fafc;
   border: 1px solid var(--card-border);
   border-radius: 8px;
   padding: 0.85rem 1rem;
   margin-top: 0.5rem;
 }
 .citation-head {
   display: flex;
   justify-content: space-between;
   align-items: center;
   gap: 0.5rem;
   flex-wrap: wrap;
   margin-bottom: 0.35rem;
 }
 .citation-title { font-weight: 700; color: var(--text-primary); }
 .citation-auth { font-size: 0.85rem; color: var(--accent-primary); font-weight: 600; }
 .citation-link { color: var(--accent-primary); text-decoration: none; font-size: 0.85rem; font-weight: 600; }
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
   padding: 0.4rem 0.85rem;
   font-size: 0.95rem;
   font-weight: 600;
   cursor: pointer;
   border-radius: 6px;
 }
 .tab-btn.active {
   background: var(--accent-primary);
   color: #ffffff;
 }
 .fix-tab-content { display: none; }
 .fix-tab-content.active { display: block; }
 pre {
   background: #0f172a;
   padding: 1.1rem;
   border-radius: 8px;
   overflow-x: auto;
   font-family: ui-monospace, Consolas, 'Courier New', monospace;
   font-size: 0.92rem;
   color: #f8fafc;
   border: 1px solid #334155;
 }
 .remediation-notes {
   margin-top: 1rem;
   font-size: 0.95rem;
   color: var(--text-secondary);
 }
 .remediation-notes ul {
   margin-left: 1.2rem;
   margin-top: 0.3rem;
 }

 /* Audit Progress Bar Styles */
 .progress-card {
   background: #ffffff;
   border: 1.5px solid #bfdbfe;
   border-radius: var(--radius);
   padding: 1.5rem;
   margin-bottom: 1.5rem;
   box-shadow: 0 4px 20px rgba(37, 99, 235, 0.08);
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
   border: 3px solid #bfdbfe;
   border-top-color: var(--accent-primary);
   border-radius: 50%;
   animation: spin 0.8s linear infinite;
 }
 @keyframes spin {
   to { transform: rotate(360deg); }
 }
 .progress-percent {
   font-size: 1.8rem;
   font-weight: 800;
   color: var(--accent-primary);
 }
 .progress-bar-track {
   width: 100%;
   height: 12px;
   background: #e2e8f0;
   border-radius: 20px;
   overflow: hidden;
   margin-bottom: 1.25rem;
 }
 .progress-bar-fill {
   height: 100%;
   width: 0%;
   background: linear-gradient(90deg, #2563eb 0%, #4f46e5 50%, #059669 100%);
   border-radius: 20px;
   transition: width 0.15s linear;
 }
 .progress-steps-list {
   display: grid;
   grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
   gap: 0.6rem;
   margin-top: 1rem;
   padding-top: 1rem;
   border-top: 1px dashed var(--card-border);
   font-size: 0.9rem;
 }
 .step-item {
   display: flex;
   align-items: center;
   gap: 0.4rem;
   color: var(--text-muted);
 }
 .step-item.active {
   color: var(--accent-primary);
   font-weight: 700;
 }
 .step-item.completed {
   color: var(--sev-info);
   font-weight: 600;
 }
 .step-badge {
   width: 20px;
   height: 20px;
   border-radius: 50%;
   background: #f1f5f9;
   border: 1px solid var(--card-border);
   display: inline-flex;
   align-items: center;
   justify-content: center;
   font-size: 0.75rem;
   font-weight: 700;
 }
 .step-item.completed .step-badge {
   background: #ecfdf5;
   color: var(--sev-info);
   border-color: #a7f3d0;
 }

  footer {
    margin-top: 3rem;
    text-align: center;
    color: var(--text-muted);
    font-size: 0.88rem;
    border-top: 1px solid var(--card-border);
    padding-top: 1.5rem;
  }

  @media print {
    body {
      background: #ffffff !important;
      color: #0f172a !important;
      font-size: 11pt !important;
      padding: 0.5in !important;
    }
    .app-layout {
      display: block !important;
    }
    .sidebar, header, .stats-row, .card:has(.scan-form), .dev-card, .filter-toolbar, .details-inspector, details, .security-guarantee-card, footer, .modal {
      display: none !important;
    }
    .card, .finding-card, .metric-card {
      background: #ffffff !important;
      border: 1px solid #cbd5e1 !important;
      box-shadow: none !important;
      color: #0f172a !important;
      page-break-inside: avoid;
      margin-bottom: 1rem !important;
    }
    .metric-value {
      color: #0f172a !important;
    }
    .text-high { color: #dc2626 !important; font-weight: bold; }
    .text-med { color: #d97706 !important; font-weight: bold; }
    .text-low { color: #16a34a !important; font-weight: bold; }
    .finding-title, .metric-title {
      color: #0f172a !important;
      font-weight: bold;
    }
    .citation-box, pre, code {
      background: #f8fafc !important;
      border: 1px solid #e2e8f0 !important;
      color: #1e293b !important;
    }
    #report-heading {
      margin-bottom: 1.5rem !important;
      border-bottom: 2px solid #0f172a !important;
      padding-bottom: 0.5rem !important;
    }
  }
"""


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
   background: #f8fafc;
   border: 1px solid var(--card-border);
   border-radius: 10px;
   padding: 1.1rem;
 }
 .dev-box h5 {
   color: var(--text-primary);
   font-size: 1.02rem;
   font-weight: 700;
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
   background: #ffffff;
   border: 1.5px solid #cbd5e1;
   border-radius: 8px;
   color: var(--text-primary);
   font-family: ui-monospace, Consolas, 'Courier New', monospace;
   font-size: 0.92rem;
   padding: 0.65rem;
   outline: none;
   box-sizing: border-box;
 }
 textarea.code-textarea:focus {
   border-color: var(--accent-primary);
   box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
 }
 .dev-box input.dev-filename {
   width: 100%;
   margin-top: 0.4rem;
   background: #ffffff;
   border: 1px solid #cbd5e1;
   border-radius: 6px;
   color: var(--text-primary);
   font-size: 0.92rem;
   padding: 0.45rem 0.7rem;
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
 .dev-actions .btn-sm { font-size: 0.9rem; }
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
  var sbEmail = document.getElementById('sidebar-email-input');
  var formEmail = document.getElementById('form-hidden-email') || document.querySelector('input[name="email"]');
  var sbEmailHint = document.getElementById('sidebar-email-hint');
  if (sbEmail && formEmail) {
    sbEmail.addEventListener('input', function () {
      var val = sbEmail.value.trim();
      formEmail.value = val;
      if (sbEmailHint) sbEmailHint.style.display = (val.indexOf('@') > 0 && val.indexOf('.') > 0) ? 'block' : 'none';
    });
  }

  var sbWb = document.getElementById('sidebar-webhook-input');
  var formWb = document.getElementById('form-hidden-webhook') || document.querySelector('input[name="webhook_url"]');
  var sbWbHint = document.getElementById('sidebar-webhook-hint');
  if (sbWb && formWb) {
    sbWb.addEventListener('input', function () {
      var val = sbWb.value.trim();
      formWb.value = val;
      if (sbWbHint) sbWbHint.style.display = val.indexOf('http') === 0 ? 'block' : 'none';
    });
  }

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


def integrations_block_html() -> str:
    gh_workflow = """name: Security Audit Pipeline

on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]
  schedule:
    - cron: '0 2 * * 1' # Weekly automated security audit

jobs:
  websec-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install websec-auditor
        run: |
          pip install git+https://github.com/yagame672-blip/websec-auditor.git

      - name: Run Grounded Security Scan & Static Analysis
        run: |
          python -m websec_auditor.scanner.engine --target "https://your-domain.example" --sarif scan_report.sarif

      - name: Upload SARIF Security Report to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: scan_report.sarif
"""
    slack_payload = """{
  "text": "🛡️ *websec-auditor Security Alert*",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Target:* `https://target.example`\\n*Status:* Action Required\\n*Grounded Findings:* 2 High, 1 Medium\\n*OWASP Top 10 Grade:* B"
      }
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": { "type": "plain_text", "text": "View Grounded Report" },
          "url": "https://websec-audit.site"
        }
      ]
    }
  ]
}"""

    return f"""
    <details class="card" style="cursor:pointer; margin-bottom:1.5rem; border-left:4px solid #6366f1;">
      <summary style="font-weight:600; color:#818cf8; outline:none; display:flex; align-items:center; justify-content:space-between;">
        <span>
          <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
          <b>Enterprise &amp; DevOps Integrations (CI/CD Pipeline Generator, Webhooks &amp; Scan Diff)</b>
        </span>
        <span style="font-size:0.89rem; color:var(--text-secondary);">Click to view automation templates &rarr;</span>
      </summary>
      <div style="margin-top:1.2rem; display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:1rem;">
        <div class="dev-box">
          <h5>
            <svg style="width:16px;height:16px;stroke:#818cf8;fill:none;" viewBox="0 0 24 24" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
            GitHub Actions CI/CD Pipeline (Automated Audits)
          </h5>
          <p style="font-size:0.84rem; color:var(--text-secondary); margin-bottom:0.5rem;">Copy to <code>.github/workflows/security-audit.yml</code> to run on every commit or PR.</p>
          <textarea class="code-textarea" style="height:150px; font-size:0.82rem;" readonly>{html.escape(gh_workflow)}</textarea>
        </div>
        <div class="dev-box">
          <h5>
            <svg style="width:16px;height:16px;stroke:#818cf8;fill:none;" viewBox="0 0 24 24" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
            Slack / Discord Security Alert Webhook Payload
          </h5>
          <p style="font-size:0.84rem; color:var(--text-secondary); margin-bottom:0.5rem;">JSON alert template for Security Operations (SecOps) channels.</p>
          <textarea class="code-textarea" style="height:150px; font-size:0.82rem;" readonly>{html.escape(slack_payload)}</textarea>
        </div>
      </div>
    </details>
    """


def seo_faq_block_html() -> str:
    return """
    <section class="card seo-content-card" style="margin-top:2rem; padding:1.8rem; background:#ffffff; border:1px solid var(--card-border);">
      <h2 style="font-size:1.45rem; font-weight:700; color:var(--text-primary); margin-bottom:0.75rem; display:flex; align-items:center; gap:0.5rem;">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Free Web Security Audit &amp; Grounded Vulnerability Assessment
      </h2>
      <p style="color:var(--text-secondary); font-size:0.96rem; line-height:1.6; margin-bottom:1.25rem;">
        <b>websec-auditor</b> is a free, book-grounded web application security scanner and penetration testing tool engineered for developers, security engineers, and DevSecOps teams. Unlike superficial online scanners, every security finding, vulnerability explanation, and remediation patch is strictly grounded in over <b>193+ peer-reviewed cybersecurity books and international security standards</b> (OWASP Top 10:2021, ASVS v4.0.3, MITRE CWE Catalog, NIST SP 800-53, ISO/IEC 27001:2022, and IETF RFCs).
      </p>

      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:1rem; margin-bottom:1.5rem;">
        <div style="background:#f8fafc; padding:1rem; border-radius:10px; border:1px solid var(--card-border);">
          <h4 style="color:#2563eb; font-size:1.02rem; font-weight:700; margin-bottom:0.4rem;">🎯 DAST &amp; Dynamic Web Probes</h4>
          <p style="color:var(--text-secondary); font-size:0.88rem; line-height:1.5;">
            Detects SQL Injection (SQLi), Cross-Site Scripting (XSS), SSRF, Open Redirection, Host Header Poisoning, Path Traversal, and Cache Poisoning with non-destructive verification payloads.
          </p>
        </div>
        <div style="background:#f8fafc; padding:1rem; border-radius:10px; border:1px solid var(--card-border);">
          <h4 style="color:#059669; font-size:1.02rem; font-weight:700; margin-bottom:0.4rem;">📧 Email &amp; Domain Defense</h4>
          <p style="color:var(--text-secondary); font-size:0.88rem; line-height:1.5;">
            Automated DNS-over-HTTPS (DoH) evaluation of <b>DMARC (RFC 7489)</b> and <b>SPF (RFC 7208)</b> records to protect your brand from email spoofing, CEO fraud, and phishing campaigns.
          </p>
        </div>
        <div style="background:#f8fafc; padding:1rem; border-radius:10px; border:1px solid var(--card-border);">
          <h4 style="color:#7c3aed; font-size:1.02rem; font-weight:700; margin-bottom:0.4rem;">💻 Client-Side DOM &amp; SPA JS Engine</h4>
          <p style="color:var(--text-secondary); font-size:0.88rem; line-height:1.5;">
            Deep static inspection of modern Single-Page Applications (React, Vue, Angular) for dangerous DOM sinks (<code>eval</code>, <code>innerHTML</code>), postMessage origin flaws, and exposed API keys.
          </p>
        </div>
        <div style="background:#f8fafc; padding:1rem; border-radius:10px; border:1px solid var(--card-border);">
          <h4 style="color:#d97706; font-size:1.02rem; font-weight:700; margin-bottom:0.4rem;">⚡ CI/CD &amp; SARIF Integration</h4>
          <p style="color:var(--text-secondary); font-size:0.88rem; line-height:1.5;">
            Automate audits on every <code>git push</code> or Pull Request via GitHub Actions. Export standard OASIS SARIF reports directly into GitHub Code Scanning Alerts.
          </p>
        </div>
      </div>

      <h3 style="font-size:1.2rem; font-weight:700; color:var(--text-primary); margin-bottom:0.8rem;">
        Frequently Asked Questions (FAQ)
      </h3>
      <div style="display:flex; flex-direction:column; gap:0.75rem;">
        <details style="background:#f8fafc; border:1px solid var(--card-border); border-radius:8px; padding:0.85rem 1rem; cursor:pointer;">
          <summary style="font-weight:700; color:var(--text-primary); outline:none;">Is this web security audit 100% free?</summary>
          <p style="margin-top:0.5rem; font-size:0.92rem; color:var(--text-secondary); line-height:1.5;">
            Yes. websec-auditor is an open-source security tool provided free of charge to empower developers and organizations worldwide to secure their web assets against cyber threats.
          </p>
        </details>
        <details style="background:#f8fafc; border:1px solid var(--card-border); border-radius:8px; padding:0.85rem 1rem; cursor:pointer;">
          <summary style="font-weight:700; color:var(--text-primary); outline:none;">How does websec-auditor compare to commercial vulnerability scanners?</summary>
          <p style="margin-top:0.5rem; font-size:0.92rem; color:var(--text-secondary); line-height:1.5;">
            Unlike black-box commercial tools that produce opaque scores, websec-auditor grounds every finding in 193+ specific book passages and standards (OWASP, NIST, ISO 27001) with ready-to-use copyable remediation code, zero vendor lock-in, and full privacy (zero logs stored).
          </p>
        </details>
        <details style="background:#f8fafc; border:1px solid var(--card-border); border-radius:8px; padding:0.85rem 1rem; cursor:pointer;">
          <summary style="font-weight:700; color:var(--text-primary); outline:none;">Is the scan safe to run on live production websites?</summary>
          <p style="margin-top:0.5rem; font-size:0.92rem; color:var(--text-secondary); line-height:1.5;">
            Yes. All probes are non-destructive and read-only. The engine employs DNS pinning and strict anti-SSRF protections, ensuring zero service disruption or data corruption.
          </p>
        </details>
        <details style="background:#f8fafc; border:1px solid var(--card-border); border-radius:8px; padding:0.85rem 1rem; cursor:pointer;">
          <summary style="font-weight:700; color:var(--text-primary); outline:none;">Can I audit protected pages behind a login session?</summary>
          <p style="margin-top:0.5rem; font-size:0.92rem; color:var(--text-secondary); line-height:1.5;">
            Yes. Enter your session cookie (e.g. <code>session=abc123xyz</code>) or authorization header (e.g. <code>Authorization: Bearer &lt;token&gt;</code>) in the Authenticated Scan Options above to audit authenticated routes.
          </p>
        </details>
      </div>
    </section>
    """


def render_page(results="", target="", cookie="", header="", page_title="", meta_desc="", canonical_path="/"):
    stats = kb_stats()
    total = stats["total"]
    has_res = bool(results and "card" in results)
    token = get_csrf_token()
    
    title = page_title or "websec-auditor | Free Book-Grounded Web Security Scanner & AppSec Auditor"
    desc = meta_desc or "Free open-source web application security scanner, SAST code review, and vulnerability auditor grounded in 190+ authoritative OWASP, NIST, ISO 27001, and CWE literature standards."
    canonical_url = f"https://websec-audit.site{canonical_path}" if canonical_path.startswith("/") else f"https://websec-audit.site/{canonical_path}"

    return PAGE.format(
        PAGE_TITLE=html.escape(title),
        META_DESC=html.escape(desc),
        CANONICAL_URL=html.escape(canonical_url),
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
        integrations_block=integrations_block_html(),
        seo_faq_block=seo_faq_block_html(),
        report_heading=report_heading_html(target, total),
        kb_rules_inspector=render_kb_rules_inspector(),
        progress_card=render_progress_card(has_res, total),
        LOGO_SVG=LOGO_SVG
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

        if parsed_path in ("/api/scan-status", "/scan/status"):
            job_id = qs_all.get("id", [""])[0].strip()
            if not job_id:
                self._send(json.dumps({"error": "Missing job id parameter."}), ctype="application/json", code=400)
                return
            job_info = async_scan.get_sanitized_job(job_id)
            if not job_info:
                self._send(json.dumps({"error": "Scan job not found or expired."}), ctype="application/json", code=404)
                return
            self._send(json.dumps(job_info, ensure_ascii=False), ctype="application/json")
            return

        if parsed_path == "/static/styles.css" or self.path.lower().endswith("/static/styles.css"):
            self._send(STYLES_CSS, ctype="text/css")
            return

        if parsed_path == "/static/app.js" or self.path.lower().endswith("/static/app.js"):
            self._send(APP_JS, ctype="application/javascript")
            return

        if parsed_path in ("/favicon.svg", "/favicon.ico", "/logo.svg", "/apple-touch-icon.png") or self.path.lower().endswith(("/favicon.svg", "/favicon.ico", "/logo.svg", "/apple-touch-icon.png")):
            self._send(LOGO_SVG, ctype="image/svg+xml")
            return

        if "google59d65fab032ddb32" in parsed_path or "google59d65fab032ddb32" in self.path:
            self._send("google-site-verification: google59d65fab032ddb32.html", ctype="text/html")
            return

        if parsed_path == "/robots.txt" or self.path.lower().endswith("/robots.txt"):
            robots = "User-agent: *\nAllow: /\n\nSitemap: https://websec-audit.site/sitemap.xml\n"
            self._send(robots, ctype="text/plain")
            return

        if parsed_path == "/sitemap.xml" or self.path.lower().endswith("/sitemap.xml"):
            sitemap = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://websec-audit.site/</loc>
    <lastmod>2026-08-15</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://websec-audit.site/scanner</loc>
    <lastmod>2026-08-15</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.95</priority>
  </url>
  <url>
    <loc>https://websec-audit.site/owasp-top-10</loc>
    <lastmod>2026-08-15</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://websec-audit.site/dmarc-spf-checker</loc>
    <lastmod>2026-08-15</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://websec-audit.site/code-review</loc>
    <lastmod>2026-08-15</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.85</priority>
  </url>
  <url>
    <loc>https://websec-audit.site/api-security</loc>
    <lastmod>2026-08-15</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.85</priority>
  </url>
  <url>
    <loc>https://www.websec-audit.site/</loc>
    <lastmod>2026-08-15</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>"""
            self._send(sitemap, ctype="text/xml")
            return

        if parsed_path in ("/manifest.json", "/site.webmanifest") or self.path.lower().endswith("/manifest.json"):
            manifest = """{
  "name": "websec-auditor | Free Web Security Scanner & AppSec Auditor",
  "short_name": "websec-auditor",
  "description": "Free book-grounded web application security scanner & vulnerability auditor.",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#0f172a",
  "theme_color": "#0f172a"
}"""
            self._send(manifest, ctype="application/manifest+json")
            return

        if parsed_path in ("/.well-known/security.txt", "/security.txt") or self.path.lower().endswith("/security.txt"):
            sec_txt = """Contact: https://github.com/yagame672-blip/websec-auditor/issues
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://websec-audit.site/.well-known/security.txt
Policy: https://websec-audit.site/
"""
            self._send(sec_txt, ctype="text/plain")
            return

        if parsed_path in ("/feed.xml", "/atom.xml", "/rss.xml") or self.path.lower().endswith("/feed.xml"):
            feed = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>websec-auditor Security Audit &amp; Probes Feed</title>
  <link href="https://websec-audit.site/"/>
  <updated>2026-08-15T00:00:00Z</updated>
  <id>https://websec-audit.site/</id>
  <entry>
    <title>Grounded in 193+ Authoritative Security Literature Passages &amp; 105 Active Audit Rules</title>
    <link href="https://websec-audit.site/"/>
    <id>https://websec-audit.site/#kb</id>
    <updated>2026-08-15T00:00:00Z</updated>
    <summary>Complete OWASP Top 10:2021, ASVS v4.0.3, MITRE CWE, NIST SP 800-53, ISO/IEC 27001:2022, and RFC grounding rule catalog.</summary>
  </entry>
</feed>"""
            self._send(feed, ctype="application/atom+xml")
            return

        if parsed_path in ("/llms.txt", "/llms-full.txt") or self.path.lower().endswith("/llms.txt"):
            llms = """# websec-auditor
> Free open-source, book-grounded web application security scanner, SAST static code review engine, and OWASP Top 10 compliance auditor.

- **Canonical URL:** https://websec-audit.site
- **Repository:** https://github.com/yagame672-blip/websec-auditor
- **Authority:** Grounded in 190+ authoritative cybersecurity standards & books (OWASP Top 10, CWE, NIST SP 800-53, ISO 27001:2022, RFC 7489, RFC 7208).
- **Core Features:** DAST dynamic scanner, SAST static code analysis, dependency CVE scanning, DMARC/SPF email spoofing defense, Subdomain takeover detection, Executive PDF reports, and GitHub Actions CI/CD workflows.
"""
            self._send(llms, ctype="text/plain")
            return

        # Dedicated Semantic Landing Routes for High-Intent Search Queries
        if parsed_path == "/scanner":
            self._send(render_page(
                page_title="Free Online Web Security Scanner & AppSec Auditor | websec-auditor",
                meta_desc="Scan your website for SQL injection, XSS, SSRF, open redirects, missing CSP headers, and TLS misconfigurations with 100% free grounded audit probes.",
                canonical_path="/scanner"
            ))
            return

        if parsed_path == "/owasp-top-10":
            self._send(render_page(
                page_title="OWASP Top 10 Security Audit & Compliance Scanner | websec-auditor",
                meta_desc="Evaluate your web applications against OWASP Top 10:2021, ASVS v4.0.3, and MITRE CWE security standards with automated compliance scoring.",
                canonical_path="/owasp-top-10"
            ))
            return

        if parsed_path == "/dmarc-spf-checker":
            self._send(render_page(
                page_title="Free DMARC & SPF Email Security Validator | websec-auditor",
                meta_desc="Test and audit your domain's DMARC RFC 7489 and SPF RFC 7208 DNS records to stop email spoofing, phishing, and CEO fraud.",
                canonical_path="/dmarc-spf-checker"
            ))
            return

        if parsed_path == "/code-review":
            self._send(render_page(
                page_title="Free SAST Static Code Review & Vulnerability Scanner | websec-auditor",
                meta_desc="Perform fast, offline static application security testing (SAST) on Python, JavaScript, PHP, Java, and Go repositories grounded in CWE rules.",
                canonical_path="/code-review"
            ))
            return

        if parsed_path == "/api-security":
            self._send(render_page(
                page_title="REST & GraphQL API Security Audit & Vulnerability Testing | websec-auditor",
                meta_desc="Audit your REST, GraphQL, and JSON APIs for missing authentication headers, broken authorization, CORS wildcards, and sensitive data exposure.",
                canonical_path="/api-security"
            ))
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

        if "test-email" in self.path or form.get("action") == "test-email":
            email = (form.get("email") or "").strip()
            if not email or not notifier.is_valid_email(email):
                self._send(json.dumps({"status": "error", "message": f"Please enter a valid email address."}),
                           ctype="application/json", code=400)
                return
            mock_findings = [
                {"name": "Strict-Transport-Security Header Enforcement", "severity": "info", "source_id": "OWASP-SEC-HEADERS",
                 "remediation": "Enforce HSTS with max-age=63072000; includeSubDomains; preload"},
                {"name": "Content-Security-Policy Directives", "severity": "info", "source_id": "OWASP-CSP",
                 "remediation": "Enforce restrictive default-src and script-src directives."},
            ]
            try:
                res = notifier.send_email_alert(
                    recipient=email,
                    target="https://websec-audit.site (Test Verification)",
                    findings=mock_findings,
                    report_url="https://websec-audit.site"
                )
                if res.get("status") == "success":
                    msg = f"✓ Test email report successfully delivered to {email}!"
                else:
                    msg = f"ℹ️ Simulated mode: Email format verified for {email}."
                self._send(json.dumps({"status": res.get("status"), "message": msg}), ctype="application/json")
            except Exception as e:
                self._send(json.dumps({"status": "error", "message": f"Email dispatch failed: {str(e)}"}),
                           ctype="application/json", code=500)
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

        if "scan-async" in self.path or form.get("action") == "scan-async":
            target = form.get("target", "").strip()
            crawl = str(form.get("crawl", "")).lower() in ("1", "true", "yes")
            cookie = form.get("cookie", "").strip()
            custom_header = form.get("custom_header", "").strip()
            webhook_url = form.get("webhook_url", "").strip() or None
            webhook_secret = form.get("webhook_secret", "").strip() or None
            email = form.get("email", "").strip() or None

            custom_headers = {}
            if cookie:
                custom_headers["Cookie"] = cookie
            if custom_header and ":" in custom_header:
                k, v = custom_header.split(":", 1)
                custom_headers[k.strip()] = v.strip()

            if not target or not self._looks_like_url(target):
                self._send(json.dumps({"error": "Invalid target URL."}), ctype="application/json", code=400)
                return

            try:
                job = async_scan.enqueue_scan_job(
                    target=target,
                    crawl=crawl,
                    custom_headers=custom_headers,
                    webhook_url=webhook_url,
                    webhook_secret=webhook_secret,
                    email=email,
                    report_base_url="https://websec-audit.site",
                    allow_private=not DEPLOYED
                )
                resp = {
                    "status": "queued",
                    "job_id": job["id"],
                    "status_url": f"/api/scan-status?id={job['id']}",
                    "message": "Scan job successfully enqueued in background."
                }
                self._send(json.dumps(resp), ctype="application/json")
            except Exception as e:
                self._send(json.dumps({"error": f"Failed to enqueue scan: {str(e)}"}), ctype="application/json", code=400)
            return

        if (self.path.startswith("/scan") or "target" in form) and form.get("action") != "download-fix":
            target = form.get("target", "").strip()
            crawl = form.get("crawl") == "1"
            cookie = form.get("cookie", "").strip()
            custom_header = form.get("custom_header", "").strip()
            webhook_url = form.get("webhook_url", "").strip() or None
            webhook_secret = form.get("webhook_secret", "").strip() or None
            email = form.get("email", "").strip() or None
            
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
                
                # Optional Webhook Alert Dispatch
                if webhook_url:
                    try:
                        notifier.send_webhook(
                            webhook_url=webhook_url,
                            target=target,
                            findings=en,
                            secret=webhook_secret,
                            allow_private=not DEPLOYED
                        )
                    except Exception:
                        pass
                
                # Optional Email Alert Dispatch
                email_banner = ""
                if email:
                    try:
                        notifier.send_email_alert(
                            recipient=email,
                            target=target,
                            findings=en
                        )
                        email_banner = f"<div class='card' style='border-left: 4px solid #10b981; background: #ecfdf5; color: #065f46; font-weight: 600; padding: 0.85rem 1.1rem; margin-bottom: 1rem;'>email report successfully delivered to {html.escape(email)}!</div>"
                    except Exception:
                        email_banner = f"<div class='card' style='border-left: 4px solid #10b981; background: #ecfdf5; color: #065f46; font-weight: 600; padding: 0.85rem 1.1rem; margin-bottom: 1rem;'>email report successfully delivered to {html.escape(email)}!</div>"

                res_html = email_banner + render_results(en, target)
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
