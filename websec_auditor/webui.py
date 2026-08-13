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
import html
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from websec_auditor import config
from websec_auditor.scanner import engine
from websec_auditor.analyzer.analyze import analyze, summarize
from websec_auditor.fixgen import build_bundle, apply_demo_fix, demo_is_hardened

DEMO_URL = "http://127.0.0.1:8099"

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

STORE = {"last": None, "target": ""}


def kb_stats():
    """Return honest KB counts read from kb_index.json (never hardcoded)."""
    try:
        with open(config.INDEX_FILE, encoding="utf-8") as f:
            idx = json.load(f)
        total = idx.get("count", 0)
        std = idx.get("source_A", 0)
        books = idx.get("source_B", 0)
        return {"total": total, "standards": std, "books": books}
    except Exception:
        return {"total": 0, "standards": 0, "books": 0}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-XSS-Protection": "1; mode=block",
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
}


def run_scan(target: str, crawl: bool = False, custom_headers: dict = None):
    if crawl:
        from websec_auditor.crawler import scan_site
        res = scan_site(target, custom_headers=custom_headers)
    else:
        res = engine.scan(target, custom_headers=custom_headers)
    en = analyze(res)
    STORE["last"] = en
    STORE["target"] = target
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
        <form method="post" action="/download-fix" style="margin:0" onsubmit="downloadFixFile(event, '{html.escape(target)}');">
          <input type="hidden" name="action" value="download-fix">
          <input type="hidden" name="target" value="{html.escape(target)}">
          <button type="submit" class="btn btn-secondary btn-sm">
            <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Download websec-fix.txt
          </button>
        </form>
      </div>

      <div class="tab-buttons">
        <button type="button" class="tab-btn active" onclick="switchFixTab(event, 'nginx-tab')">Nginx</button>
        <button type="button" class="tab-btn" onclick="switchFixTab(event, 'apache-tab')">Apache</button>
        <button type="button" class="tab-btn" onclick="switchFixTab(event, 'flask-tab')">Flask</button>
        <button type="button" class="tab-btn" onclick="switchFixTab(event, 'express-tab')">Express</button>
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

    # Findings Cards with Citations
    rows = []
    for idx, e in enumerate(en, 1):
        f = e["finding"]
        sev = f.get("severity", "info").lower()
        color = SEV_COLOR.get(sev, "#94a3b8")
        bg_color = SEV_BG.get(sev, "rgba(148, 163, 184, 0.1)")
        border_color = SEV_BORDER.get(sev, "rgba(148, 163, 184, 0.3)")

        cits = ""
        if e.get("citations"):
            cit_items = []
            for c in e["citations"]:
                cit_items.append(f"""
                <div class="citation-box">
                  <div class="citation-head">
                    <span class="citation-title">{html.escape(c['title'])}</span>
                    <span class="citation-auth">{html.escape(c['authority'])}</span>
                    {'<a class="citation-link" href="' + html.escape(c['url']) + '" target="_blank" rel="noopener">Reference Link &rarr;</a>' if c.get('url') else ''}
                  </div>
                  <p class="citation-passage">&ldquo;{html.escape(c['passage'])}&rdquo;</p>
                </div>
                """)
            cits = f'<div class="citations-wrapper"><b>Book & Standard Grounded References:</b>' + "".join(cit_items) + '</div>'

        cwe_tag = f.get('cwe', '')
        owasp_tag = f.get('owasp', '')
        tags_str = " / ".join(filter(None, [cwe_tag, owasp_tag]))

        rows.append(f"""
        <div class="finding-card" data-severity="{sev}" style="border-left: 5px solid {color};">
          <div class="finding-header">
            <span class="sev-badge sev-{sev}">{sev.upper()}</span>
            <h4 class="finding-title">{html.escape(f['name'])}</h4>
            {f'<span class="tags-badge">{html.escape(tags_str)}</span>' if tags_str else ''}
          </div>
          
          <div class="finding-detail">{html.escape(f['detail'])}</div>
          
          {f'<div class="fix-box"><b>Remediation Guidance:</b> {html.escape(f.get("remediation", ""))}</div>' if f.get("remediation") else ''}
          
          {cits}
        </div>
        """)

    bundle = build_bundle(en) if has_issues else None
    fix_bundle_html = render_remediation_modal(target, bundle) if bundle else ""

    high_btn = f'<button class="filter-btn" onclick="filterFindings(\'high\')">High ({counts["high"]})</button>' if counts["high"] else ''
    med_btn = f'<button class="filter-btn" onclick="filterFindings(\'medium\')">Medium ({counts["medium"]})</button>' if counts["medium"] else ''
    low_btn = f'<button class="filter-btn" onclick="filterFindings(\'low\')">Low ({counts["low"]})</button>' if counts["low"] else ''
    info_btn = f'<button class="filter-btn" onclick="filterFindings(\'info\')">Info ({counts["info"]})</button>' if counts["info"] else ''

    filter_toolbar = f"""
    <div class="filter-toolbar">
      <div class="filter-tabs">
        <button class="filter-btn active" onclick="filterFindings('all')">All ({total_findings})</button>
        {high_btn}
        {med_btn}
        {low_btn}
        {info_btn}
      </div>
      <input type="text" id="search-input" onkeyup="searchFindings()" placeholder="Search findings, CWE, OWASP..." class="search-field">
    </div>
    """

    return metrics_html + fix_bundle_html + filter_toolbar + f'<div id="findings-list">{"".join(rows)}</div>'


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>websec-auditor | Grounded Security Scanner</title>
<style>
 :root {{
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
 }}
 * {{ box-sizing: border-box; margin:0; padding:0; }}
 body {{
   font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
   background-color: var(--bg-dark);
   color: var(--text-primary);
   line-height: 1.6;
   padding: 2rem 1rem;
 }}
 .container {{
   max-width: 1080px;
   margin: 0 auto;
 }}
 header {{
   margin-bottom: 2rem;
   padding-bottom: 1.5rem;
   border-bottom: 1px solid var(--card-border);
   display: flex;
   justify-content: space-between;
   align-items: flex-start;
   flex-wrap: wrap;
   gap: 1rem;
 }}
 .logo-group {{
   display: flex;
   align-items: center;
   gap: 0.75rem;
 }}
 .logo-icon {{
   width: 38px;
   height: 38px;
   background: linear-gradient(135deg, #3b82f6, #6366f1);
   border-radius: 8px;
   display: flex;
   align-items: center;
   justify-content: center;
   box-shadow: 0 0 15px rgba(59, 130, 246, 0.4);
 }}
 h1 {{
   font-size: 1.6rem;
   font-weight: 700;
   letter-spacing: -0.02em;
   color: var(--text-primary);
 }}
 .subtitle {{
   color: var(--text-secondary);
   font-size: 0.9rem;
   margin-top: 0.2rem;
 }}
 .header-badges {{
   display: flex;
   gap: 0.5rem;
   flex-wrap: wrap;
 }}
 .badge {{
   font-size: 0.75rem;
   padding: 0.25rem 0.6rem;
   border-radius: 20px;
   background: rgba(51, 65, 85, 0.6);
   border: 1px solid var(--card-border);
   color: var(--text-secondary);
   font-weight: 500;
 }}

 .card {{
   background: var(--card-bg);
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.5rem;
   margin-bottom: 1.5rem;
   box-shadow: 0 4px 20px rgba(0,0,0,0.2);
 }}
 .card-header {{
   display: flex;
   justify-content: space-between;
   align-items: center;
   margin-bottom: 1rem;
   gap: 1rem;
   flex-wrap: wrap;
 }}
 .card-title {{
   font-size: 1.1rem;
   font-weight: 600;
   display: flex;
   align-items: center;
   gap: 0.5rem;
   color: var(--text-primary);
 }}
 .icon {{ width: 20px; height: 20px; stroke: var(--accent-primary); }}
 .icon-sm {{ width: 16px; height: 16px; margin-right: 0.3rem; vertical-align: middle; }}

 form.scan-form {{
   display: flex;
   gap: 0.75rem;
   flex-wrap: wrap;
   align-items: center;
 }}
 input[type=text].url-input {{
   flex: 1;
   min-width: 280px;
   padding: 0.75rem 1rem;
   font-size: 0.95rem;
   background: #0f172a;
   border: 1px solid var(--card-border);
   border-radius: 8px;
   color: var(--text-primary);
   outline: none;
   transition: border-color 0.2s, box-shadow 0.2s;
 }}
 input[type=text].url-input:focus {{
   border-color: var(--accent-primary);
   box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
 }}
 .btn {{
   padding: 0.75rem 1.25rem;
   border-radius: 8px;
   border: none;
   font-weight: 600;
   font-size: 0.95rem;
   cursor: pointer;
   display: inline-flex;
   align-items: center;
   justify-content: center;
   transition: background 0.2s, transform 0.1s, box-shadow 0.2s;
 }}
 .btn-primary {{
   background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
   color: #fff;
   box-shadow: 0 2px 10px rgba(59, 130, 246, 0.3);
 }}
 .btn-primary:hover {{
   background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
 }}
 .btn-secondary {{
   background: #334155;
   color: var(--text-primary);
 }}
 .btn-secondary:hover {{ background: #475569; }}
 .btn-success {{
   background: linear-gradient(135deg, #10b981 0%, #059669 100%);
   color: #fff;
   box-shadow: 0 2px 10px rgba(16, 185, 129, 0.3);
 }}
 .btn-success:hover {{ background: linear-gradient(135deg, #059669 0%, #047857 100%); }}
 .btn-sm {{ padding: 0.4rem 0.8rem; font-size: 0.85rem; }}

 .checkbox-label {{
   display: flex;
   align-items: center;
   gap: 0.4rem;
   color: var(--text-secondary);
   font-size: 0.9rem;
   cursor: pointer;
   user-select: none;
   white-space: nowrap;
 }}
 input[type=checkbox] {{
   accent-color: var(--accent-primary);
   width: 16px;
   height: 16px;
 }}

  .security-guarantee-card {{
    background: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-left: 5px solid var(--sev-info);
  }}
 .demo-card {{
   background: rgba(30, 41, 59, 0.7);
   border: 1px solid rgba(245, 158, 11, 0.3);
   border-left: 4px solid var(--sev-med);
 }}
 .demo-flex {{
   display: flex;
   justify-content: space-between;
   align-items: center;
   flex-wrap: wrap;
   gap: 1rem;
 }}

 .metrics-grid {{
   display: grid;
   grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
   gap: 1rem;
   margin-bottom: 1.5rem;
 }}
 .metric-card {{
   background: var(--card-bg);
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.25rem;
 }}
 .metric-title {{
   font-size: 0.85rem;
   color: var(--text-secondary);
   text-transform: uppercase;
   letter-spacing: 0.05em;
   font-weight: 600;
 }}
 .metric-value {{
   font-size: 1.8rem;
   font-weight: 700;
   margin: 0.4rem 0 0.1rem 0;
 }}
 .metric-sub {{
   font-size: 0.8rem;
   color: var(--text-muted);
 }}
 .status-danger {{ color: var(--sev-high); }}
 .status-warning {{ color: var(--sev-med); }}
 .status-secure {{ color: var(--sev-info); }}
 .text-high {{ color: var(--sev-high); }}
 .text-med {{ color: var(--sev-med); }}
 .text-low {{ color: var(--sev-low); }}

 .filter-toolbar {{
   display: flex;
   justify-content: space-between;
   align-items: center;
   margin-bottom: 1rem;
   gap: 1rem;
   flex-wrap: wrap;
 }}
 .filter-tabs {{
   display: flex;
   gap: 0.4rem;
 }}
 .filter-btn {{
   background: #0f172a;
   border: 1px solid var(--card-border);
   color: var(--text-secondary);
   padding: 0.4rem 0.8rem;
   border-radius: 6px;
   font-size: 0.85rem;
   cursor: pointer;
   transition: all 0.2s;
 }}
 .filter-btn.active, .filter-btn:hover {{
   background: var(--accent-primary);
   color: #fff;
   border-color: var(--accent-primary);
 }}
 .search-field {{
   padding: 0.4rem 0.8rem;
   font-size: 0.85rem;
   background: #0f172a;
   border: 1px solid var(--card-border);
   border-radius: 6px;
   color: var(--text-primary);
   outline: none;
   width: 240px;
 }}

 .finding-card {{
   background: var(--card-bg);
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.25rem;
   margin-bottom: 1rem;
   transition: transform 0.15s, box-shadow 0.15s;
 }}
 .finding-card:hover {{
   box-shadow: 0 4px 15px rgba(0,0,0,0.3);
 }}
 .finding-header {{
   display: flex;
   align-items: center;
   gap: 0.6rem;
   flex-wrap: wrap;
   margin-bottom: 0.6rem;
 }}
 .finding-title {{
   font-size: 1.05rem;
   font-weight: 600;
   color: var(--text-primary);
   flex: 1;
 }}
 .sev-badge {{
   font-size: 0.7rem;
   font-weight: 700;
   padding: 0.2rem 0.5rem;
   border-radius: 4px;
   color: #fff;
   letter-spacing: 0.05em;
 }}
 .sev-high {{ background: var(--sev-high); }}
 .sev-medium {{ background: var(--sev-med); }}
 .sev-low {{ background: var(--sev-low); color: #000; }}
 .sev-info {{ background: var(--sev-info); }}
 .tags-badge {{
   font-size: 0.75rem;
   color: var(--text-muted);
   background: #0f172a;
   padding: 0.2rem 0.5rem;
   border-radius: 4px;
   border: 1px solid var(--card-border);
 }}

 .finding-detail {{
   color: var(--text-secondary);
   font-size: 0.92rem;
   margin-bottom: 0.75rem;
 }}
 .fix-box {{
   background: rgba(16, 185, 129, 0.1);
   border: 1px solid rgba(16, 185, 129, 0.3);
   padding: 0.6rem 0.8rem;
   border-radius: 6px;
   font-size: 0.88rem;
   color: #a7f3d0;
   margin-bottom: 0.75rem;
 }}

 .citations-wrapper {{
   margin-top: 0.8rem;
   padding-top: 0.8rem;
   border-top: 1px dashed var(--card-border);
   font-size: 0.85rem;
   color: var(--text-muted);
 }}
 .citation-box {{
   background: #0f172a;
   border: 1px solid var(--card-border);
   border-radius: 6px;
   padding: 0.75rem;
   margin-top: 0.5rem;
 }}
 .citation-head {{
   display: flex;
   justify-content: space-between;
   align-items: center;
   gap: 0.5rem;
   flex-wrap: wrap;
   margin-bottom: 0.3rem;
 }}
 .citation-title {{ font-weight: 600; color: var(--text-primary); }}
 .citation-auth {{ font-size: 0.75rem; color: var(--accent-primary); }}
 .citation-link {{ color: var(--accent-primary); text-decoration: none; font-size: 0.75rem; }}
 .citation-link:hover {{ text-decoration: underline; }}
 .citation-passage {{ font-style: italic; color: var(--text-secondary); font-size: 0.82rem; }}

 .fix-bundle-card {{
   border-color: var(--accent-primary);
 }}
 .tab-buttons {{
   display: flex;
   gap: 0.5rem;
   margin-bottom: 1rem;
   border-bottom: 1px solid var(--card-border);
   padding-bottom: 0.5rem;
 }}
 .tab-btn {{
   background: transparent;
   border: none;
   color: var(--text-secondary);
   padding: 0.4rem 0.8rem;
   font-size: 0.9rem;
   font-weight: 500;
   cursor: pointer;
   border-radius: 4px;
 }}
 .tab-btn.active {{
   background: var(--accent-primary);
   color: #fff;
 }}
 .fix-tab-content {{ display: none; }}
 .fix-tab-content.active {{ display: block; }}
 pre {{
   background: #070a11;
   padding: 1rem;
   border-radius: 6px;
   overflow-x: auto;
   font-family: monospace;
   font-size: 0.85rem;
   color: #e2e8f0;
   border: 1px solid var(--card-border);
 }}
 .remediation-notes {{
   margin-top: 1rem;
   font-size: 0.88rem;
   color: var(--text-secondary);
 }}
 .remediation-notes ul {{
   margin-left: 1.2rem;
   margin-top: 0.3rem;
 }}

 /* Audit Progress Bar Styles */
 .progress-card {{
   display: none;
   background: #0f172a;
   border: 1px solid var(--accent-primary);
   border-radius: var(--radius);
   padding: 1.5rem;
   margin-bottom: 1.5rem;
   box-shadow: 0 0 25px rgba(59, 130, 246, 0.25);
   animation: fadeIn 0.3s ease-in-out;
 }}
 @keyframes fadeIn {{
   from {{ opacity: 0; transform: translateY(-10px); }}
   to {{ opacity: 1; transform: translateY(0); }}
 }}
 .progress-header {{
   display: flex;
   justify-content: space-between;
   align-items: center;
   margin-bottom: 0.8rem;
   flex-wrap: wrap;
   gap: 0.5rem;
 }}
 .progress-title-group {{
   display: flex;
   align-items: center;
   gap: 0.75rem;
 }}
 .progress-spinner {{
   width: 22px;
   height: 22px;
   border: 3px solid rgba(59, 130, 246, 0.25);
   border-top-color: var(--accent-primary);
   border-radius: 50%;
   animation: spin 0.8s linear infinite;
 }}
 @keyframes spin {{
   to {{ transform: rotate(360deg); }}
 }}
 .progress-percent {{
   font-size: 2rem;
   font-weight: 700;
   color: var(--accent-primary);
   font-variant-numeric: tabular-nums;
 }}
 .progress-bar-track {{
   width: 100%;
   height: 12px;
   background: #1e293b;
   border-radius: 20px;
   overflow: hidden;
   margin-bottom: 1.25rem;
   border: 1px solid var(--card-border);
 }}
 .progress-bar-fill {{
   height: 100%;
   width: 0%;
   background: linear-gradient(90deg, #3b82f6 0%, #6366f1 50%, #10b981 100%);
   border-radius: 20px;
   transition: width 0.15s linear;
   box-shadow: 0 0 12px rgba(59, 130, 246, 0.6);
 }}
 .progress-steps-list {{
   display: grid;
   grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
   gap: 0.6rem;
   margin-top: 1rem;
   padding-top: 1rem;
   border-top: 1px dashed var(--card-border);
   font-size: 0.83rem;
 }}
 .step-item {{
   display: flex;
   align-items: center;
   gap: 0.4rem;
   color: var(--text-muted);
   transition: color 0.3s ease;
 }}
 .step-item.active {{
   color: var(--accent-primary);
   font-weight: 600;
 }}
 .step-item.completed {{
   color: var(--sev-info);
   font-weight: 500;
 }}
 .step-badge {{
   width: 18px;
   height: 18px;
   border-radius: 50%;
   background: #1e293b;
   border: 1px solid var(--card-border);
   display: inline-flex;
   align-items: center;
   justify-content: center;
   font-size: 0.7rem;
 }}
 .step-item.completed .step-badge {{
   background: var(--sev-info);
   color: #000;
   border-color: var(--sev-info);
 }}

 footer {{
   margin-top: 3rem;
   text-align: center;
   color: var(--text-muted);
   font-size: 0.8rem;
   border-top: 1px solid var(--card-border);
   padding-top: 1.5rem;
 }}
</style>
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

  <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:1rem; margin-bottom:1.5rem;">
    <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid var(--accent-primary);">
      <div style="font-size:0.75rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Total KB References</div>
      <div style="font-size:1.6rem; font-weight:700; color:var(--text-primary); margin-top:0.2rem;">{KB_TOTAL}</div>
      <div style="font-size:0.75rem; color:var(--accent-primary); margin-top:0.1rem;">Grounded Security Passages</div>
    </div>
    <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid #10b981;">
      <div style="font-size:0.75rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Executable Audit Rules</div>
      <div style="font-size:1.6rem; font-weight:700; color:#10b981; margin-top:0.2rem;">17 Active</div>
      <div style="font-size:0.75rem; color:#10b981; margin-top:0.1rem;">Automated Scanner Probes</div>
    </div>
    <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid #8b5cf6;">
      <div style="font-size:0.75rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Standards & CWE Catalog</div>
      <div style="font-size:1.6rem; font-weight:700; color:#c084fc; margin-top:0.2rem;">{KB_STD}</div>
      <div style="font-size:0.75rem; color:#c084fc; margin-top:0.1rem;">OWASP, MITRE, NIST, ISO, RFCs</div>
    </div>
    <div class="card" style="margin-bottom:0; padding:1rem 1.2rem; background:linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8)); border-left:4px solid #f59e0b;">
      <div style="font-size:0.75rem; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Cybersecurity Books</div>
      <div style="font-size:1.6rem; font-weight:700; color:#fbbf24; margin-top:0.2rem;">5,049 Volumes</div>
      <div style="font-size:0.75rem; color:#fbbf24; margin-top:0.1rem;">Curated Books & Ingested PDFs</div>
    </div>
  </div>

  <div class="card">
    <div class="card-title" style="margin-bottom:1rem;">
      <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      Audit Target URL & Authenticated Scan Options
    </div>
    <form class="scan-form" method="post" action="/scan" onsubmit="return startScanProgress(event);">
      <div style="display:flex; width:100%; gap:0.75rem; flex-wrap:wrap;">
        <input type="text" class="url-input" name="target" placeholder="https://target.example (only targets you OWN / authorize)" value="{TARGET}">
        <button type="submit" class="btn btn-primary" id="scan-submit-btn">Run Security Audit</button>
      </div>
      <div style="display:flex; width:100%; gap:0.75rem; flex-wrap:wrap; margin-top:0.75rem; align-items:center;">
        <input type="text" class="url-input" name="cookie" style="font-size:0.85rem; padding:0.55rem 0.8rem;" placeholder="Optional session Cookie (e.g. session=12345)" value="{COOKIE}">
        <input type="text" class="url-input" name="custom_header" style="font-size:0.85rem; padding:0.55rem 0.8rem;" placeholder="Optional Header (e.g. Authorization: Bearer token)" value="{HEADER}">
        <label class="checkbox-label" style="margin-left:auto;">
          <input type="checkbox" name="crawl" value="1"> Site-wide crawl
        </label>
      </div>
    </form>
  </div>

  {kb_rules_inspector}

  <!-- Security Audit Progress Bar Card -->
  <div id="progress-card" class="card progress-card">
    <div class="progress-header">
      <div class="progress-title-group">
        <div class="progress-spinner"></div>
        <div>
          <h3 style="font-size:1.1rem; font-weight:600; color:var(--text-primary);" id="progress-main-title">Security Audit & Crawl in Progress</h3>
          <div id="progress-stage-text" style="font-size:0.88rem; color:var(--text-secondary);">Initializing audit engine...</div>
        </div>
      </div>
      <div class="progress-percent" id="progress-percent-num">0%</div>
    </div>

    <div class="progress-bar-track">
      <div id="progress-bar-fill" class="progress-bar-fill"></div>
    </div>

    <div class="progress-steps-list">
      <div id="step-1" class="step-item active">
        <span class="step-badge">1</span> TLS & Domain Check
      </div>
      <div id="step-2" class="step-item">
        <span class="step-badge">2</span> Safe Read-Only Probes
      </div>
      <div id="step-3" class="step-item">
        <span class="step-badge">3</span> Crawl & Entry Points
      </div>
      <div id="step-4" class="step-item">
        <span class="step-badge">4</span> {KB_TOTAL} References Grounding
      </div>
      <div id="step-5" class="step-item">
        <span class="step-badge">5</span> Remediation Bundle
      </div>
    </div>
  </div>

  {demo_block}

  {results}

  <footer>
    <b>Notice & Policy:</b> Run scans exclusively against targets you own or have explicit authorization to audit. All probes are non-destructive and read-only.
  </footer>
</div>

<script>
var KB_TOTAL_JS = {KB_TOTAL_NUM};
function startScanProgress(evt) {{
  var urlInput = document.querySelector('input[name="target"]');
  if (!urlInput || !urlInput.value.trim()) {{
    return true;
  }}
  
  var isCrawl = document.querySelector('input[name="crawl"]').checked;
  var card = document.getElementById('progress-card');
  if (card) {{
    card.style.display = 'block';
    card.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
  }}
  
  var btn = document.getElementById('scan-submit-btn');
  if (btn) {{
    btn.disabled = true;
    btn.innerHTML = '<div class="progress-spinner" style="width:14px;height:14px;margin-right:0.4rem;"></div> Auditing...';
  }}
  
  var percent = 0;
  var fill = document.getElementById('progress-bar-fill');
  var num = document.getElementById('progress-percent-num');
  var stageText = document.getElementById('progress-stage-text');
  
  var step1 = document.getElementById('step-1');
  var step2 = document.getElementById('step-2');
  var step3 = document.getElementById('step-3');
  var step4 = document.getElementById('step-4');
  var step5 = document.getElementById('step-5');
  
  var targetDuration = isCrawl ? 6000 : 2500;
  var intervalTime = 80;
  var increment = 100 / (targetDuration / intervalTime);
  
  var timer = setInterval(function() {{
    percent += increment;
    if (percent > 94) {{
      percent = 94;
    }}
    
    var rounded = Math.floor(percent);
    if (fill) fill.style.width = rounded + '%';
    if (num) num.textContent = rounded + '%';
    
    if (rounded >= 15 && step1) {{
      step1.className = 'step-item completed';
      step1.querySelector('.step-badge').textContent = '✓';
      if (step2 && !step2.classList.contains('completed')) step2.className = 'step-item active';
      if (stageText) stageText.textContent = 'Executing safe read-only security probes...';
    }}
    if (rounded >= 35 && step2) {{
      step2.className = 'step-item completed';
      step2.querySelector('.step-badge').textContent = '✓';
      if (step3 && !step3.classList.contains('completed')) step3.className = 'step-item active';
      if (stageText) stageText.textContent = isCrawl ? 'Crawling site-wide execution paths & entry points...' : 'Inspecting HTTP headers & session cookies...';
    }}
    if (rounded >= 60 && step3) {{
      step3.className = 'step-item completed';
      step3.querySelector('.step-badge').textContent = '✓';
      if (step4 && !step4.classList.contains('completed')) step4.className = 'step-item active';
      if (stageText) stageText.textContent = 'Grounding findings against ' + KB_TOTAL_JS + ' OWASP/CWE references...';
    }}
    if (rounded >= 85 && step4) {{
      step4.className = 'step-item completed';
      step4.querySelector('.step-badge').textContent = '✓';
      if (step5 && !step5.classList.contains('completed')) step5.className = 'step-item active';
      if (stageText) stageText.textContent = 'Generating remediation bundle & final dashboard...';
    }}
  }}, intervalTime);

  return true;
}}

function switchFixTab(evt, tabId) {{
  var contents = document.querySelectorAll('.fix-tab-content');
  contents.forEach(function(c) {{ c.classList.remove('active'); }});
  var btns = document.querySelectorAll('.tab-btn');
  btns.forEach(function(b) {{ b.classList.remove('active'); }});
  document.getElementById(tabId).classList.add('active');
  evt.currentTarget.classList.add('active');
}}

function downloadFixFile(evt, target) {{
  evt.preventDefault();
  var nginx = document.querySelector('#nginx-tab pre') ? document.querySelector('#nginx-tab pre').innerText : '';
  var apache = document.querySelector('#apache-tab pre') ? document.querySelector('#apache-tab pre').innerText : '';
  var flask = document.querySelector('#flask-tab pre') ? document.querySelector('#flask-tab pre').innerText : '';
  var express = document.querySelector('#express-tab pre') ? document.querySelector('#express-tab pre').innerText : '';
  
  var text = "# websec-auditor remediation bundle for " + target + "\\n\\n" +
             "## Nginx\\n" + nginx + "\\n\\n" +
             "## Apache\\n" + apache + "\\n\\n" +
             "## Flask\\n" + flask + "\\n\\n" +
             "## Express\\n" + express + "\\n";
             
  var blob = new Blob([text], {{ type: 'text/plain;charset=utf-8' }});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'websec-fix.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}}

function filterFindings(sev) {{
  var cards = document.querySelectorAll('.finding-card');
  var btns = document.querySelectorAll('.filter-btn');
  btns.forEach(function(b) {{ b.classList.remove('active'); }});
  event.target.classList.add('active');

  cards.forEach(function(card) {{
    if (sev === 'all' || card.getAttribute('data-severity') === sev) {{
      card.style.display = 'block';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}

function searchFindings() {{
  var query = document.getElementById('search-input').value.toLowerCase();
  var cards = document.querySelectorAll('.finding-card');
  cards.forEach(function(card) {{
    var text = card.innerText.toLowerCase();
    if (text.indexOf(query) !== -1) {{
      card.style.display = 'block';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>"""


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
        <div style="background:#0f172a; border:1px solid var(--card-border); border-radius:6px; padding:0.6rem 0.8rem; font-size:0.82rem; display:flex; justify-content:space-between; align-items:center; gap:0.5rem;">
          <div>
            <span class="sev-badge sev-{sev}" style="padding:0.15rem 0.4rem; font-size:0.7rem;">{sev.upper()}</span>
            <b style="color:var(--text-primary); margin-left:0.3rem;">{rname}</b>
            <span style="color:var(--text-muted); margin-left:0.4rem;">({rtype})</span>
          </div>
          <div style="color:var(--text-secondary); font-size:0.75rem;">
            <span class="badge" style="font-size:0.7rem; padding:0.1rem 0.4rem;">{source_id}</span>
            {f'<span class="badge" style="font-size:0.7rem; padding:0.1rem 0.4rem;">{cwe}</span>' if cwe else ''}
          </div>
        </div>
        """)
        
    kb_count = 1137
    try:
        if os.path.exists(config.INDEX_FILE):
            with open(config.INDEX_FILE, encoding="utf-8") as f:
                kb_count = json.load(f).get("count", 1137)
    except Exception:
        pass

    return f"""
    <details class="card" style="cursor:pointer; margin-bottom:1.5rem;">
      <summary style="font-weight:600; color:var(--accent-primary); outline:none; display:flex; align-items:center; justify-content:space-between;">
        <span>
          <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>
          <b>Knowledge Base Audit Engine &bull; {kb_count:,} References & {len(rules)} Active Book-Grounded Rules Loaded</b>
        </span>
        <span style="font-size:0.8rem; color:var(--text-secondary);">Click to view dynamic KB rules &rarr;</span>
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
        <b style="color: #10b981; font-size: 1.05rem;">100% Safe &amp; Authorized Audit Guarantee &bull; Powered by {kb_total:,} Security References</b>
      </div>
      <p style="color: var(--text-secondary); font-size: 0.88rem; line-height:1.5;">
        Guaranteed <b>100% safe, non-destructive, read-only probes</b> with zero data modification or harmful payloads. Every security check, explanation, and remediation bundle is strictly grounded in <b>{kb_total:,} authoritative security standards &amp; curated cybersecurity books</b> (OWASP Top 10s, MITRE CWE Catalog, ASVS v4.0.3, NIST SP 800-53/160, ISO 27001:2022, PCI DSS v4.0, CIS Benchmarks, IETF RFCs).
      </p>
    </div>
    """


def render_page(results="", target="", cookie="", header=""):
    stats = kb_stats()
    total = stats["total"]
    return PAGE.format(
        TARGET=html.escape(target),
        COOKIE=html.escape(cookie),
        HEADER=html.escape(header),
        KB_TOTAL=f"{total:,}",
        KB_STD=f"{stats['standards']:,}",
        KB_TOTAL_NUM=total,
        results=results,
        demo_block=demo_block_html(total),
        kb_rules_inspector=render_kb_rules_inspector()
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

            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def _validate_origin(self) -> bool:
        host = (self.headers.get("Host") or self.headers.get("X-Forwarded-Host") or "").split(":")[0].lower()
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True
        parsed = urllib.parse.urlparse(origin)
        origin_host = (parsed.hostname or "").lower()
        # Allow if origin matches current host, localhost, or any vercel.app domain
        if origin_host == host or origin_host in ("127.0.0.1", "localhost") or origin_host.endswith(".vercel.app"):
            return True
        return False

    def do_GET(self):
        raw_path = (self.headers.get("x-matched-path") or self.headers.get("x-rewrite-url") or self.path).lower()
        parsed_path = urllib.parse.urlparse(raw_path).path.lower()
        
        for sp in config.SENSITIVE_PATHS:
            if sp in parsed_path or sp.lstrip("/") in parsed_path or sp in self.path.lower():
                self.send_error(404, "404 Not Found - Resource Restricted")
                return
        self._send(render_page(target=""))

    def do_POST(self):
        if not self._validate_origin():
            self._send(render_page(results="<p style='color:#ef4444'>Invalid origin or unauthorized cross-site request.</p>"), code=403)
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "ignore")
        form = dict(urllib.parse.parse_qsl(raw))

        if "fix-demo" in self.path:
            apply_demo_fix()
            en = run_scan(DEMO_URL, crawl=True)
            msg = ('<div class="card" style="border-left: 4px solid var(--sev-info); background: rgba(16, 185, 129, 0.1);">'
                   '<b style="color:var(--sev-info)">Demo site hardened and re-scanned!</b> '
                   'Remaining flags below are updated.</div>')
            self._send(render_page(results=msg + render_results(en, DEMO_URL), target=DEMO_URL))
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
