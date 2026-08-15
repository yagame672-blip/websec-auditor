"""Render an analysis to a self-contained HTML report (terminal-friendly text
also available). Findings are always shown with their book/standard citation.
"""
from __future__ import annotations
import html
import json
from datetime import datetime

from websec_auditor.owasptop10 import scorecard as owasp_scorecard
from websec_auditor.owasptop10 import render_html as owasp_render_html
from websec_auditor.owasptop10 import render_text as owasp_render_text
from websec_auditor.owasptop10 import owasp_css

SEV_COLOR = {
    "high": "#ef4444",
    "medium": "#f59e0b",
    "low": "#eab308",
    "info": "#10b981",
}


def render_json(enriched, target):
    """Machine-readable JSON report: summary + full findings + citations."""
    return json.dumps({
        "tool": "websec-auditor",
        "target": target,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "summary": owasp_scorecard(enriched) if enriched else {},
        "findings": [e["finding"] for e in enriched],
    }, indent=2, default=str)


def render_sarif(enriched, target):
    """SARIF 2.1.0 report (VSCode/GitHub security code scanning compatible).
    Only fail/warn findings are emitted as SARIF results."""
    results = []
    rules = {}
    for e in enriched:
        f = e["finding"]
        if f["status"] not in ("fail", "warn"):
            continue
        rule_id = f.get("check") or f["name"]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f["name"],
                "shortDescription": {"text": f["name"]},
                "fullDescription": {"text": f.get("detail", "")},
                "helpUri": f.get("source_id") or "",
                "properties": {
                    "security-severity": _sarif_severity(f.get("severity", "medium")),
                    "cwe": f.get("cwe", ""),
                    "owasp": f.get("owasp", ""),
                    "confidence": f.get("confidence", ""),
                    "status": f["status"],
                },
            }
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(f.get("severity", "medium")),
            "message": {"text": f.get("detail", "") or f["name"]},
            "properties": {
                "findingName": f["name"],
                "remediation": f.get("remediation", ""),
                "sourceId": f.get("source_id", ""),
            },
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "websec-auditor",
                    "informationUri": "https://github.com/yagame672-blip/websec-auditor",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }, indent=2, default=str)


def _sarif_severity(sev: str):
    return {"high": "9.0", "medium": "6.0", "low": "3.0", "info": "1.0"}.get(sev, "6.0")


def _sarif_level(sev: str):
    return {"high": "error", "medium": "warning", "low": "note", "info": "note"}.get(sev, "warning")


def render_text(enriched, target):
    lines = []
    lines.append(f"WEBSEC-AUDITOR REPORT  |  {target}")
    lines.append(f"generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("=" * 64)
    for e in enriched:
        f = e["finding"]
        conf = f.get("confidence", "")
        conf_s = f" [confidence: {conf}]" if conf else ""
        lines.append(f"\n[{f['severity'].upper()}]{conf_s} {f['name']}  ({f.get('cwe','')}/{f.get('owasp','')})")
        lines.append(f"  status : {f['status']}")
        lines.append(f"  detail : {f['detail']}")
        if f.get("remediation"):
            lines.append(f"  fix    : {f['remediation']}")
        if e["citations"]:
            lines.append("  cited by:")
            for c in e["citations"]:
                match_s = " (" + ", ".join(c.get("match") or []) + ")" if c.get("match") else ""
                lines.append(f"    - {c['title']}{match_s} ({c['authority']}) {c['url']}")
    lines.append("\n" + owasp_render_text(owasp_scorecard(enriched)))
    return "\n".join(lines)


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


def render_action_checklist(enriched) -> str:
    """Render a dedicated, high-visibility Fix Checklist showing exactly what is wrong and how to fix it."""
    if not enriched:
        return ""
    
    issues = []
    for item in enriched:
        f = item.get("finding", {})
        sev = (f.get("severity") or "info").lower()
        status = (f.get("status") or "pass").lower()
        if sev in ("high", "medium", "low") or status in ("fail", "warn"):
            issues.append(f)
            
    if not issues:
        return """
        <div class="card" style="border-left: 4px solid var(--sev-info); background: rgba(16, 185, 129, 0.08); margin-bottom: 1.5rem; padding: 1.25rem; border-radius: var(--radius);">
          <div style="display:flex; align-items:center; gap:0.75rem;">
            <span style="font-size:1.4rem;">🎉</span>
            <div>
              <b style="color:var(--sev-info); font-size:1.05rem;">Walang Kritikal na Problema (No Vulnerabilities Detected)</b>
              <p style="margin-top:0.2rem; font-size:0.9rem; color:var(--text-secondary);">Lahat ng security checks at baseline configurations ay maayos na nakapasa.</p>
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
        remediation = f.get("remediation") or "Audit at i-update ang server configuration base sa inirekomendang security standard."
        
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
              {area_icon} <b>Parte:</b> {html.escape(area_name)}
            </span>
          </div>
          
          <div style="font-size:0.88rem; color:var(--text-secondary); margin-bottom:0.45rem;">
            <span style="color:#f87171; font-weight:600;">⚠️ Problema:</span> {html.escape(f.get('detail', ''))}
          </div>
          
          <div style="font-size:0.88rem; color:var(--text-primary); background:rgba(0,0,0,0.25); padding:0.5rem 0.75rem; border-radius:4px; border:1px dashed rgba(255,255,255,0.15);">
            <b style="color:#10b981;">💡 Paano Aayusin (Actionable Fix):</b> <code>{html.escape(remediation)}</code>
          </div>
        </div>
        """)
        
    return f"""
    <div class="card action-checklist-card" style="background:var(--card-bg); border:1px solid rgba(59, 130, 246, 0.4); border-radius:var(--radius); padding:1.25rem; margin-bottom:1.5rem;">
      <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--card-border); padding-bottom:0.75rem; margin-bottom:1rem; flex-wrap:wrap; gap:0.5rem;">
        <div style="display:flex; align-items:center; gap:0.6rem;">
          <span style="font-size:1.4rem;">🎯</span>
          <div>
            <h3 style="margin:0; font-size:1.15rem; font-weight:700; color:var(--text-primary);">Mga Bahaging May Problema at Kailangang Ayusin (Priority Fix Checklist)</h3>
            <p style="margin:0; font-size:0.85rem; color:var(--text-secondary);">Direktang listahan ng mga nakitang kakulangan, apektadong component, at ang eksaktong gagawin para maayos.</p>
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


def render_html(enriched, target):
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for e in enriched:
        sev = e["finding"].get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    total_findings = len(enriched)
    if counts["high"] > 0:
        health_status = "CRITICAL RISK"
        health_class = "status-danger"
    elif counts["medium"] > 0 or counts["low"] > 0:
        health_status = "NEEDS FIXES"
        health_class = "status-warning"
    else:
        health_status = "SECURE POSTURE"
        health_class = "status-secure"

    checklist_section = render_action_checklist(enriched)
    owasp_section = owasp_render_html(owasp_scorecard(enriched))
    owasp_styles = owasp_css()

    SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
    enriched_sorted = sorted(enriched, key=lambda x: SEV_ORDER.get(x["finding"].get("severity", "info").lower(), 4))

    body = []
    for e in enriched_sorted:
        f = e["finding"]
        sev = f.get("severity", "info").lower()
        color = SEV_COLOR.get(sev, "#94a3b8")

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
                    <span class="citation-auth">{html.escape(c.get('authority') or c.get('publisher') or '')}</span>
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

        body.append(f"""
        <div class="finding-card" style="border-left: 5px solid {color};">
          <div class="finding-header">
            <span class="sev-badge sev-{sev}">{sev.upper()}</span>
            {conf_html}
            <h3 class="finding-title">{html.escape(f['name'])}</h3>
            {f'<span class="tags-badge">{html.escape(tags_str)}</span>' if tags_str else ''}
          </div>
          
          <div class="finding-detail">{html.escape(f['detail'])}</div>
          
          {ctx_line}
          
          {f'<div class="fix-box"><b>Remediation Guidance:</b> {html.escape(f.get("remediation", ""))}</div>' if f.get("remediation") else ''}
          
          {cits}
        </div>
        """)

    timestamp = datetime.now().isoformat(timespec='seconds')

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>websec-auditor Report | {html.escape(target)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
 :root {{
   --bg-dark: #0b0f19;
   --card-bg: #1e293b;
   --card-border: #334155;
   --text-primary: #f8fafc;
   --text-secondary: #94a3b8;
   --text-muted: #64748b;
   --accent-primary: #3b82f6;
   --sev-high: #ef4444;
   --sev-med: #f59e0b;
   --sev-low: #eab308;
   --sev-info: #10b981;
   --radius: 10px;
 }}
 * {{ box-sizing: border-box; margin:0; padding:0; }}
 body {{
   font-family: 'Inter', system-ui, -apple-system, sans-serif;
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
   color: var(--text-primary);
 }}
 .subtitle {{
   color: var(--text-secondary);
   font-size: 0.9rem;
   margin-top: 0.2rem;
 }}
 .header-meta {{
   text-align: right;
   font-size: 0.85rem;
   color: var(--text-secondary);
 }}
 .header-meta code {{
   background: #0f172a;
   padding: 0.2rem 0.5rem;
   border-radius: 4px;
   border: 1px solid var(--card-border);
   color: var(--accent-primary);
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

 .finding-card {{
   background: var(--card-bg);
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.25rem;
   margin-bottom: 1rem;
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
  .conf-high {{ background: #059669; }}
  .conf-medium {{ background: #d97706; }}
  .conf-low {{ background: #64748b; }}
  .tags-badge {{
    font-size: 0.75rem;
    color: var(--text-muted);
    background: #0f172a;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    border: 1px solid var(--card-border);
  }}
  .finding-context {{
    font-size: 0.78rem;
    color: var(--accent-primary);
    margin-bottom: 0.75rem;
  }}
  .citation-meta {{
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 0.3rem;
  }}
  .citation-match {{
    color: #34d399;
    margin-right: 0.5rem;
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
 .citation-passage {{ font-style: italic; color: var(--text-secondary); font-size: 0.82rem; }}

  footer {{
    margin-top: 3rem;
    text-align: center;
    color: var(--text-muted);
    font-size: 0.8rem;
    border-top: 1px solid var(--card-border);
    padding-top: 1.5rem;
  }}
 {owasp_styles}
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
        <h1>websec-auditor Report</h1>
        <div class="subtitle">Book-Grounded Security Analysis</div>
      </div>
    </div>
    <div class="header-meta">
      <div>Target: <code>{html.escape(target)}</code></div>
      <div>Generated: {timestamp}</div>
    </div>
  </header>

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

  {checklist_section}

  {owasp_section}

  {''.join(body)}

  <footer>
    Findings are strictly grounded in OWASP Top 10:2021, MITRE CWE, and OWASP ASVS v4.0.1.
    <br>Scan only targets you own or are explicitly authorized to audit.
  </footer>
</div>
</body>
</html>"""


if __name__ == "__main__":
    import sys
    sys.path.insert(0, sys.path[0])
    from websec_auditor.scanner import engine
    from websec_auditor.analyzer import analyze as _analyze
    tgt = sys.argv[1] if len(sys.argv) > 1 else "https://self-signed.badssl.com"
    r = engine.scan(tgt)
    en = _analyze(r)
    print(render_text(en, tgt))
