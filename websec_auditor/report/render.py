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


def group_enriched_findings(enriched):
    """Group duplicate/same error findings into a single consolidated record."""
    if not enriched:
        return []
    grouped = []
    index_map = {}
    for item in enriched:
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

    owasp_section = owasp_render_html(owasp_scorecard(enriched))
    owasp_styles = owasp_css()

    SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
    enriched_grouped = group_enriched_findings(enriched)
    enriched_sorted = sorted(enriched_grouped, key=lambda x: SEV_ORDER.get(x["finding"].get("severity", "info").lower(), 4))

    body = []
    for e in enriched_sorted:
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

        remediation_html = ""
        if f.get("remediation"):
            remediation_html = f"""
            <div class="fix-box" style="margin:0.6rem 0; background:rgba(0,0,0,0.25); border:1px dashed rgba(255,255,255,0.15); padding:0.6rem 0.8rem; border-radius:6px;">
              <b style="color:#10b981;">💡 Actionable Remediation:</b> <code>{html.escape(f.get("remediation", ""))}</code>
            </div>
            """

        body.append(f"""
        <div class="finding-card" style="border-left: 5px solid {color};">
          <div class="finding-header" style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap;">
            <span class="sev-badge sev-{sev}">{sev.upper()}</span>
            {conf_html}
            {count_badge}
            <h3 class="finding-title" style="margin:0;">{html.escape(f['name'])}</h3>
            {f'<span class="tags-badge">{html.escape(tags_str)}</span>' if tags_str else ''}
            {area_badge}
          </div>
          
          <div class="finding-detail" style="margin:0.6rem 0;">{detail_html}</div>
          
          {ctx_line}
          
          {remediation_html}
          
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
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
 :root {{
   --bg-page: #f8fafc;
   --card-bg: #ffffff;
   --card-border: #e2e8f0;
   --text-primary: #0f172a;
   --text-secondary: #475569;
   --text-muted: #64748b;
   --accent-primary: #2563eb;
   --sev-high: #dc2626;
   --sev-med: #d97706;
   --sev-low: #ca8a04;
   --sev-info: #059669;
   --radius: 12px;
 }}
 * {{ box-sizing: border-box; margin:0; padding:0; }}
 body {{
   font-family: 'Inter', system-ui, -apple-system, sans-serif;
   background: var(--bg-page);
   color: var(--text-primary);
   line-height: 1.6;
   padding: 2rem 1.5rem;
 }}
 .container {{
   max-width: 1100px;
   margin: 0 auto;
 }}
 header {{
   display: flex;
   justify-content: space-between;
   align-items: center;
   background: #ffffff;
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.25rem 1.75rem;
   margin-bottom: 2rem;
   box-shadow: 0 1px 3px rgba(0,0,0,0.05);
   flex-wrap: wrap;
   gap: 1rem;
 }}
 .logo-group {{ display: flex; align-items: center; gap: 0.85rem; }}
 .logo-icon {{
   background: linear-gradient(135deg, #2563eb, #4f46e5);
   width: 42px;
   height: 42px;
   border-radius: 10px;
   display: flex;
   align-items: center;
   justify-content: center;
   box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
 }}
 h1 {{ font-size: 1.5rem; font-weight: 800; }}
 .subtitle {{ font-size: 0.88rem; color: var(--text-secondary); }}
 .header-meta {{ font-size: 0.85rem; color: var(--text-secondary); text-align: right; }}

 .metrics-grid {{
   display: grid;
   grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
   gap: 1rem;
   margin-bottom: 2rem;
 }}
 .metric-card {{
   background: #ffffff;
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.25rem;
   box-shadow: 0 1px 3px rgba(0,0,0,0.05);
 }}
 .metric-title {{ font-size: 0.82rem; color: var(--text-muted); text-transform: uppercase; font-weight: 700; }}
 .metric-value {{ font-size: 1.8rem; font-weight: 800; margin: 0.3rem 0; }}
 .metric-sub {{ font-size: 0.82rem; color: var(--text-secondary); }}

 .status-secure {{ color: var(--sev-info); }}
 .status-warning {{ color: var(--sev-med); }}
 .status-danger {{ color: var(--sev-high); }}
 .text-high {{ color: var(--sev-high); }}
 .text-med {{ color: var(--sev-med); }}
 .text-low {{ color: var(--sev-low); }}

 .finding-card {{
   background: #ffffff;
   border: 1px solid var(--card-border);
   border-radius: var(--radius);
   padding: 1.35rem;
   margin-bottom: 1rem;
   box-shadow: 0 1px 3px rgba(0,0,0,0.05);
 }}
 .finding-header {{
   display: flex;
   align-items: center;
   gap: 0.6rem;
   margin-bottom: 0.6rem;
   flex-wrap: wrap;
 }}
 .finding-title {{ font-size: 1.12rem; font-weight: 700; color: var(--text-primary); }}
 .sev-badge {{
   font-size: 0.72rem;
   font-weight: 700;
   padding: 0.2rem 0.55rem;
   border-radius: 6px;
   color: #fff;
   text-transform: uppercase;
 }}
 .sev-high {{ background: var(--sev-high); }}
 .sev-medium {{ background: var(--sev-med); }}
 .sev-low {{ background: var(--sev-low); color: #fff; }}
 .sev-info {{ background: var(--sev-info); }}

 .tags-badge {{
   font-size: 0.78rem;
   background: #f1f5f9;
   padding: 0.2rem 0.5rem;
   border-radius: 6px;
   color: var(--text-muted);
   border: 1px solid var(--card-border);
 }}
 .finding-detail {{
   color: var(--text-secondary);
   font-size: 0.95rem;
   line-height: 1.6;
   margin-bottom: 0.75rem;
 }}
 .finding-context {{
   font-size: 0.85rem;
   color: var(--accent-primary);
   font-weight: 600;
   margin-bottom: 0.6rem;
 }}
 .fix-box {{
   background: #f0fdf4;
   border: 1px solid #bbf7d0;
   padding: 0.75rem 1rem;
   border-radius: 8px;
   font-size: 0.92rem;
   color: #166534;
   margin-bottom: 0.75rem;
 }}
 .citations-wrapper {{
   margin-top: 0.75rem;
   padding-top: 0.75rem;
   border-top: 1px dashed var(--card-border);
   font-size: 0.88rem;
   color: var(--text-muted);
 }}
 .citation-box {{
   background: #f8fafc;
   border: 1px solid var(--card-border);
   border-radius: 8px;
   padding: 0.85rem 1rem;
   margin-top: 0.5rem;
 }}
 .citation-head {{
   display: flex;
   justify-content: space-between;
   align-items: center;
   gap: 0.5rem;
   flex-wrap: wrap;
   margin-bottom: 0.35rem;
 }}
 .citation-title {{ font-weight: 700; color: var(--text-primary); }}
 .citation-auth {{ font-size: 0.82rem; color: var(--accent-primary); font-weight: 600; }}
 .citation-link {{ color: var(--accent-primary); text-decoration: none; font-size: 0.82rem; font-weight: 600; }}
 .citation-passage {{ font-style: italic; color: var(--text-secondary); font-size: 0.9rem; }}

  footer {{
    margin-top: 3rem;
    text-align: center;
    color: var(--text-muted);
    font-size: 0.85rem;
    border-top: 1px solid var(--card-border);
    padding-top: 1.5rem;
  }}
  @media print {{
    body {{
      background: #ffffff !important;
      color: #0f172a !important;
      font-size: 11pt !important;
      padding: 0.5in !important;
    }}
    .no-print {{ display: none !important; }}
    .card, .finding-card, .metric-card {{
      background: #ffffff !important;
      border: 1px solid #cbd5e1 !important;
      color: #0f172a !important;
      page-break-inside: avoid;
    }}
    .text-high {{ color: #dc2626 !important; }}
    .text-med {{ color: #d97706 !important; }}
    .text-low {{ color: #16a34a !important; }}
    .citation-box, pre {{
      background: #f8fafc !important;
      border: 1px solid #e2e8f0 !important;
      color: #1e293b !important;
    }}
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
      <button type="button" class="no-print" onclick="window.print()" style="margin-top:0.4rem; padding:0.35rem 0.75rem; background:var(--accent-primary); color:#fff; border:none; border-radius:4px; font-weight:600; cursor:pointer; font-size:0.82rem;">🖨️ Export PDF / Print</button>
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
