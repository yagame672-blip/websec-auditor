"""OWASP Top 10:2021 assessment - per-category scorecard built from scan
findings (and static code-review / dependency-scan findings).

Each finding maps to a category by its `owasp` tag, falling back to a CWE
lookup against config.OWASP_TOP10. The scorecard gives a target owner an
at-a-glance "which of the Top 10 does this app fail on" summary, grounded in
the same standards the findings cite.
"""
from __future__ import annotations
import html

from websec_auditor import config


def _category_for(finding):
    owasp = (finding.get("owasp") or "").upper()
    if owasp in config.OWASP_TOP10:
        return owasp
    cwe = finding.get("cwe") or ""
    for cat, (_, cwes) in config.OWASP_TOP10.items():
        if cwe in cwes:
            return cat
    return None


def _status_for(counts):
    if counts["high"] > 0:
        return "fail"
    if counts["medium"] > 0 or counts["low"] > 0:
        return "warn"
    if counts["info"] > 0:
        return "ok"
    return "na"


def scorecard(enriched):
    """Aggregate enriched findings (list of {"finding": {...}, "citations": [...]})
    into an OWASP Top 10 scorecard dict keyed by A01..A10.

    Non-Top-10 findings (unmapped CWE/OWASP) are tallied under "other".
    """
    rows = {cat: {"title": title, "counts": {"high": 0, "medium": 0, "low": 0, "info": 0},
                  "findings": [], "cwes": []}
            for cat, (title, _) in config.OWASP_TOP10.items()}
    rows["other"] = {"title": "Unmapped (not in Top 10)", "counts": {"high": 0, "medium": 0, "low": 0, "info": 0},
                     "findings": [], "cwes": []}

    for e in enriched:
        f = e.get("finding", {})
        sev = (f.get("severity") or "info").lower()
        cat = _category_for(f)
        row = rows[cat] if cat else rows["other"]
        row["counts"][sev] = row["counts"].get(sev, 0) + 1
        if f.get("cwe") and f["cwe"] not in row["cwes"]:
            row["cwes"].append(f["cwe"])
        row["findings"].append({"name": f.get("name"), "severity": sev,
                                "cwe": f.get("cwe"), "owasp": f.get("owasp")})

    ordered = {cat: rows[cat] for cat in config.OWASP_TOP10}
    ordered["other"] = rows["other"]
    for cat, row in ordered.items():
        row["status"] = _status_for(row["counts"])
        row["score"] = (row["counts"]["high"] * 5 + row["counts"]["medium"] * 3
                        + row["counts"]["low"] * 1 + row["counts"]["info"] * 0)
    return ordered


def render_text(sc):
    lines = ["OWASP TOP 10 :2021 ASSESSMENT"]
    lines.append("-" * 64)
    for cat, row in sc.items():
        if cat == "other" and row["counts"] == {"high": 0, "medium": 0, "low": 0, "info": 0}:
            continue
        c = row["counts"]
        lines.append(f"  {cat}  {row['status'].upper():<4}  {row['title']}  "
                     f"[high {c['high']} | med {c['medium']} | low {c['low']}]")
        if row["cwes"]:
            lines.append(f"      CWEs: {', '.join(sorted(set(row['cwes'])))}")
    lines.append("-" * 64)
    lines.append("Status: FAIL = high findings | WARN = medium/low | OK = info only | NA = untested")
    return "\n".join(lines)


_SEV_COLOR = {"high": "#ef4444", "medium": "#f59e0b", "low": "#eab308", "info": "#10b981"}
_STATUS_BADGE = {"fail": "FAIL", "warn": "WARN", "ok": "OK", "na": "N/A"}


def render_html(sc):
    """Self-contained <section> fragment for embedding in the web UI result page."""
    rows = []
    for cat, row in sc.items():
        if cat == "other" and row["counts"] == {"high": 0, "medium": 0, "low": 0, "info": 0}:
            continue
        c = row["counts"]
        badge = _STATUS_BADGE.get(row["status"], "N/A")
        color = "#64748b"
        if row["status"] == "fail":
            color = _SEV_COLOR["high"]
        elif row["status"] == "warn":
            color = _SEV_COLOR["medium"]
        elif row["status"] == "ok":
            color = _SEV_COLOR["info"]
        bars = "".join(
            f'<div class="owasp-bar" style="background:{_SEV_COLOR[sev]};width:{cnt * 8 + 4}px" '
            f'title="{sev}: {cnt}"></div>'
            for sev, cnt in (("high", c["high"]), ("medium", c["medium"]),
                             ("low", c["low"]), ("info", c["info"]))
            if cnt)
        rows.append(
            f'<tr><td class="owasp-cat">{html.escape(cat)}</td>'
            f'<td>{html.escape(row["title"])}</td>'
            f'<td><span class="owasp-badge" style="background:{color}">{badge}</span></td>'
            f'<td class="owasp-bars">{bars}</td>'
            f'<td class="owasp-cwes">{", ".join(html.escape(c) for c in sorted(set(row["cwes"])))}</td></tr>')
    if not rows:
        return ""
    return f"""
<section class="owasp-section">
  <h2>OWASP Top 10 :2021 Assessment</h2>
  <table class="owasp-table">
    <thead><tr><th>Cat</th><th>Category</th><th>Status</th><th>Severity mix</th><th>CWEs observed</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <p class="owasp-note">Status: <b>FAIL</b> = high-risk finding in category &middot; <b>WARN</b> = medium/low
  &middot; <b>OK</b> = info only &middot; <b>N/A</b> = not tested. Findings are grounded in the cited book/standard passages.</p>
</section>"""


def owasp_css():
    return """
.owasp-section { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: var(--radius); padding: 1.25rem; margin: 1rem 0; }
.owasp-section h2 { font-size: 1.05rem; margin-bottom: 0.75rem; }
.owasp-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
.owasp-table th, .owasp-table td { text-align: left; padding: 0.45rem 0.6rem; border-bottom: 1px solid var(--card-border); }
.owasp-table th { color: var(--text-muted); text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; }
.owasp-cat { font-weight: 700; color: var(--accent-primary); }
.owasp-badge { color: #fff; font-size: 0.68rem; font-weight: 700; padding: 0.15rem 0.4rem; border-radius: 4px; }
.owasp-bars { white-space: nowrap; }
.owasp-bar { display: inline-block; height: 10px; margin-right: 2px; border-radius: 2px; }
.owasp-cwes { color: var(--text-muted); }
.owasp-note { color: var(--text-muted); font-size: 0.75rem; margin-top: 0.6rem; }
"""
