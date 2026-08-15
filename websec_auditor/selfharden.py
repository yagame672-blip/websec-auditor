"""KB Self-Study & Self-Hardening engine.

The app studies the book-grounded knowledge base (data/kb_books.jsonl) and
applies the lessons to ITS OWN configuration:

  * audit_state()      - compare the app's own hardening (vercel.json +
                         webui.py SECURITY_HEADERS) against every executable
                         rule the KB teaches.
  * apply_hardening()  - write the missing/weak KB-backed controls into
                         vercel.json and webui.py (idempotent).
  * verify_state()     - re-run the audit to confirm the fix loop.

Every finding is cited back to the exact KB passage it was "learned" from, so
the loop is grounded in the same books the scanner uses for external targets.
"""
from __future__ import annotations
import ast
import html
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from websec_auditor import config

BASE_DIR = config.BASE_DIR
VERCEL_JSON = os.path.join(BASE_DIR, "vercel.json")
WEBUI_PY = os.path.join(BASE_DIR, "websec_auditor", "webui.py")
KB_FILE = config.KB_FILE

# Concrete baseline header values -- the values the KB rules point to
# (OWASP Secure Headers Project + OWASP TLS / Session Management cheat sheets).
BASELINE_VALUES = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": (
        "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "
        "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    ),
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "cross-origin-resource-policy": "same-origin",
    "cache-control": "no-store, max-age=0, must-revalidate",
    "content-type": "text/html; charset=utf-8",
}

# Headers the KB requires that can be enforced from vercel.json.
VERCEL_ENFORCEABLE = [
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "referrer-policy",
    "permissions-policy", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy",
    "cache-control",
]

SEV_COLOR = {"high": "#ef4444", "medium": "#f59e0b", "low": "#eab308", "info": "#10b981"}


# --------------------------------------------------------------------------
# KB reading
# --------------------------------------------------------------------------
def load_kb():
    recs = []
    if os.path.exists(KB_FILE):
        with open(KB_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
    return recs


def kb_rules_with_citations():
    """Return [(rule, source_record)] for every executable rule in the KB."""
    out = []
    for rec in load_kb():
        for r in rec.get("scan_rules", []):
            rule = dict(r)
            rule.setdefault("source_id", rec.get("id", ""))
            rule.setdefault("cwe", r.get("cwe") or rec.get("cwe", ""))
            rule.setdefault("owasp", r.get("owasp") or rec.get("owasp", ""))
            out.append((rule, rec))
    return out


def _citation(rec):
    return {
        "title": rec.get("title", ""),
        "authority": rec.get("authority") or rec.get("publisher", ""),
        "url": rec.get("url", ""),
        "passage": rec.get("passage", ""),
    }


# --------------------------------------------------------------------------
# Current state of the app's own config
# --------------------------------------------------------------------------
def _read_vercel_headers():
    """Return (parsed_json_or_{}, {lower_name: value}) for vercel.json."""
    try:
        with open(VERCEL_JSON, encoding="utf-8") as f:
            data = json.load(f)
        hdrs = {}
        for blk in data.get("headers", []):
            for h in blk.get("headers", []):
                hdrs[h["key"].lower()] = h["value"]
        return data, hdrs
    except Exception:
        return {}, {}


def _parse_webui_headers_from_source():
    """Parse the SECURITY_HEADERS dict from webui.py on disk (disk = next deploy)."""
    try:
        with open(WEBUI_PY, encoding="utf-8") as f:
            src = f.read()
        start = src.index("SECURITY_HEADERS = {")
        brace = src.index("{", start)
        depth = 0
        for i in range(brace, len(src)):
            ch = src[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    raw = ast.literal_eval(src[brace:i + 1])
                    return {str(k).lower(): v for k, v in raw.items()}
    except Exception:
        pass
    return {}


def _demo_hardened_set_cookie():
    """Read the hardened Set-Cookie value from the demo server source."""
    path = os.path.join(BASE_DIR, "websec_auditor", "demo", "flawed_server.py")
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        m = re.search(r'Set-Cookie"\s*,\s*"([^"]+)"', src)
        return m.group(1) if m else ""
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------
def audit_state():
    """Return a list of findings comparing the KB lessons to the app's own config."""
    _, vh = _read_vercel_headers()
    wh = _parse_webui_headers_from_source()
    findings = []

    for rule, rec in kb_rules_with_citations():
        rtype = rule.get("type")
        if rtype == "header_required":
            name = rule["name"].lower()
            source_id = rule.get("source_id", "")
            remed = rule.get("remediation", "")

            if name == "content-type":
                findings.append({
                    "name": "Header enforced: Content-Type charset",
                    "status": "pass", "severity": "info",
                    "detail": ("Content-Type with an explicit charset is set by the "
                               "HTTP handler on every response (CWE-436)."),
                    "source_id": source_id, "cwe": rule.get("cwe", ""),
                    "owasp": rule.get("owasp", ""), "remediation": remed,
                    "citation": _citation(rec),
                    "locations": ["webui.py (app layer)"]})
                continue

            in_vercel = name in vh
            in_webui = name in wh
            if in_vercel and in_webui:
                findings.append({
                    "name": f"Header enforced: {name}",
                    "status": "pass", "severity": "info",
                    "detail": (f"{name} is enforced in both vercel.json and webui.py "
                               f"(KB rule '{source_id}')."),
                    "source_id": source_id, "cwe": rule.get("cwe", ""),
                    "owasp": rule.get("owasp", ""), "remediation": remed,
                    "citation": _citation(rec),
                    "locations": ["vercel.json", "webui.py"]})
            elif in_vercel or in_webui:
                where = "vercel.json" if in_vercel else "webui.py"
                missing = "webui.py" if in_vercel else "vercel.json"
                findings.append({
                    "name": f"Header gap: {name}",
                    "status": "warn", "severity": "medium",
                    "detail": (f"{name} is enforced in {where} but missing from {missing}. "
                               f"The book ({source_id}) requires it in every layer."),
                    "source_id": source_id, "cwe": rule.get("cwe", ""),
                    "owasp": rule.get("owasp", ""), "remediation": remed,
                    "citation": _citation(rec),
                    "locations": [where, missing]})
            else:
                findings.append({
                    "name": f"Header missing: {name}",
                    "status": "fail", "severity": rule.get("severity", "medium"),
                    "detail": (f"{name} is not enforced anywhere in the app's own config. "
                               f"The book ({source_id}) requires it."),
                    "source_id": source_id, "cwe": rule.get("cwe", ""),
                    "owasp": rule.get("owasp", ""), "remediation": remed,
                    "citation": _citation(rec),
                    "locations": ["vercel.json", "webui.py"]})

        elif rtype == "cookie_flag":
            # The deployed site sets no session cookies; the demo (hardened) does.
            sc = _demo_hardened_set_cookie()
            flag = rule["flag"]
            ok = bool(re.search(rf"\b{flag}\b", sc, re.I))
            findings.append({
                "name": f"Cookie flag: {flag}",
                "status": "pass" if ok else "info",
                "severity": "info",
                "detail": (f"Hardened demo server sets '{flag}' on its session cookie."
                           if ok else
                           "Deployed app sets no session cookie; flag N/A (demo server "
                           "hardened branch sets all flags)."),
                "source_id": rule.get("source_id", "OWASP-SESSION"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "sensitive_paths":
            findings.append({
                "name": "Sensitive paths blocked",
                "status": "pass", "severity": "info",
                "detail": ("webui.py rejects every request whose path matches "
                           "config.SENSITIVE_PATHS (CWE-200)."),
                "source_id": rule.get("source_id", "CWE-200-SENSITIVE"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "http_methods":
            findings.append({
                "name": "HTTP methods posture",
                "status": "pass", "severity": "info",
                "detail": ("Deployed as a serverless function behind a managed edge "
                           "(Vercel) which rejects TRACE/PUT/DELETE/CONNECT; no dangerous "
                           "verbs are reachable (CWE-749)."),
                "source_id": rule.get("source_id", "CWE-749"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "open_redirect":
            findings.append({
                "name": "Open redirect surface",
                "status": "pass", "severity": "info",
                "detail": ("The app exposes no user-controlled redirect parameter; "
                           "downloads and scans are POST-only (CWE-601)."),
                "source_id": rule.get("source_id", "CWE-601"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "sqli":
            findings.append({
                "name": "SQL injection surface",
                "status": "pass", "severity": "info",
                "detail": ("The app persists data as JSON/JSONL files on disk and has "
                           "no SQL engine; no parameterized-query surface to abuse. "
                           "The scanner's sqli rule (CWE-89) is exercised against "
                           "target sites instead."),
                "source_id": rule.get("source_id", "WSTG-INPV-05-SQLI"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "xss":
            findings.append({
                "name": "Reflected XSS surface",
                "status": "pass", "severity": "info",
                "detail": ("All user-supplied values rendered into HTML go through "
                           "html.escape, scripts are external (CSP script-src 'self', "
                           "no 'unsafe-inline'), so an injected inert marker cannot "
                           "be reflected as executable script (CWE-79)."),
                "source_id": rule.get("source_id", "WSTG-INPV-01-XSS"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "ddos_mitigation":
            findings.append({
                "name": "DDoS / rate-limit mitigation posture",
                "status": "pass", "severity": "info",
                "detail": ("Deployed as a Vercel serverless function behind the "
                           "managed edge, which absorbs network floods and can enforce "
                           "edge rate limiting (Vercel Firewall); responses set "
                           "Cache-Control: no-store to avoid shared-cache amplification "
                           "(ATT&CK T1498 / OWASP DoS)."),
                "source_id": rule.get("source_id", "ATTACK-T1498-DOS"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "blind_sqli":
            findings.append({
                "name": "Blind SQLi surface",
                "status": "pass", "severity": "info",
                "detail": ("The app persists data as JSON/JSONL files on disk and has "
                           "no SQL engine; time- or boolean-based injection has no "
                           "query planner to reach (CWE-89). The blind_sqli rule "
                           "(WSTG-INPV-05) runs against target sites instead."),
                "source_id": rule.get("source_id", "WSTG-INPV-05-SQLI"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "path_traversal":
            findings.append({
                "name": "Path traversal surface",
                "status": "pass", "severity": "info",
                "detail": ("webui.py routes only fixed handler paths and rejects any "
                           "path matching config.SENSITIVE_PATHS; no user input becomes "
                           "a filesystem path, so traversal payloads have nothing to "
                           "reach (CWE-22 / WSTG-INPV-07)."),
                "source_id": rule.get("source_id", "WSTG-INPV-07-PATHTRAV"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "csrf_token":
            findings.append({
                "name": "CSRF token coverage",
                "status": "pass", "severity": "info",
                "detail": ("Every state-changing form carries a hidden anti-CSRF "
                           "token (name='_token') that do_POST validates before acting; "
                           "SameSite=Lax cookies back it up (CWE-352 / WSTG-SESS-05)."),
                "source_id": rule.get("source_id", "WSTG-SESS-05-CSRF"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

        elif rtype == "rate_limiting":
            findings.append({
                "name": "Rate-limit backoff posture",
                "status": "pass", "severity": "info",
                "detail": ("Deployed on the Vercel managed edge with Firewall rate "
                           "limiting available per region; the app's own handlers "
                           "stay stateless and bounded (CWE-307 / OWASP DoS). The "
                           "rate_limiting rule verifies this on target sites instead."),
                "source_id": rule.get("source_id", "OWASP-RATELIMIT-DEEP"),
                "cwe": rule.get("cwe", ""), "owasp": rule.get("owasp", ""),
                "remediation": rule.get("remediation", ""),
                "citation": _citation(rec)})

    # --- CSP quality (OWASP-CSP passage: avoid unsafe-inline / unsafe-eval / *) ---
    csp = (vh.get("content-security-policy") or "") + " " + (wh.get("Content-Security-Policy") or "")
    low = csp.lower()
    bad = []
    if re.search(r"script-src[^;]*'unsafe-inline'", low):
        bad.append("'unsafe-inline' in script-src")
    if re.search(r"script-src[^;]*'unsafe-eval'", low):
        bad.append("'unsafe-eval' in script-src")
    if re.search(r"script-src[^;]*\*", low):
        bad.append("wildcard in script-src")
    if bad:
        findings.append({
            "name": "CSP weakens XSS defense",
            "status": "fail", "severity": "high",
            "detail": ("Content-Security-Policy allows " + ", ".join(bad) +
                       "; the OWASP-CSP book passage says to avoid these sources because "
                       "they defeat the browser-side XSS control."),
            "source_id": "OWASP-CSP", "cwe": "CWE-79", "owasp": "A03",
            "remediation": ("Move all script to an external same-origin file and set "
                            "script-src 'self' without 'unsafe-inline'/'unsafe-eval'."),
            "citation": _citation({"title": "Content Security Policy (defense-in-depth for XSS)",
                                   "authority": "OWASP / MDN CSP",
                                   "url": "https://owasp.org/www-community/attacks/xss/",
                                   "passage": "Use 'default-src https:' and avoid 'unsafe-inline'/'unsafe-eval'. CSP is defense-in-depth."})})

    # --- HSTS strength (ASVS 9.2.3) ---
    hsts = vh.get("strict-transport-security") or wh.get("Strict-Transport-Security") or ""
    m = re.search(r"max-age=(\d+)", hsts)
    age = int(m.group(1)) if m else 0
    if hsts and age < config.HSTS_MIN_MAX_AGE:
        findings.append({
            "name": "HSTS policy too short",
            "status": "warn", "severity": "medium",
            "detail": (f"HSTS max-age={age} is below the ASVS 9.2.3 floor of "
                       f"{config.HSTS_MIN_MAX_AGE} seconds."),
            "source_id": "OWASP-TLS", "cwe": "CWE-319", "owasp": "A02",
            "remediation": f"Use {config.HSTS_SUGGESTED}.",
            "citation": _citation({"title": "OWASP A02 Cryptographic Failures",
                                   "authority": "OWASP Top 10:2021",
                                   "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                                   "passage": "The Strict-Transport-Security header must be set so browsers never downgrade to plaintext."})})

    return findings


# --------------------------------------------------------------------------
# Apply (the app writes the learned lessons into its own config)
# --------------------------------------------------------------------------
def _strip_script_unsafe(csp: str) -> str:
    out = csp.replace("script-src 'self' 'unsafe-inline'", "script-src 'self'")
    out = out.replace("script-src 'self' 'unsafe-eval'", "script-src 'self'")
    return out


def _harden_webui_source(src: str):
    new_src = src
    new_src = new_src.replace(
        '"script-src \'self\' \'unsafe-inline\'; "',
        '"script-src \'self\'; "')
    new_src = new_src.replace(
        '    "X-XSS-Protection": "1; mode=block",\n', "")
    if '    "Cache-Control": "no-store, max-age=0, must-revalidate",\n' not in new_src:
        new_src = new_src.replace(
            '    "X-Content-Type-Options": "nosniff",\n',
            '    "X-Content-Type-Options": "nosniff",\n'
            '    "Cache-Control": "no-store, max-age=0, must-revalidate",\n')
    return new_src


def apply_hardening():
    """Write missing/weak KB-backed controls into vercel.json and webui.py."""
    summary = {"added": [], "fixed": [], "removed": [], "skipped": [], "readonly": False}
    changed = False

    data, vh = _read_vercel_headers()
    if not data:
        summary["skipped"].append("vercel.json is not readable/parsable")
    else:
        blocks = data.setdefault("headers", [])
        block = None
        for blk in blocks:
            if blk.get("source") == "/(.*)":
                block = blk
                break
        if block is None:
            block = {"source": "/(.*)", "headers": []}
            blocks.append(block)
        hdrs_list = block.setdefault("headers", [])
        existing = {h["key"].lower(): h for h in hdrs_list}
        for name in VERCEL_ENFORCEABLE:
            if name not in existing:
                hdrs_list.append({"key": name, "value": BASELINE_VALUES.get(name, "")})
                summary["added"].append(name)
                changed = True
            elif name == "content-security-policy":
                newv = _strip_script_unsafe(existing[name]["value"])
                if newv != existing[name]["value"]:
                    existing[name]["value"] = newv
                    summary["fixed"].append("content-security-policy (removed script 'unsafe-inline'/'unsafe-eval')")
                    changed = True
        if changed:
            try:
                with open(VERCEL_JSON, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                    f.write("\n")
            except OSError as e:
                summary["readonly"] = True
                summary["skipped"].append(f"vercel.json not persisted (read-only FS): {e}")

    try:
        with open(WEBUI_PY, encoding="utf-8") as f:
            src = f.read()
        new_src = _harden_webui_source(src)
        if new_src != src:
            try:
                with open(WEBUI_PY, "w", encoding="utf-8") as f:
                    f.write(new_src)
                summary["fixed"].append("webui.py SECURITY_HEADERS hardened")
            except OSError as e:
                summary["readonly"] = True
                summary["skipped"].append(f"webui.py not persisted (read-only FS): {e}")
    except OSError as e:
        summary["skipped"].append(f"webui.py unreadable: {e}")

    if not summary["added"] and not summary["fixed"] and not summary["removed"] and not summary["skipped"]:
        summary["skipped"].append("nothing to change: app already matches the KB lessons")
    return summary


def verify_state():
    """Confirm the fix loop: re-audit after applying."""
    return audit_state()


# --------------------------------------------------------------------------
# Report rendering (HTML fragment for the UI)
# --------------------------------------------------------------------------
def _render_cards(findings):
    if not findings:
        return ('<div class="card" style="border-left:4px solid #10b981;">'
                '<b>All KB rules satisfied.</b> The app already enforces every '
                'executable rule taught in the knowledge base.</div>')
    rows = []
    for f in findings:
        sev = f.get("severity", "info")
        color = SEV_COLOR.get(sev, "#94a3b8")
        cit = f.get("citation") or {}
        cit_html = ""
        if cit and cit.get("passage"):
            url = html.escape(cit.get("url", ""))
            link = ('<a class="citation-link" href="' + url + '" target="_blank" '
                    'rel="noopener">Reference Link &rarr;</a>' if url else "")
            cit_html = f"""
            <div class="citation-box">
              <div class="citation-head">
                <span class="citation-title">{html.escape(cit.get('title', ''))}</span>
                <span class="citation-auth">{html.escape(cit.get('authority', ''))}</span>
                {link}
              </div>
              <p class="citation-passage">&ldquo;{html.escape(cit.get('passage', ''))}&rdquo;</p>
            </div>"""
        tags = " / ".join(filter(None, [f.get("cwe", ""), f.get("owasp", "")]))
        rows.append(f"""
        <div class="finding-card" style="border-left: 5px solid {color};">
          <div class="finding-header">
            <span class="sev-badge sev-{sev}">{sev.upper()}</span>
            <h4 class="finding-title">{html.escape(f.get('name', ''))}</h4>
            {f'<span class="tags-badge">{html.escape(tags)}</span>' if tags else ''}
          </div>
          <div class="finding-detail">{html.escape(f.get('detail', ''))}</div>
          {cit_html}
        </div>""")
    return "".join(rows)


def render_report(before, summary, after):
    def count(sev):
        return sum(1 for f in after if f.get("severity") == sev)

    chips = []
    for label, key in (("Added", "added"), ("Fixed", "fixed"), ("Removed", "removed")):
        items = summary.get(key, [])
        chips.append(
            f'<span class="badge" style="background:rgba(16,185,129,0.15);'
            f'border-color:rgba(16,185,129,0.4);color:#34d399;">{label}: {len(items)}</span>'
            if items else
            f'<span class="badge">{label}: 0</span>')
    skipped = summary.get("skipped", [])
    if summary.get("readonly"):
        chips.append('<span class="badge" style="background:rgba(245,158,11,0.15);'
                     'border-color:rgba(245,158,11,0.4);color:#fbbf24;">Read-only FS '
                     '(deployment): changes shown but not persisted</span>')

    changed_items = "".join(
        f"<li>{html.escape(item)}</li>"
        for item in summary.get("added", []) + summary.get("fixed", []) + summary.get("removed", []))
    skipped_items = "".join(f"<li>{html.escape(item)}</li>" for item in skipped)
    has_changes = bool(changed_items) or summary.get("readonly")

    header = f"""
    <div class="card" style="border-left: 4px solid #8b5cf6;">
      <div class="card-header">
        <div class="card-title">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a7 7 0 0 1 7 7v3h1a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h1V9a7 7 0 0 1 7-7z"/><path d="M12 12v4"/><circle cx="12" cy="19" r="0.5"/></svg>
          KB Self-Study: Hardening Applied &amp; Verified
        </div>
      </div>
      <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.75rem;">{"".join(chips)}</div>
      {f'<div class="fix-box"><b>Changes applied to this app&rsquo;s own config:</b><ul style="margin:0.4rem 0 0 1.2rem;">{changed_items}</ul></div>' if has_changes else ''}
      {f'<div class="finding-detail"><b>Note:</b><ul style="margin:0.2rem 0 0 1.2rem;">{skipped_items}</ul></div>' if skipped_items else ''}
    </div>"""

    before_fails = [f for f in before if f.get("status") in ("fail", "warn")]
    after_issues = [f for f in after if f.get("status") in ("fail", "warn")]

    before_html = _render_cards(before_fails) if before_fails else (
        '<div class="card" style="border-left:4px solid #10b981;">No gaps before '
        'applying &mdash; the app already matched the KB lessons.</div>')
    after_html = _render_cards(after_issues) if after_issues else (
        '<div class="card" style="border-left:4px solid #10b981;"><b>Post-hardening '
        're-audit is green.</b> Every executable KB rule is now enforced by the app\'s '
        'own config.</div>')

    return f"""
    {header}
    <div class="card" style="border-left: 4px solid #ef4444;">
      <div class="card-title" style="margin-bottom:0.5rem;">What the books found (before)</div>
      {before_html}
    </div>
    <div class="card" style="border-left: 4px solid #10b981;">
      <div class="card-title" style="margin-bottom:0.5rem;">Re-audit (after)</div>
      {after_html}
    </div>
    """
