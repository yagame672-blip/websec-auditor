"""Fix generator: turn scanner findings into concrete, deployable remediations.

Two modes:
  * apply_demo_fix()  -> writes data/demo_fixstate.json so the bundled demo
    server runs HARDENED (proves the fix loop on a site we own).
  * build_bundle(findings) -> a dict of remediation artifacts a user can deploy
    on THEIR OWN server (nginx / Apache / Flask / Express). We generate config,
    we never reach into a remote host.

Each artifact is grounded in the same standards (CWE/OWASP/ASVS) as the KB.
"""
from __future__ import annotations
import json
import os

from websec_auditor import config

FIXSTATE_FILE = os.path.join(config.DATA_DIR, "demo_fixstate.json")


# --------------------------------------------------------------------------
# Demo fixstate (proves the loop on a site we own)
# --------------------------------------------------------------------------
def apply_demo_fix() -> dict:
    state = {"hardened": True}
    try:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        with open(FIXSTATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except OSError as e:
        # Deployed / read-only filesystem: record the failure so callers can
        # report it instead of crashing the request handler.
        raise OSError(f"could not write {FIXSTATE_FILE}: {e}") from e
    return state


def demo_is_hardened() -> bool:
    try:
        with open(FIXSTATE_FILE, encoding="utf-8") as f:
            return bool(json.load(f).get("hardened"))
    except Exception:
        return False


def reset_demo_fix():
    """Return the demo to FLAWED state (the intended default for the proof loop)."""
    state = {"hardened": False}
    try:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        with open(FIXSTATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except OSError as e:
        raise OSError(f"could not write {FIXSTATE_FILE}: {e}") from e
    return state


# --------------------------------------------------------------------------
# Remediation snippets keyed by the finding 'name' (matches scanner output)
# --------------------------------------------------------------------------
HEADER_NAME_MAP = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}

HEADER_VAL_MAP = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "cross-origin-resource-policy": "same-origin",
}

COOKIE_FLAGS = "Secure; HttpOnly; SameSite=Lax"


def build_bundle(enriched):
    """Return {'nginx':..., 'apache':..., 'flask':..., 'express':..., 'notes':[...]}."""
    missing_headers = []
    cookie_missing = False
    xss = False
    sqli = False
    blind_sqli = False
    traversal = False
    open_redirect = False
    csrf_forms = False
    weak_csp = False
    cors = False
    plaintext = False
    disclosure = False
    cacheable = False
    dirlist = False
    for e in enriched:
        f = e["finding"]
        n = f["name"]
        chk = f.get("check", "")
        if n.startswith("Missing header:"):
            h = n.split(":", 1)[1].strip()
            missing_headers.append(h)
        elif n.startswith("Missing cookie flag:"):
            cookie_missing = True
        elif chk == "xss" and f.get("status") == "fail":
            xss = True
        elif chk == "sqli" and f.get("status") == "fail":
            sqli = True
        elif chk == "blind_sqli" and f.get("status") == "fail":
            blind_sqli = True
        elif chk == "path_traversal" and f.get("status") == "fail":
            traversal = True
        elif chk == "open_redirect" and f.get("status") == "fail":
            open_redirect = True
        elif chk == "csrf_token" and f.get("status") == "fail":
            csrf_forms = True
        elif n == "Weak CSP directives":
            weak_csp = True
        elif n.startswith("Overly permissive CORS"):
            cors = True
        elif n == "Plaintext HTTP transport":
            plaintext = True
        elif n.startswith("Technology disclosure") and f.get("status") in ("fail", "warn"):
            disclosure = True
        elif n == "Session response is cacheable":
            cacheable = True
        elif n == "Directory listing exposed":
            dirlist = True

    # Deduplicate missing_headers while preserving order
    seen_h = set()
    deduped_headers = []
    for h in missing_headers:
        if h not in seen_h:
            seen_h.add(h)
            deduped_headers.append(h)
    missing_headers = deduped_headers

    # Render missing headers, or full KB baseline security headers if empty
    render_headers = missing_headers if missing_headers else list(HEADER_VAL_MAP.keys())

    nginx_headers = "\n".join(
        f'    add_header {HEADER_NAME_MAP.get(h, h)} "{HEADER_VAL_MAP.get(h, "")}" always;'
        for h in render_headers if h in HEADER_VAL_MAP
    )
    apache_headers = "\n".join(
        f'    Header always set {HEADER_NAME_MAP.get(h, h)} "{HEADER_VAL_MAP.get(h, "")}"'
        for h in render_headers if h in HEADER_VAL_MAP
    )
    flask_headers = "\n".join(
        f'    resp.headers["{HEADER_NAME_MAP.get(h, h)}"] = "{HEADER_VAL_MAP.get(h, "")}"'
        for h in render_headers if h in HEADER_VAL_MAP
    )
    express_headers = "\n".join(
        f'  res.setHeader("{HEADER_NAME_MAP.get(h, h)}", "{HEADER_VAL_MAP.get(h, "")}");'
        for h in render_headers if h in HEADER_VAL_MAP
    )

    nginx = f"""# websec-auditor remediation (deploy on YOUR OWN server)
server {{
    # ... existing server block ...
{nginx_headers}
    # Cookie hardening: set flags on your session cookie, e.g. in your app:
    # Set-Cookie: sessionid=...; {COOKIE_FLAGS}
}}"""

    apache = f"""# websec-auditor remediation (deploy on YOUR OWN server)
<IfModule mod_headers.c>
{apache_headers}
</IfModule>
# Cookie hardening: in your app set session cookie with: {COOKIE_FLAGS}"""

    flask = f"""# websec-auditor remediation (Flask example, YOUR OWN app)
from flask import Flask, make_response
app = Flask(__name__)

@app.after_request
def secure_headers(resp):
{flask_headers}
    # Cookie hardening
    for name in list(resp.headers.keys()):
        if name.lower() == 'set-cookie' and 'sessionid' in resp.headers[name].lower():
            resp.headers[name] = resp.headers[name] + "; {COOKIE_FLAGS}"
    return resp"""

    express = f"""// websec-auditor remediation (Express example, YOUR OWN app)
app.use((req, res, next) => {{
{express_headers}
  // Cookie hardening: use cookie-session / express-session with:
  //   secure: true, httpOnly: true, sameSite: 'lax'
  next();
}});"""

    notes = []
    if xss:
        notes.append("XSS surface: HTML-escape all reflected output (e.g. "
                     "markupsafe.escape / context-aware encoding) and keep the CSP above.")
    if sqli:
        notes.append("SQL error leaked: disable verbose DB errors in production "
                     "and use parameterized queries (prepared statements).")
    if blind_sqli:
        notes.append("Blind SQLi suspected (timing/boolean): use parameterized "
                     "queries and disable DB error output; run a manual "
                     "authorized test to confirm the injection point.")
    if traversal:
        notes.append("Path traversal / LFI: validate and canonicalize file "
                     "parameters (reject '..' and absolute paths), serve files "
                     "from a fixed root via a whitelist, never from user input.")
    if open_redirect:
        notes.append("Open redirect: never redirect to a user-supplied URL "
                     "verbatim; validate it against an allow-list of trusted "
                     "origins and require an explicit safe path.")
    if csrf_forms:
        notes.append("State-changing form lacks a CSRF token: add a per-session "
                     "token (double-submit or synchronizer pattern) and validate "
                     "it server-side on every POST/PUT/DELETE.")
    if weak_csp:
        notes.append("Weak CSP: remove unsafe-inline / unsafe-eval / wildcard "
                     "sources and add frame-ancestors 'none'.")
    if cors:
        notes.append("CORS too permissive: restrict Access-Control-Allow-Origin "
                     "to a trusted allow-list and never combine '*' with credentials.")
    if plaintext:
        notes.append("Plaintext HTTP: enable HTTPS and 301-redirect all HTTP to "
                     "HTTPS, then enforce HSTS.")
    if disclosure:
        notes.append("Technology disclosure: strip Server / X-Powered-By banners "
                     "to hide software versions from attackers.")
    if cacheable:
        notes.append("Session response cacheable: send Cache-Control: no-store on "
                     "every response that sets a cookie.")
    if dirlist:
        notes.append("Directory listing: disable autoindex (nginx: autoindex off; "
                     "Apache: Options -Indexes).")
    if not missing_headers and not cookie_missing and not xss and not sqli \
            and not blind_sqli and not traversal and not open_redirect \
            and not csrf_forms and not weak_csp and not cors and not plaintext \
            and not disclosure and not cacheable and not dirlist:
        notes.append("No remediations needed for the scanned checks.")

    return {
        "nginx": nginx, "apache": apache, "flask": flask,
        "express": express, "notes": notes,
        "missing_headers": missing_headers,
        "cookie_missing": cookie_missing,
    }
