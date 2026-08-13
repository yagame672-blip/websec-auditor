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
    os.makedirs(config.DATA_DIR, exist_ok=True)
    with open(FIXSTATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)
    return state


def demo_is_hardened() -> bool:
    try:
        with open(FIXSTATE_FILE, encoding="utf-8") as f:
            return bool(json.load(f).get("hardened"))
    except Exception:
        return False


def reset_demo_fix():
    try:
        os.remove(FIXSTATE_FILE)
    except FileNotFoundError:
        pass


# --------------------------------------------------------------------------
# Remediation snippets keyed by the finding 'name' (matches scanner output)
# --------------------------------------------------------------------------
HEADER_FIX = {
    "strict-transport-security":
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    "content-security-policy":
        "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; "
        "object-src 'none'; base-uri 'self'",
    "x-content-type-options": "X-Content-Type-Options: nosniff",
    "x-frame-options": "X-Frame-Options: DENY",
    "referrer-policy": "Referrer-Policy: no-referrer",
    "permissions-policy": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
}

COOKIE_FLAGS = "Secure; HttpOnly; SameSite=Lax"


def build_bundle(enriched):
    """Return {'nginx':..., 'apache':..., 'flask':..., 'express':..., 'notes':[...]}."""
    missing_headers = []
    cookie_missing = False
    xss = False
    sqli = False
    weak_csp = False
    cors = False
    plaintext = False
    disclosure = False
    cacheable = False
    dirlist = False
    for e in enriched:
        f = e["finding"]
        n = f["name"]
        if n.startswith("Missing header:"):
            h = n.split(":", 1)[1].strip()
            if h in HEADER_FIX:
                missing_headers.append(h)
        elif n.startswith("Missing cookie flag:"):
            cookie_missing = True
        elif n == "Reflected input detected":
            xss = True
        elif n == "SQL error signature in response":
            sqli = True
        elif n == "Weak CSP directives":
            weak_csp = True
        elif n.startswith("Overly permissive CORS"):
            cors = True
        elif n == "Plaintext HTTP transport":
            plaintext = True
        elif n.startswith("Technology disclosure"):
            disclosure = True
        elif n == "Session response is cacheable":
            cacheable = True
        elif n == "Directory listing exposed":
            dirlist = True

    add_headers = "\n".join(f"    add_header {h} \"{HEADER_FIX[h]}\";"
                            for h in missing_headers)
    nginx = f"""# websec-auditor remediation (deploy on YOUR OWN server)
server {{
    # ... existing server block ...
{add_headers}
    # Cookie hardening: set flags on your session cookie, e.g. in your app:
    # Set-Cookie: sessionid=...; {COOKIE_FLAGS}
}}"""

    apache = f"""# websec-auditor remediation (deploy on YOUR OWN server)
<IfModule mod_headers.c>
{chr(10).join(f'    Header always set {h} "{HEADER_FIX[h]}"' for h in missing_headers)}
</IfModule>
# Cookie hardening: in your app set session cookie with: {COOKIE_FLAGS}"""

    flask = f"""# websec-auditor remediation (Flask example, YOUR OWN app)
from flask import Flask, make_response
app = Flask(__name__)

@app.after_request
def secure_headers(resp):
{chr(10).join(f'    resp.headers["{h}"] = "{HEADER_FIX[h]}"' for h in missing_headers)}
    # Cookie hardening
    for name in list(resp.headers.keys()):
        if name.lower() == 'set-cookie' and 'sessionid' in resp.headers[name].lower():
            resp.headers[name] = resp.headers[name] + "; {COOKIE_FLAGS}"
    return resp"""

    express = f"""// websec-auditor remediation (Express example, YOUR OWN app)
app.use((req, res, next) => {{
{chr(10).join(f'  res.setHeader("{h}", "{HEADER_FIX[h]}");' for h in missing_headers)}
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
            and not weak_csp and not cors and not plaintext and not disclosure \
            and not cacheable and not dirlist:
        notes.append("No remediations needed for the scanned checks.")

    return {
        "nginx": nginx, "apache": apache, "flask": flask,
        "express": express, "notes": notes,
        "missing_headers": missing_headers,
        "cookie_missing": cookie_missing,
    }
