"""Configuration and safe defaults for websec-auditor.

Rule catalog is grounded in: OWASP Top 10:2021, MITRE CWE, OWASP ASVS v4.0.1,
OWASP Secure Headers Project, OWASP Session Management Cheat Sheet.
"""
from __future__ import annotations
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
KB_FILE = os.path.join(DATA_DIR, "kb_books.jsonl")
INDEX_FILE = os.path.join(DATA_DIR, "kb_index.json")

# Safe, benign reflection probe token. Contains metacharacters on purpose so we
# can tell *unencoded* reflection (XSS surface) from *HTML-escaped* reflection
# (safe). The URL value is percent-encoded when sent; the server decodes it.
SAFE_PROBE_MARKER = "z3cwq<>"

MIN_TLS_VERSION = "TLSv1.2"  # ASVS 9.2 / OWASP TLS cheat sheet

# Required security headers (OWASP Secure Headers Project + ASVS 14.4)
REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": "high", "cwe": "CWE-319", "owasp": "A02",
        "source_id": "OWASP-SEC-HEADERS",
        "remediation": "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "severity": "high", "cwe": "CWE-79", "owasp": "A03",
        "source_id": "OWASP-CSP",
        "remediation": "Add a Content-Security-Policy that whitelists trusted script/style sources.",
    },
    "x-content-type-options": {
        "severity": "low", "cwe": "CWE-16", "owasp": "A05",
        "source_id": "OWASP-SEC-HEADERS",
        "remediation": "Add X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "severity": "medium", "cwe": "CWE-1021", "owasp": "A05",
        "source_id": "OWASP-CLICKJACK",
        "remediation": "Add X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
    },
    "referrer-policy": {
        "severity": "low", "cwe": "CWE-200", "owasp": "A05",
        "source_id": "OWASP-SEC-HEADERS",
        "remediation": "Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
    },
}

# Cookie attributes (OWASP Session Management Cheat Sheet / ASVS 3.3)
COOKIE_FLAGS = {
    "Secure": {"severity": "high", "cwe": "CWE-614", "owasp": "A02",
               "source_id": "OWASP-SESSION",
               "remediation": "Set the Secure flag on all session cookies."},
    "HttpOnly": {"severity": "high", "cwe": "CWE-1004", "owasp": "A05",
                 "source_id": "OWASP-SESSION",
                 "remediation": "Set HttpOnly on session cookies to block JS access."},
    "SameSite": {"severity": "medium", "cwe": "CWE-1275", "owasp": "A01",
                 "source_id": "OWASP-SESSION",
                 "remediation": "Set SameSite=Lax (or Strict) to mitigate CSRF."},
}

# Additional header posture (OWASP Secure Headers Project / ASVS 14.4)
EXTRA_HEADERS = {
    "permissions-policy": {
        "severity": "low", "cwe": "CWE-16", "owasp": "A05",
        "source_id": "OWASP-SEC-HEADERS",
        "remediation": ("Add a Permissions-Policy denying high-privilege browser APIs, "
                        "e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()."),
    },
    "cross-origin-opener-policy": {
        "severity": "low", "cwe": "CWE-693", "owasp": "A05",
        "source_id": "OWASP-SEC-HEADERS",
        "remediation": "Add Cross-Origin-Opener-Policy: same-origin to isolate top-level window context.",
    },
    "cross-origin-embedder-policy": {
        "severity": "low", "cwe": "CWE-693", "owasp": "A05",
        "source_id": "OWASP-SEC-HEADERS",
        "remediation": "Add Cross-Origin-Embedder-Policy: require-corp to prevent loading un-credentialed cross-origin resources.",
    },
    "cross-origin-resource-policy": {
        "severity": "low", "cwe": "CWE-693", "owasp": "A05",
        "source_id": "OWASP-SEC-HEADERS",
        "remediation": "Add Cross-Origin-Resource-Policy: same-origin (or same-site) to block cross-origin read requests.",
    },
}

# Info-disclosure headers (CWE-200): advertise server software / versions.
DISCLOSURE_HEADERS = {
    "server": {"severity": "low", "cwe": "CWE-200", "owasp": "A05",
               "source_id": "CWE-200",
               "remediation": "Suppress or obfuscate the Server header so attackers cannot "
                              "fingerprint software and version."},
    "x-powered-by": {"severity": "low", "cwe": "CWE-200", "owasp": "A05",
                     "source_id": "CWE-200",
                     "remediation": "Remove the X-Powered-By header so the framework/version "
                                    "is not advertised."},
}

# CORS misconfiguration (CWE-942 / OWASP A01)
CORS_RULE = {
    "severity": "medium", "cwe": "CWE-942", "owasp": "A01", "source_id": "CWE-942",
    "remediation": ("Never use Access-Control-Allow-Origin: * (or reflect any Origin) with "
                    "credentials; whitelist specific trusted origins and validate the Origin "
                    "server-side."),
}

# Session responses must not be cached (CWE-524)
CACHE_RULE = {
    "severity": "medium", "cwe": "CWE-524", "owasp": "A05", "source_id": "CWE-524",
    "remediation": "Set Cache-Control: no-store (and Pragma: no-cache) on every response "
                   "that sets a session cookie.",
}

# Directory browsing (CWE-548)
DIRLIST_RULE = {
    "severity": "medium", "cwe": "CWE-548", "owasp": "A05", "source_id": "CWE-548",
    "remediation": "Disable directory listing in the web server (nginx: autoindex off; "
                   "Apache: Options -Indexes).",
}

# Plaintext transport (OWASP A02 / CWE-319)
PLAINTEXT_RULE = {
    "severity": "high", "cwe": "CWE-319", "owasp": "A02", "source_id": "OWASP-TLS",
    "remediation": "Serve exclusively over HTTPS and 301-redirect all HTTP to HTTPS (with HSTS).",
}

# Sensitive Files & Backup Exposure (CWE-200 / OWASP A05)
SENSITIVE_FILES_RULE = {
    "severity": "high", "cwe": "CWE-200", "owasp": "A05", "source_id": "CWE-200-SENSITIVE",
    "remediation": "Block web server access to version control metadata, environment configs, and backup files.",
}
SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/.ds_store", "/backup.sql", "/config.json",
    "/.htaccess", "/.svn/entries", "/phpinfo.php",
]

# Open Redirect (CWE-601 / OWASP A01)
OPEN_REDIRECT_RULE = {
    "severity": "medium", "cwe": "CWE-601", "owasp": "A01", "source_id": "CWE-601",
    "remediation": "Validate redirection targets against a strict whitelist of internal relative paths.",
}
REDIRECT_PARAM_NAMES = ["redirect", "next", "url", "return", "dest", "r", "target", "redirect_uri"]

# Dangerous HTTP Methods (CWE-749 / OWASP A05)
HTTP_METHODS_RULE = {
    "severity": "medium", "cwe": "CWE-749", "owasp": "A05", "source_id": "CWE-749",
    "remediation": "Disable unneeded HTTP verbs like TRACE, PUT, DELETE in web server configuration.",
}

# HSTS floor per ASVS 9.2.3 (>= 180 days); we require 1 year as a safe floor.
HSTS_MIN_MAX_AGE = 31536000
HSTS_SUGGESTED = "max-age=63072000; includeSubDomains; preload"

# Dangerous CSP keywords/sources (CWE-79): defeat the point of CSP.
# CSP tokens are quoted per spec, so match the exact quoted forms plus a bare '*'.
CSP_DANGEROUS = ("'unsafe-inline'", "'unsafe-eval'", "'*'")
# Broad source patterns that weaken CSP without being a full wildcard.
CSP_BROAD = ("*.", "http:",)

# SQL error signatures -> verbose errors (CWE-200) / injection surface (CWE-89)
SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "unclosed quotation mark", "ora-01756",
    "sqlite_error", "psql::", "syntax error near", "you have an error in your sql",
    "pg_query()", "sqlite3::query", "microsoft oledb provider for sql server",
]

# Framework debug error signatures (CWE-200 / CWE-16)
FRAMEWORK_ERROR_SIGNATURES = [
    ("django_debug", "you're seeing this error because you have debug = true"),
    ("werkzeug_debug", "werkzeug powered traceback"),
    ("express_stack", "at function.module._compile"),
    ("spring_whitelabel", "whitelabel error page"),
    ("php_fatal", "fatal error: uncaught error"),
    ("rails_exec", "action controller: exception caught"),
]

# State-changing forms need a per-session anti-CSRF token (CWE-352 / A01)
CSRF_RULE = {
    "severity": "medium", "cwe": "CWE-352", "owasp": "A01", "source_id": "CWE-352",
    "remediation": ("Add a per-session anti-CSRF token to every state-changing "
                    "form and validate it server-side; set cookies to SameSite=Lax."),
}
# Common token field names, so the crawler can tell a form WITH protection apart.
CSRF_FIELD_RE = "csrf|_token|token|authenticity|__requestverification|xsrf"

# Site-wide crawl bounds (Web Scraping with Python: polite, bounded crawling)
CRAWL_MAX_PAGES = 20
CRAWL_MAX_DEPTH = 2
CRAWL_TIMEOUT = 15
# Asset extensions that are links but not pages worth scanning.
CRAWL_SKIP_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
                   ".css", ".js", ".mjs", ".pdf", ".zip", ".gz", ".tar",
                   ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".webm")
