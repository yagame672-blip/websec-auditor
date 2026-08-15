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

# Trusted origins for the web UI's strict Origin/Referer check (CWE-352).
# Same-origin requests (Origin == Host) are always allowed; add any custom
# domain the UI is served from here.
ALLOWED_ORIGINS = [
    "websec-audit.site",
    "www.websec-audit.site",
    "websec-auditor.vercel.app",
    "websec-auditor-light-6cec.vercel.app",
]

# Local Full-Book Library (LOCAL ONLY - never deployed, never redistributed).
# Download your own legally-owned book files (PDF/TXT/MD) into D:\LocalLibrary
# and run `python websec_cli.py ingest-book` (or `ingest-book <file>`). The
# app chunks the FULL text and indexes it here so local scans can quote your
# copies. This folder is on the D: drive, OUTSIDE the project tree, so no
# copyrighted content ever leaves your machine or reaches Vercel/git.
LOCAL_BOOKS_DIR = r"D:\LocalLibrary"
LOCAL_KB_FILE = os.path.join(LOCAL_BOOKS_DIR, "local_books.jsonl")

# Full-text chunking parameters for the local library.
LOCAL_CHUNK_SIZE = 900
LOCAL_CHUNK_OVERLAP = 120

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

# HSTS floor per hstspreload.org (>= 2 years) and ASVS 9.2.3. 1 year is
# insufficient for HSTS preload submission; require 2 years (63072000s).
HSTS_MIN_MAX_AGE = 63072000
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

# SQLi / XSS probe surfaces (OWASP A03 / WSTG-INPV-05 / WSTG-INPV-01)
# Hard wall-clock budget for ONE page scan (seconds). Keeps the whole scan
# well under the Vercel serverless timeout even when the target is slow.
SCAN_BUDGET_SEC = 10 if bool(os.environ.get("VERCEL") == "1" or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")) else 30

SQLI_PROBE_PARAMS = ["q", "id", "search", "name"]
SQLI_MARKERS = ["'", "' OR '1'='1"]
XSS_PROBE_PARAMS = ["q", "search", "name", "page", "id"]
XSS_MARKERS = ["<websec_xss_probe_9f6b2>", "\"><websec_xss_probe_9f6b2>"]
SQLI_MAX_PROBES = 12
XSS_MAX_PROBES = 12

# Blind / boolean SQLi probes (WSTG-INPV-05). Sleep probes are read-only.
BLIND_SQLI_TIMING_PAYLOADS = [
    "' OR SLEEP(2)-- ",
    "' OR pg_sleep(2)-- ",
    "' OR WAITFOR DELAY '0:0:2'-- ",
    "' OR DBMS_PIPE.RECEIVE_MESSAGE('x',2)-- ",
]
BLIND_SQLI_BOOL_TRUE = "' AND '1'='1"
BLIND_SQLI_BOOL_FALSE = "' AND '1'='2"
BLIND_SQLI_MAX_PROBES = 8

# Path traversal / LFI (WSTG-INPV-07, CWE-22)
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "....//....//....//....//etc/passwd",
    "..\\\\..\\\\..\\\\windows\\\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
]
PATH_TRAVERSAL_SIGNATURES = ["root:x:0:0", "[extensions]", "[fonts]", "boot loader"]
PATH_TRAVERSAL_MAX_PROBES = 10
PATH_TRAVERSAL_PARAMS = ["file", "path", "page", "lang", "template", "doc"]

# CSRF token detection (WSTG-SESS-05, CWE-352)
CSRF_TOKEN_NAME_PATTERNS = [
    r"csrf", r"_token", r"token", r"authenticity_token",
    r"__requestverificationtoken", r"xsrf",
]
CSRF_METHODS = {"post", "put", "delete", "patch"}

# Rate-limit backoff test (OWASP DoS / Authentication Cheat Sheets)
RATE_LIMIT_PROBE_COUNT = 5
RATE_LIMIT_WINDOW_SLEEP = 0.2

# DDoS / brute-force mitigation posture (ATT&CK T1498 / OWASP DoS Cheat Sheet):
# passive header evidence that a WAF/CDN or rate limiter is in front of the site.
DDOS_WAF_HEADERS = [
    "cf-ray", "server: cloudflare", "x-sucuri-id", "akamai",
    "x-amz-cf-id", "x-azure-ref", "x-qw", "x-vercel-id", "x-cache",
    "via: 1.1 google", "x-fastly",
]
DDOS_RATELIMIT_HEADERS = [
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
]

# Synonym groups for keyword matching (Level-3 expansion). Two texts "mention
# the same group" when any phrase of the group appears (case-insensitively) in
# both, boosting the match even when the exact wording differs (e.g. a finding
# says "session riding" and a book passage says "CSRF").
SYNONYM_GROUPS = [
    ("csrf", "cross-site request forgery", "session riding", "xsrf", "request forgery"),
    ("sqli", "sql injection", "query injection", "database injection"),
    ("xss", "cross-site scripting", "cross site scripting", "script injection"),
    ("tls", "https", "transport layer security", "ssl", "encryption in transit", "tls 1.2", "tls 1.3"),
    ("hsts", "strict-transport-security", "http strict transport security", "max-age=63072000"),
    ("csp", "content-security-policy", "content security policy", "script-src", "default-src"),
    ("ssrf", "server-side request forgery", "server side request forgery", "metadata service"),
    ("idor", "insecure direct object reference", "object level authorization", "bola", "broken object level authorization"),
    ("cors", "cross-origin resource sharing", "access-control-allow-origin", "acao"),
    ("clickjacking", "ui redress", "x-frame-options", "frame-ancestors"),
    ("brute force", "brute-force", "credential stuffing", "password guessing", "login throttling"),
    ("path traversal", "directory traversal", "local file inclusion", "lfi", "etc/passwd"),
    ("deserialization", "insecure deserialization", "object injection", "pickle", "serializable"),
    ("command injection", "os command injection", "shell injection", "remote code execution", "rce"),
    ("directory listing", "autoindex", "index of", "options -indexes"),
    ("open redirect", "url redirection", "unvalidated redirect", "redirect_uri"),
    ("session fixation", "session hijacking", "session token", "cookie flags", "httponly"),
    ("rate limiting", "rate-limit", "throttling", "retry-after", "ratelimit-limit", "backoff"),
    ("waf", "web application firewall", "cloudflare", "akamai", "cdr", "edge protection"),
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
CRAWL_MAX_PAGES = 10
CRAWL_MAX_DEPTH = 2
CRAWL_TIMEOUT = 3
# Politeness delay (seconds) between page fetches during a site crawl. Keeps
# the scanner from self-triggering the target's rate limiter / bot protection,
# which would otherwise turn an automated crawl into 403s and hide real content.
CRAWL_POLITE_DELAY = 0.4
# Asset extensions that are links but not pages worth scanning.
CRAWL_SKIP_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
                   ".css", ".js", ".mjs", ".pdf", ".zip", ".gz", ".tar",
                   ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".webm")

# ---------------------------------------------------------------------------
# OWASP Top 10:2021 metadata (titles + representative CWEs per category). Used
# by the OWASP Top 10 assessment to build a per-category scorecard and to map
# a finding to a category even when its own owasp tag is missing.
# ---------------------------------------------------------------------------
OWASP_TOP10 = {
    "A01": ("Broken Access Control", [
        "CWE-200", "CWE-201", "CWE-204", "CWE-205", "CWE-206", "CWE-209",
        "CWE-213", "CWE-214", "CWE-22", "CWE-352", "CWE-425", "CWE-441",
        "CWE-601", "CWE-639", "CWE-862", "CWE-863", "CWE-922", "CWE-1270",
        "CWE-1275", "CWE-285", "CWE-98",
    ]),
    "A02": ("Cryptographic Failures", [
        "CWE-257", "CWE-259", "CWE-261", "CWE-262", "CWE-295", "CWE-297",
        "CWE-311", "CWE-312", "CWE-321", "CWE-322", "CWE-323", "CWE-324",
        "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330",
        "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-339",
        "CWE-340", "CWE-347", "CWE-523", "CWE-613", "CWE-615", "CWE-640",
        "CWE-756", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-940",
        "CWE-943", "CWE-998", "CWE-319", "CWE-614",
    ]),
    "A03": ("Injection", [
        "CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80",
        "CWE-83", "CWE-89", "CWE-90", "CWE-94", "CWE-564", "CWE-611", "CWE-643",
        "CWE-917", "CWE-434",
    ]),
    "A04": ("Insecure Design", [
        "CWE-1188", "CWE-1236", "CWE-1336", "CWE-13", "CWE-29", "CWE-209",
        "CWE-260", "CWE-271", "CWE-284", "CWE-332", "CWE-344", "CWE-350",
        "CWE-352", "CWE-358", "CWE-366", "CWE-373", "CWE-390", "CWE-430",
        "CWE-435", "CWE-467", "CWE-568", "CWE-620", "CWE-640", "CWE-651",
        "CWE-691", "CWE-770", "CWE-772", "CWE-779", "CWE-791", "CWE-799",
        "CWE-834", "CWE-840", "CWE-885", "CWE-920", "CWE-986", "CWE-993",
    ]),
    "A05": ("Security Misconfiguration", [
        "CWE-2", "CWE-11", "CWE-13", "CWE-16", "CWE-215", "CWE-269", "CWE-307",
        "CWE-315", "CWE-338", "CWE-420", "CWE-470", "CWE-506", "CWE-508",
        "CWE-509", "CWE-510", "CWE-511", "CWE-514", "CWE-520", "CWE-540",
        "CWE-547", "CWE-556", "CWE-558", "CWE-584", "CWE-595", "CWE-607",
        "CWE-611", "CWE-614", "CWE-615", "CWE-616", "CWE-617", "CWE-638",
        "CWE-639", "CWE-699", "CWE-739", "CWE-742", "CWE-750", "CWE-771",
        "CWE-802", "CWE-805", "CWE-813", "CWE-828", "CWE-863", "CWE-913",
        "CWE-915", "CWE-916", "CWE-922", "CWE-956", "CWE-1005", "CWE-1007",
        "CWE-1036", "CWE-1042", "CWE-1044", "CWE-1047", "CWE-1059", "CWE-1062",
        "CWE-1069", "CWE-1104", "CWE-1108", "CWE-1152", "CWE-1163", "CWE-1173",
        "CWE-1295", "CWE-548", "CWE-524", "CWE-749", "CWE-942", "CWE-1021",
        "CWE-693", "CWE-16", "CWE-400",
    ]),
    "A06": ("Vulnerable and Outdated Components", [
        "CWE-937", "CWE-1035", "CWE-1104", "CWE-1357",
    ]),
    "A07": ("Identification and Authentication Failures", [
        "CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-292",
        "CWE-293", "CWE-302", "CWE-305", "CWE-306", "CWE-307", "CWE-346",
        "CWE-384", "CWE-521", "CWE-522", "CWE-613", "CWE-620", "CWE-640",
        "CWE-645", "CWE-798", "CWE-804", "CWE-940", "CWE-1193", "CWE-1263",
        "CWE-1282",
    ]),
    "A08": ("Software and Data Integrity Failures", [
        "CWE-345", "CWE-346", "CWE-353", "CWE-426", "CWE-494", "CWE-502",
        "CWE-565", "CWE-649", "CWE-829", "CWE-830", "CWE-838", "CWE-1145",
        "CWE-1239", "CWE-1274", "CWE-1357",
    ]),
    "A09": ("Security Logging and Monitoring Failures", [
        "CWE-117", "CWE-223", "CWE-532", "CWE-778", "CWE-1049", "CWE-1164",
        "CWE-1307",
    ]),
    "A10": ("Server-Side Request Forgery", ["CWE-918"]),
}

# Language tag by file extension (code review routing).
LANG_BY_EXT = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".rb": "ruby",
    ".go": "go",
    ".cs": "csharp",
    ".html": "html", ".htm": "html",
    ".j2": "html", ".jinja": "html", ".jinja2": "html",
    ".ejs": "html", ".hbs": "html", ".pug": "html", ".jade": "html",
}
# Files to skip during recursive code review.
CODE_REVIEW_SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "venv", ".venv",
                         "__pycache__", ".idea", ".vscode", "dist", "build",
                         "coverage", ".tox", "site-packages", "tests", "test"}
CODE_REVIEW_MAX_FILE_BYTES = 512 * 1024
CODE_REVIEW_MAX_FILES = 2000
# Maximum lines returned around each match for the report.
CODE_REVIEW_CONTEXT_LINES = 2
# Rule-definition files (the KB rule catalog itself). These files DO define the
# regex patterns the scanner searches for, so a match inside them is the tool
# matching its OWN pattern tables (data), not a real vulnerability. Excluding
# them from recursive review prevents self-flagging without hiding application
# code. A file listed here is still reviewable when passed explicitly.
CODE_REVIEW_RULE_DATA_FILES = {"expansion.py", "build_kb.py", "config.py"}
# Inline suppression marker: a line (or the line directly above a match)
# containing `# codereview-ignore` suppresses all rules; `# codereview-ignore:
# <rule-name>` suppresses only that rule. Used for documented, intentional
# security exceptions (e.g. a scanner relaxing TLS only to inspect broken
# certs). Mirrors Bandit `# nosec` / Semgrep `# nosemgrep` conventions.
CODE_REVIEW_IGNORE_MARKER = "codereview-ignore"

# ---------------------------------------------------------------------------
# Dependency scanning (OWASP A06 / SCVS). Locally-curated advisory seed mapping
# well-known CVE to package + minimum fixed version. Offline and read-only; it
# is a conservative seed meant to be refreshed/expanded, never a substitute for
# a live vulnerability feed (OSV/OSV-Scanner, GHSA, NVD) in production.
# ---------------------------------------------------------------------------
DEPENDENCY_RULE = {
    "severity": "high", "cwe": "CWE-1104", "owasp": "A06",
    "source_id": "OWASP-SCVS-SUPPLYCHAIN",
    "remediation": ("Upgrade to a fixed version, pin exact versions, and re-scan; "
                    "keep the local advisory seed refreshed from OSV/NVD/GHSA."),
}
CVE_ADVISORIES = [
    # python
    {"cve": "CVE-2023-32681", "names": ["requests"], "ecosystem": "python",
     "fixed": "2.31.0", "severity": "high", "cwe": "CWE-522",
     "note": "Proxy-Authorization header may leak to the proxy on redirect."},
    {"cve": "CVE-2023-45803", "names": ["urllib3"], "ecosystem": "python",
     "fixed": "2.0.7", "severity": "medium", "cwe": "CWE-319",
     "note": "Request body is not stripped across HTTP(S) redirect (data leak)."},
    {"cve": "CVE-2023-25577", "names": ["werkzeug"], "ecosystem": "python",
     "fixed": "2.2.3", "severity": "medium", "cwe": "CWE-400",
     "note": "Large multipart/form-data requests can exhaust memory (DoS)."},
    {"cve": "CVE-2022-36359", "names": ["django"], "ecosystem": "python",
     "fixed": "4.0.7", "severity": "high", "cwe": "CWE-89",
     "note": "SQL injection in Trunc(kind, output_field) database functions."},
    {"cve": "CVE-2024-45230", "names": ["django"], "ecosystem": "python",
     "fixed": "5.0.7", "severity": "high", "cwe": "CWE-79",
     "note": "Potential XSS in URL validator / email validation handling."},
    {"cve": "CVE-2023-4421", "names": ["pillow"], "ecosystem": "python",
     "fixed": "10.1.0", "severity": "high", "cwe": "CWE-20",
     "note": "Possible arbitrary code execution via crafted TIFF in getstring."},
    # npm
    {"cve": "CVE-2021-23337", "names": ["lodash"], "ecosystem": "npm",
     "fixed": "4.17.21", "severity": "high", "cwe": "CWE-1321",
     "note": "Prototype pollution via defaultsDeep/cloneDeep payloads."},
    {"cve": "CVE-2021-44906", "names": ["minimist"], "ecosystem": "npm",
     "fixed": "1.2.6", "severity": "high", "cwe": "CWE-1321",
     "note": "Prototype pollution in minimist option parsing."},
    {"cve": "CVE-2022-24999", "names": ["qs"], "ecosystem": "npm",
     "fixed": "6.10.3", "severity": "high", "cwe": "CWE-1321",
     "note": "Prototype pollution via crafted query strings."},
    {"cve": "CVE-2022-46175", "names": ["json5"], "ecosystem": "npm",
     "fixed": "2.2.2", "severity": "high", "cwe": "CWE-1321",
     "note": "Prototype pollution in JSON5 string parsing."},
    {"cve": "CVE-2021-3803", "names": ["nth-check"], "ecosystem": "npm",
     "fixed": "2.0.1", "severity": "medium", "cwe": "CWE-1333",
     "note": "ReDoS in nth-check CSS selector parsing."},
    {"cve": "CVE-2022-38900", "names": ["decode-uri-component"], "ecosystem": "npm",
     "fixed": "0.2.1", "severity": "medium", "cwe": "CWE-1333",
     "note": "ReDoS when decoding crafted encoded URI components."},
    # maven
    {"cve": "CVE-2021-44228", "names": ["log4j-core"], "ecosystem": "maven",
     "fixed": "2.17.0", "severity": "critical", "cwe": "CWE-502",
     "note": "Log4Shell: JNDI lookup RCE on user-controlled log messages."},
    {"cve": "CVE-2017-5638", "names": ["struts2-core", "struts-core"], "ecosystem": "maven",
     "fixed": "2.3.32", "severity": "critical", "cwe": "CWE-20",
     "note": "RCE via Jakarta Multipart parser Content-Type handling."},
    {"cve": "CVE-2022-22965", "names": ["spring-core"], "ecosystem": "maven",
     "fixed": "5.3.18", "severity": "critical", "cwe": "CWE-94",
     "note": "Spring4Shell: RCE via data binding to class properties."},
    # composer
    {"cve": "CVE-2022-31042", "names": ["guzzlehttp/guzzle"], "ecosystem": "composer",
     "fixed": "7.4.4", "severity": "medium", "cwe": "CWE-522",
     "note": "Authorization header may be leaked to a different host on redirect."},
    # rubygems
    {"cve": "CVE-2020-8163", "names": ["rails", "railties"], "ecosystem": "rubygems",
     "fixed": "5.2.4.3", "severity": "high", "cwe": "CWE-94",
     "note": "Code execution (RCE) via Strong Parameters permit yaml deserialization."},
    {"cve": "CVE-2022-30122", "names": ["rack"], "ecosystem": "rubygems",
     "fixed": "2.2.3.1", "severity": "medium", "cwe": "CWE-400",
     "note": "DoS in Rack Multipart MIME parsing."},
    # go
    {"cve": "CVE-2021-38561", "names": ["golang.org/x/text"], "ecosystem": "go",
     "fixed": "0.3.8", "severity": "medium", "cwe": "CWE-1333",
     "note": "ReDoS in golang.org/x/text language tag parsing."},
]

# Manifest file -> ecosystem, so `depscan <dir>` knows what to parse.
MANIFEST_FILENAMES = {
    "requirements.txt": "python",
    "Pipfile": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "composer.json": "composer",
    "composer.lock": "composer",
    "Gemfile": "rubygems",
    "Gemfile.lock": "rubygems",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "go.mod": "go",
    "go.sum": "go",
}

# ---------------------------------------------------------------------------
# Static code review (OWASP Code Review Guide / SAST). Fallback rule set used
# when the KB has not been built yet; the codereview engine loads its primary
# rule set from KB records (scan_rules type "code_review"). Each entry is a
# regex + class metadata; "source_id" links the finding to a KB passage.
# ---------------------------------------------------------------------------
CODE_REVIEW_FALLBACK_RULES = [
    {"type": "code_review", "name": "sql-string-concat", "severity": "high",
     "cwe": "CWE-89", "owasp": "A03", "source_id": "CWE-89",
     "languages": ["python", "php", "javascript", "java"],
     "pattern": r"[\"']\s*(SELECT|INSERT|UPDATE|DELETE)\b[^\"']{0,160}[\"']{1,2}\s*(?:%|\+|\.format\s*\(|\.join\s*\(|f[\"']|\{)",
     "confidence": "medium",
     "description": "SQL built by string concatenation/interpolation.",
     "remediation": "Use parameterized queries / prepared statements everywhere; never build SQL by concatenation."},
    {"type": "code_review", "name": "execute-fstring-sql", "severity": "high",
     "cwe": "CWE-89", "owasp": "A03", "source_id": "CWE-89",
     "languages": ["python"],
     "pattern": r"\.execute\s*\(\s*f[\"']\s*(SELECT|INSERT|UPDATE|DELETE)",
     "confidence": "high",
     "description": "DB-API execute() called with an f-string starting a SQL statement.",
     "remediation": "Pass parameters as a separate argument tuple to execute(sql, params); never inline values."},
    {"type": "code_review", "name": "innerHTML-assign", "severity": "high",
     "cwe": "CWE-79", "owasp": "A03", "source_id": "CWE-79",
     "languages": ["javascript"],
     "pattern": r"\.innerHTML\s*=\s*(?![\"'][^\"']*[\"']\s*$)\S",
     "confidence": "medium",
     "description": "innerHTML assigned a dynamic value; no context-aware encoding.",
     "remediation": "Use textContent / createElement + text nodes, or encode with an HTML-escape context."},
    {"type": "code_review", "name": "python-command-shell", "severity": "high",
     "cwe": "CWE-78", "owasp": "A03", "source_id": "CWE-78",
     "languages": ["python"],
     "pattern": r"(os\.system\s*\(|os\.popen\s*\(|subprocess\.(run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True)",
     "confidence": "high",
     "description": "OS command executed through the shell.",
     "remediation": "Call executables directly with an argument list (shell=False), never with user input."},
    {"type": "code_review", "name": "urlopen-user-input", "severity": "high",
     "cwe": "CWE-918", "owasp": "A10", "source_id": "CWE-918",
     "languages": ["python"],
     "pattern": r"(urllib\.request\.)?urlopen\s*\(\s*[a-z_]\w*",
     "confidence": "medium",
     "description": "urlopen() fed a variable (request-derived URLs can reach internal hosts).",
     "remediation": "Allow-list permitted schemes/hosts, block link-local/loopback/cloud metadata IPs, and resolve+validate before fetch."},
    {"type": "code_review", "name": "hardcoded-password", "severity": "high",
     "cwe": "CWE-798", "owasp": "A07", "source_id": "CWE-798",
     "languages": ["python", "php", "javascript", "java", "ruby", "go"],
     "pattern": r"\b(password|passwd|pwd|pass|db_passwd)\s*[=:]\s*[\"'][^\"']{3,}[\"']",
     "confidence": "medium",
     "description": "Hardcoded password/credential literal in source.",
     "remediation": "Store secrets in a vault/env vars; rotate any committed credential immediately."},
    {"type": "code_review", "name": "python-pickle-load", "severity": "high",
     "cwe": "CWE-502", "owasp": "A08", "source_id": "CWE-502-DESERIALIZATION",
     "languages": ["python"],
     "pattern": r"pickle\.loads?\s*\(|\bcPickle\b",
     "confidence": "high",
     "description": "pickle.loads() on (possibly untrusted) data executes code on decode.",
     "remediation": "Never deserialize untrusted data with pickle; use JSON and validate the schema."},
    {"type": "code_review", "name": "weak-hash-credential", "severity": "medium",
     "cwe": "CWE-327", "owasp": "A02", "source_id": "CWE-327",
     "languages": ["python", "php", "javascript", "java", "ruby"],
     "pattern": r"(hashlib\.md5|hashlib\.sha1|\.sha1\s*\(|\bmd5\s*\(|\bsha1\s*\(|MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-1)[\"'])",
     "confidence": "medium",
     "description": "MD5/SHA-1 used (common for credential hashing / integrity where collision resistance matters).",
     "remediation": "Use Argon2/bcrypt/scrypt/PBKDF2 for passwords and SHA-256+ for integrity."},
]

# ---------------------------------------------------------------------------
# Notifications & Asynchronous Scanner Configuration
# Grounded in: NIST SP 800-53 (AC-4, SC-7), OWASP ASVS v4.0.3 (V5, V12, V13),
# and RFC 5322 / RFC 2104.
# ---------------------------------------------------------------------------
WEBHOOK_TIMEOUT_SECONDS = int(os.environ.get("WEBHOOK_TIMEOUT_SECONDS", "10"))
MAX_ASYNC_WORKERS = int(os.environ.get("MAX_ASYNC_WORKERS", "5"))
ASYNC_JOB_TTL_SECONDS = int(os.environ.get("ASYNC_JOB_TTL_SECONDS", str(24 * 3600)))

# Email delivery settings (SMTP / Resend API)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "0").lower() in ("1", "true", "yes")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "1").lower() in ("1", "true", "yes")

# Transactional email API token
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM = os.environ.get("RESEND_FROM", "")

