"""Build the book-grounded knowledge base for websec-auditor.

Three sources (per project design):
  A) Free, legal, authoritative docs  -> OWASP Top 10:2021, MITRE CWE, ASVS,
     OWASP cheat sheets. Passages are OUR OWN paraphrased explanations of those
     public standards (facts + guidance), attributed with source name + URL.
     No copyrighted text is copied.
  B) Curated reputable security books -> metadata + publisher + the publisher's
     own free/preview material links (e.g. free chapters, official TOC). We do
     NOT redistribute book bodies.
  C) User-owned books                -> optional local PDFs the USER supplies.
     Ingestion is offline/local only; see ingest_pdf() / the analyzer loads
     whatever the user drops in data/user_books/.

Output: data/kb_books.jsonl  (one JSON object per passage chunk)
Output: data/kb_index.json   (metadata)
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from websec_auditor import config

DATA_DIR = config.DATA_DIR
os.makedirs(DATA_DIR, exist_ok=True)

SOURCE_A = [
    {
        "id": "OWASP-A01-BROKEN-AC",
        "source_type": "A",
        "title": "A01:2021 Broken Access Control",
        "authority": "OWASP Top 10:2021",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "cwe": "CWE-285", "owasp": "A01",
        "passage": (
            "Broken Access Control is the #1 web risk in OWASP's 2021 list. It occurs when"
            "an application fails to enforce proper restrictions on what authenticated or"
            "anonymous users may do. Common forms: insecure direct object references"
            "(tampering with an id/key to reach another user's data), missing"
            "function-level authorization (a URL or API works for a normal user when only"
            "admins should use it), and CORS misconfiguration trusting arbitrary origins."
            "Detection: probe for IDOR by substituting record ids and for missing authz by"
            "requesting admin endpoints as a low-privilege user. Remediation: deny by"
            "default, enforce authorization server-side on every request, use per-user"
            "object ownership checks, and avoid CORS allow-origin '*' with credentials."
        ),
    },
    {
        "id": "OWASP-A02-CRYPTO",
        "source_type": "A",
        "title": "A02:2021 Cryptographic Failures",
        "authority": "OWASP Top 10:2021",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "cwe": "CWE-319", "owasp": "A02",
        "passage": (
            "Cryptographic Failures cover data exposed in transit or at rest due to weak or"
            "missing crypto. Key checks: TLS must be TLS 1.2+ with strong ciphers; the"
            "Strict-Transport-Security (HSTS) header must be set so browsers never"
            "downgrade to plaintext; sensitive cookies must carry the Secure flag; and any"
            "stored secrets/passwords must use a slow, salted hash"
            "(bcrypt/Argon2/scrypt/PBKDF2), never plain text or fast hashes like MD5/SHA1."
            "Detection: observe the TLS negotiated version and the absence of HSTS / Secure"
            "flags. Remediation: enable HSTS, set Secure on cookies, upgrade TLS, and"
            "rehash any weak password storage."
        ),
    },
    {
        "id": "OWASP-A03-INJECTION",
        "source_type": "A",
        "title": "A03:2021 Injection (SQLi / XSS)",
        "authority": "OWASP Top 10:2021",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "Injection happens when untrusted data is sent to an interpreter as part of a"
            "command or query. SQL Injection (CWE-89) lets an attacker read or modify the"
            "database; Cross-Site Scripting (CWE-79) lets them run script in a victim's"
            "browser. Detection: send a benign unique marker into each input and check"
            "whether it is reflected unencoded in the response, and watch for SQL error"
            "messages that reveal query structure (CWE-200) -- verbose errors both leak"
            "data and signal an injection surface. Remediation: use parameterized queries /"
            "prepared statements for SQL, contextual output encoding, and a"
            "Content-Security-Policy to contain any XSS. Never build queries by string"
            "concatenation."
        ),
    },
    {
        "id": "OWASP-A05-MISCONFIG",
        "source_type": "A",
        "title": "A05:2021 Security Misconfiguration",
        "authority": "OWASP Top 10:2021",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "Security Misconfiguration is the most common entry in the 2021 list's"
            "supporting data. It includes missing security headers, verbose error pages,"
            "default credentials, unnecessary features enabled (directory listing, debug"
            "modes), and unpatched frameworks. Detection: verify the presence and"
            "correctness of security headers (HSTS, CSP, X-Content-Type-Options,"
            "X-Frame-Options, Referrer-Policy), check for stack-trace/debug output, and"
            "confirm directory listing is disabled. Remediation: a repeatable hardened"
            "build, remove unused features, and a header baseline enforced by default."
        ),
    },
    {
        "id": "OWASP-SEC-HEADERS",
        "source_type": "A",
        "title": "OWASP Secure Headers Project",
        "authority": "OWASP Secure Headers Project",
        "url": "https://owasp.org/www-project-secure-headers/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "HTTP response headers are a cheap, high-impact control."
            "Strict-Transport-Security forces HTTPS. Content-Security-Policy limits where"
            "scripts/styles may load, blunting XSS. X-Content-Type-Options: nosniff stops"
            "MIME sniffing. X-Frame-Options (or CSP frame-ancestors) blocks clickjacking."
            "Referrer-Policy limits what URL info leaks to third parties. A missing header"
            "is a concrete, fixable misconfiguration -- not a theoretical risk."
        ),
        "scan_rules": [
            {"type": "header_required", "name": "strict-transport-security", "severity": "high", "cwe": "CWE-319", "owasp": "A02", "remediation": "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"},
            {"type": "header_required", "name": "content-security-policy", "severity": "high", "cwe": "CWE-79", "owasp": "A03", "remediation": "Add a Content-Security-Policy that whitelists trusted script/style sources."},
            {"type": "header_required", "name": "x-content-type-options", "severity": "low", "cwe": "CWE-16", "owasp": "A05", "remediation": "Add X-Content-Type-Options: nosniff"},
            {"type": "header_required", "name": "referrer-policy", "severity": "low", "cwe": "CWE-200", "owasp": "A05", "remediation": "Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin."},
            {"type": "header_required", "name": "permissions-policy", "severity": "low", "cwe": "CWE-16", "owasp": "A05", "remediation": "Add a Permissions-Policy header."},
            {"type": "header_required", "name": "cross-origin-opener-policy", "severity": "low", "cwe": "CWE-693", "owasp": "A05", "remediation": "Add Cross-Origin-Opener-Policy: same-origin"},
            {"type": "header_required", "name": "cross-origin-embedder-policy", "severity": "low", "cwe": "CWE-693", "owasp": "A05", "remediation": "Add Cross-Origin-Embedder-Policy: require-corp"},
            {"type": "header_required", "name": "cross-origin-resource-policy", "severity": "low", "cwe": "CWE-693", "owasp": "A05", "remediation": "Add Cross-Origin-Resource-Policy: same-origin"},
            {"type": "header_required", "name": "cache-control", "severity": "low", "cwe": "CWE-524", "owasp": "A05", "remediation": "Add Cache-Control: no-store, max-age=0 on pages that serve sensitive data or session tokens."},
            {"type": "header_required", "name": "content-type", "severity": "medium", "cwe": "CWE-436", "owasp": "A05", "remediation": "Add Content-Type header with explicit charset declaration."}
        ]
    },
    {
        "id": "OWASP-CSP",
        "source_type": "A",
        "title": "Content Security Policy (defense-in-depth for XSS)",
        "authority": "OWASP / MDN CSP",
        "url": "https://owasp.org/www-community/attacks/xss/",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "A Content-Security-Policy is the primary browser-side defense against XSS. It"
            "declares approved sources for scripts, styles, images, and other resources;"
            "anything else is blocked. Use 'default-src https:' and avoid"
            "'unsafe-inline'/'unsafe-eval'. CSP is defense-in-depth: it limits damage when"
            "output encoding is missed, it does not replace proper input handling."
        ),
    },
    {
        "id": "OWASP-CLICKJACK",
        "source_type": "A",
        "title": "Clickjacking defense",
        "authority": "OWASP Clickjacking Defense Cheat Sheet",
        "url": "https://owasp.org/www-community/attacks/Clickjacking",
        "cwe": "CWE-1021", "owasp": "A05",
        "passage": (
            "Clickjacking tricks a user into clicking a hidden element overlaid on a"
            "legitimate page. Defense: send X-Frame-Options: DENY (or SAMEORIGIN) and/or"
            "the CSP directive frame-ancestors 'none'. Without it, your authenticated UI"
            "can be framed by an attacker and used to perform unintended actions."
        ),
        "scan_rules": [
            {"type": "header_required", "name": "x-frame-options", "severity": "medium", "cwe": "CWE-1021", "owasp": "A05", "remediation": "Add X-Frame-Options: DENY (or CSP frame-ancestors 'none')."}
        ]
    },
    {
        "id": "OWASP-SESSION",
        "source_type": "A",
        "title": "Session cookie hardening",
        "authority": "OWASP Session Management Cheat Sheet",
        "url": "https://owasp.org/www-community/Session_Management_Cheat_Sheet",
        "cwe": "CWE-614", "owasp": "A05",
        "passage": (
            "Session cookies must be protected. The Secure flag ensures they are sent only"
            "over HTTPS (CWE-614). HttpOnly blocks JavaScript access, neutralizing most"
            "XSS-based session theft (CWE-1004). SameSite=Lax or Strict reduces cross-site"
            "request forgery (CWE-1275). A session cookie missing any of these three is a"
            "real, exploitable weakness."
        ),
        "scan_rules": [
            {"type": "cookie_flag", "flag": "Secure", "severity": "high", "cwe": "CWE-614", "owasp": "A02", "remediation": "Set the Secure flag on all session cookies."},
            {"type": "cookie_flag", "flag": "HttpOnly", "severity": "high", "cwe": "CWE-1004", "owasp": "A05", "remediation": "Set HttpOnly on session cookies to block JS access."},
            {"type": "cookie_flag", "flag": "SameSite", "severity": "medium", "cwe": "CWE-1275", "owasp": "A01", "remediation": "Set SameSite=Lax (or Strict) to mitigate CSRF."}
        ]
    },
    {
        "id": "CWE-601",
        "source_type": "A",
        "title": "CWE-601 URL Redirection to Untrusted Site ('Open Redirect')",
        "authority": "MITRE CWE-601 / OWASP Unvalidated Redirects",
        "url": "https://cwe.mitre.org/data/definitions/601.html",
        "cwe": "CWE-601", "owasp": "A01",
        "passage": (
            "Open Redirect occurs when a web application accepts a user-controlled URL input"
            "and redirects the user to that URL without proper validation. Attackers use open"
            "redirects in phishing campaigns to make malicious links appear trustworthy because"
            "the initial URL points to a legitimate domain. Remediation: avoid user-controlled"
            "redirect targets, or validate all redirect URLs against a strict whitelist of internal"
            "relative paths."
        ),
        "scan_rules": [
            {"type": "open_redirect", "params": ["redirect", "next", "url", "return", "dest", "r", "target", "redirect_uri"], "severity": "medium", "cwe": "CWE-601", "owasp": "A01", "remediation": "Validate redirection targets against a strict whitelist of internal relative paths."}
        ]
    },
    {
        "id": "CWE-200-SENSITIVE",
        "source_type": "A",
        "title": "CWE-200 Exposure of Sensitive Information via Public Files",
        "authority": "MITRE CWE-200",
        "url": "https://cwe.mitre.org/data/definitions/200.html",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "Sensitive file exposure happens when configuration files (.env), version control"
            "metadata (.git), backup databases (.sql), or system metadata (.DS_Store) are exposed"
            "in publicly accessible web server directories. Attackers can read API keys, database"
            "credentials, or source code history directly. Remediation: configure web server block"
            "rules for hidden dotfiles and backup extensions, and keep sensitive files outside webroot."
        ),
        "scan_rules": [
            {"type": "sensitive_paths", "paths": ["/.env", "/.git/HEAD", "/.ds_store", "/backup.sql", "/config.json", "/.htaccess", "/.svn/entries", "/phpinfo.php"], "severity": "high", "cwe": "CWE-200", "owasp": "A05", "remediation": "Block web server access to version control metadata, environment configs, and backup files."}
        ]
    },
    {
        "id": "CWE-749",
        "source_type": "A",
        "title": "CWE-749 Exposed Dangerous Method / Verb Exposure",
        "authority": "MITRE CWE-749 / OWASP Web Server Configuration",
        "url": "https://cwe.mitre.org/data/definitions/749.html",
        "cwe": "CWE-749", "owasp": "A05",
        "passage": (
            "Dangerous HTTP methods (such as TRACE, PUT, or DELETE) enabled on web servers can"
            "expose the application to Cross-Site Tracing (XST) attacks or unauthorized file manipulation."
            "The TRACE method echoes back the exact request headers received, potentially leaking sensitive"
            "authentication headers or cookies. Remediation: restrict HTTP methods at the web server"
            "or API gateway to only required verbs (e.g., GET and POST)."
        ),
        "scan_rules": [
            {"type": "http_methods", "dangerous": ["TRACE", "PUT", "DELETE", "CONNECT"], "severity": "medium", "cwe": "CWE-749", "owasp": "A05", "remediation": "Disable unneeded HTTP verbs like TRACE, PUT, DELETE in web server configuration."}
        ]
    },
    {
        "id": "CWE-89",
        "source_type": "A",
        "title": "CWE-89 SQL Injection",
        "authority": "MITRE CWE-89",
        "url": "https://cwe.mitre.org/data/definitions/89.html",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command."
            "The software constructs SQL with externally-influenced input without"
            "neutralizing characters such as the single quote. Impact ranges from"
            "authentication bypass to full database compromise. The accepted fix is"
            "parameterized queries / bound parameters; escaping alone is insufficient."
            "Reflection of a probe marker or exposure of SQL errors are strong indicators."
        ),
    },
    {
        "id": "CWE-79",
        "source_type": "A",
        "title": "CWE-79 Cross-site Scripting",
        "authority": "MITRE CWE-79",
        "url": "https://cwe.mitre.org/data/definitions/79.html",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "CWE-79: Improper Neutralization of Input During Web Page Generation. Untrusted"
            "input is placed into output sent to a web browser without proper encoding,"
            "letting an attacker execute scripts in the victim's context. Reflected XSS"
            "echoes input back immediately; stored XSS persists in the application. Fix:"
            "context-aware output encoding plus a CSP; never insert raw user input into"
            "HTML/JS/attribute contexts."
        ),
    },
    {
        "id": "ASVS-V4-CRYPTO",
        "source_type": "A",
        "title": "ASVS 4.0.1 V9 Communications / V6 Crypto",
        "authority": "OWASP ASVS 4.0.1",
        "url": "https://owasp.org/www-project-application-security-verification-standard/",
        "cwe": "CWE-326", "owasp": "A02",
        "passage": (
            "The ASVS sets concrete bars: V9.2 requires TLS 1.2+ with strong ciphers and"
            "HSTS; V6 requires no weak or deprecated algorithms (MD5/SHA1, DES, RC4) and"
            "unique salts for password storage. A scan that finds TLS 1.0/1.1, no HSTS, or"
            "plaintext password storage fails ASVS at the most basic (L1) level and should"
            "be remediated before deployment."
        ),
    },
    {
        "id": "OWASP-TLS",
        "source_type": "A",
        "title": "TLS configuration baseline",
        "authority": "OWASP TLS Cheat Sheet",
        "url": "https://owasp.org/www-community/attacks/Transport_Layer_Protection_Cheat_Sheet",
        "cwe": "CWE-319", "owasp": "A02",
        "passage": (
            "Transport Layer Protection: all traffic must use TLS 1.2 or 1.3 with"
            "forward-secret ciphers. Disable SSLv3, TLS 1.0, and TLS 1.1. Pair this with"
            "HSTS so clients cannot be tricked into plaintext. A server negotiating below"
            "TLS 1.2 exposes data to interception."
        ),
    },
    {
        "id": "CWE-200",
        "source_type": "A",
        "title": "CWE-200 Exposure of Sensitive Information",
        "authority": "MITRE CWE-200",
        "url": "https://cwe.mitre.org/data/definitions/200.html",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "CWE-200: exposure of sensitive information to an unauthorized actor. Responses"
            "that advertise server software and versions (Server, X-Powered-By) or leak"
            "verbose stack traces hand an attacker a map of the technology stack and its"
            "known-vulnerable versions. Suppress version banners, remove framework headers,"
            "and keep debug output out of production responses."
        ),
    },
    {
        "id": "CWE-942",
        "source_type": "A",
        "title": "CWE-942 Overly Permissive Cross-domain Whitelist",
        "authority": "MITRE CWE-942",
        "url": "https://cwe.mitre.org/data/definitions/942.html",
        "cwe": "CWE-942", "owasp": "A01",
        "passage": (
            "CWE-942: a cross-domain trust list that allows any origin."
            "Access-Control-Allow-Origin: * - or a server that reflects any requested"
            "Origin - with credentials lets any website issue cross-origin requests on"
            "behalf of a logged-in user and read the responses. The server must restrict"
            "Access-Control-Allow-Origin to a small allow-list of trusted origins."
        ),
    },
    {
        "id": "CWE-524",
        "source_type": "A",
        "title": "CWE-524 Improperly Controlled Cache of Sensitive Data",
        "authority": "MITRE CWE-524",
        "url": "https://cwe.mitre.org/data/definitions/524.html",
        "cwe": "CWE-524", "owasp": "A05",
        "passage": (
            "CWE-524: sensitive data cached by a shared or browser cache without proper"
            "control. A response that sets a session cookie but lacks Cache-Control:"
            "no-store can be replayed from cache on the same machine or a shared proxy."
            "Send Cache-Control: no-store on every response that establishes a session."
        ),
    },
    {
        "id": "CWE-548",
        "source_type": "A",
        "title": "CWE-548 Information Exposure Through Directory Listing",
        "authority": "MITRE CWE-548",
        "url": "https://cwe.mitre.org/data/definitions/548.html",
        "cwe": "CWE-548", "owasp": "A05",
        "passage": (
            "CWE-548: when a web server auto-indexes directories it exposes file names and"
            "structure ('Index of /'), which eases targeted attacks against the site."
            "Disable directory browsing and serve an explicit index document so the"
            "filesystem layout stays private."
        ),
    },
    {
        "id": "CWE-295",
        "source_type": "A",
        "title": "CWE-295 Improper Certificate Validation",
        "authority": "MITRE CWE-295",
        "url": "https://cwe.mitre.org/data/definitions/295.html",
        "cwe": "CWE-295", "owasp": "A02",
        "passage": (
            "CWE-295: failure to properly validate certificates - chain, hostname, or"
            "expiry. An expired certificate (or one about to expire) signals lapsed"
            "operational control and invites man-in-the-middle interception. Renew"
            "certificates well before their notAfter date and automate the renewal."
        ),
    },
    {
        "id": "WSTG-INFO-03-METAFILES",
        "source_type": "A",
        "title": "WSTG-INFO-03 Review Webserver Metafiles for Information Leakage",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "WSTG-INFO-03: review the webserver metafiles for information leakage before"
            "testing. robots.txt and sitemap.xml frequently reveal paths the application"
            "never links to - admin areas, staging directories, backup files - that a"
            "manual crawl would miss. The crawler fetches these metafiles and feeds any"
            "disallowed or sitemapped URLs into discovery so the whole surface is mapped,"
            "not just the linked pages."
        ),
    },
    {
        "id": "WSTG-INFO-06-ENTRYPOINTS",
        "source_type": "A",
        "title": "WSTG-INFO-06 Identify Application Entry Points",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "WSTG-INFO-06: identify the application's entry points - query-string"
            "parameters, HTTP headers, cookies, form fields, and API endpoints - because"
            "every entry point is a potential injection surface. The crawler enumerates"
            "forms and their fields and records which parameters exist on each URL, so the"
            "scanner can probe every discovered parameter rather than only a guessed 'q'"
            "value."
        ),
    },
    {
        "id": "WSTG-INFO-07-MAPPING",
        "source_type": "A",
        "title": "WSTG-INFO-07 Map Execution Paths Through Application",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "WSTG-INFO-07: map the target application and understand its principal"
            "workflows before testing. In black-box tests, page contents are parsed to"
            "discover links and execution paths; every discovered path is then tested for"
            "vulnerabilities. Automated spidering crawls the pages, and each unique URL -"
            "plus the parameters and forms on it - becomes an input to the per-page checks."
        ),
    },
    {
        "id": "CWE-352",
        "source_type": "A",
        "title": "CWE-352 Cross-Site Request Forgery",
        "authority": "MITRE CWE-352",
        "url": "https://cwe.mitre.org/data/definitions/352.html",
        "cwe": "CWE-352", "owasp": "A01",
        "passage": (
            "CWE-352: the web server validates a state-changing request without proving the"
            "request came from the authenticated user, letting an attacker's site forge"
            "requests that ride the victim's session. State-changing forms (login, password"
            "change, payment) must carry a per-session anti-CSRF token that is validated"
            "server-side, and cookies should be SameSite=Lax or Strict."
        ),
    },
    {
        "id": "OWASP-API-2023-BOLA",
        "source_type": "A",
        "title": "API1:2023 Broken Object Level Authorization (BOLA / IDOR)",
        "authority": "OWASP API Security Top 10:2023",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "cwe": "CWE-639", "owasp": "A01",
        "passage": (
            "BOLA (Broken Object Level Authorization) is the #1 risk in OWASP's API Top 10."
            "APIs frequently expose endpoints that handle object identifiers (e.g. /api/users/123/orders)."
            "If the server fails to validate that the logged-in user owns the requested object ID,"
            "attackers can manipulate IDs to access unauthorized data. Remediation: enforce authorization"
            "checks at the code/object level using user session identity, not client-supplied parameters."
        ),
    },
    {
        "id": "OWASP-API-2023-AUTH",
        "source_type": "A",
        "title": "API2:2023 Broken Authentication",
        "authority": "OWASP API Security Top 10:2023",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        "cwe": "CWE-287", "owasp": "A07",
        "passage": (
            "Broken Authentication in APIs allows attackers to compromise authentication tokens or"
            "exploit implementation flaws to assume other users' identities temporarily or permanently."
            "Common causes: weak JWT validation, missing signature checks, exposure of tokens in URLs,"
            "and lack of brute-force protection. Remediation: use robust OAuth2/OIDC standards, enforce"
            "strict signature verification on JWTs, and implement rate limiting."
        ),
    },
    {
        "id": "OWASP-API-2023-SSRF",
        "source_type": "A",
        "title": "API7:2023 Server-Side Request Forgery (SSRF)",
        "authority": "OWASP API Security Top 10:2023",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
        "cwe": "CWE-918", "owasp": "A10",
        "passage": (
            "Server-Side Request Forgery occurs when an API fetches a remote resource without validating"
            "the user-supplied URL. This allows attackers to coerce the application to send crafted requests"
            "to internal systems, cloud metadata services (e.g., 169.254.169.254), or local services."
            "Remediation: validate and sanitize all client-supplied URLs against an explicit allowlist"
            "and block requests to private IP spaces."
        ),
    },
    {
        "id": "NIST-SP-800-63B",
        "source_type": "A",
        "title": "NIST SP 800-63B Digital Identity Guidelines",
        "authority": "NIST SP 800-63B",
        "url": "https://pages.nist.gov/800-63-3/sp800-63b.html",
        "cwe": "CWE-521", "owasp": "A07",
        "passage": (
            "NIST SP 800-63B provides technical guidelines for authenticators and session management."
            "Key recommendations: allow long passphrases (up to 64+ chars), check passwords against"
            "known breached lists (HaveIBeenPwned), disallow arbitrary truncation or composition rules,"
            "and enforce secure cookie flags (Secure, HttpOnly, SameSite) for session tokens."
        ),
    },
    {
        "id": "NIST-SP-800-53",
        "source_type": "A",
        "title": "NIST SP 800-53 Rev. 5 Security Controls Baseline",
        "authority": "NIST SP 800-53 Rev. 5",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "NIST SP 800-53 controls mandate baseline security posture for information systems:"
            "AC-3 Access Enforcement, SC-8 Transmission Confidentiality and Integrity (TLS/HSTS),"
            "SI-10 Information Input Validation, and CM-6 Configuration Settings. All web applications"
            "must enforce default-deny policies and suppress internal system details."
        ),
    },
    {
        "id": "ATTACK-T1498-DOS",
        "source_type": "A",
        "title": "MITRE ATT&CK T1498 / T1499 Denial of Service",
        "authority": "MITRE ATT&CK Framework",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "cwe": "CWE-400", "owasp": "A05",
        "passage": (
            "MITRE ATT&CK T1498/T1499 details Denial of Service tradecraft used to take down web applications."
            "Attack vectors include application-layer HTTP floods, Slowloris socket exhaustion, Regular Expression"
            "Denial of Service (ReDoS), and XML entity expansion (Billion Laughs attack). Defense: enforce connection"
            "timeouts, rate-limiting on endpoints, strict request payload size caps, and non-backtracking regex engines."
        ),
    },
    {
        "id": "OWASP-HTTP-SMUGGLING",
        "source_type": "A",
        "title": "HTTP Request Smuggling & Desynchronization (CWE-444)",
        "authority": "OWASP / PortSwigger Research",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Incoming_Requests_Execution/",
        "cwe": "CWE-444", "owasp": "A05",
        "passage": (
            "HTTP Request Smuggling exploits discrepancies between front-end reverse proxies and back-end web servers"
            "when handling conflicting Content-Length and Transfer-Encoding headers. Attackers use this to bypass"
            "web application firewalls (WAF), poison web caches, and hijack other users' HTTP requests. Remediation:"
            "use HTTP/2 or HTTP/3 end-to-end, normalize HTTP headers, and reject requests with ambiguous headers."
        ),
    },
    {
        "id": "CWE-502-DESERIALIZATION",
        "source_type": "A",
        "title": "CWE-502 Deserialization of Untrusted Data",
        "authority": "MITRE CWE-502",
        "url": "https://cwe.mitre.org/data/definitions/502.html",
        "cwe": "CWE-502", "owasp": "A08",
        "passage": (
            "CWE-502: the application deserializes untrusted data without sufficient verification."
            "Attackers manipulate serialized objects to achieve Remote Code Execution (RCE), instantiate arbitrary"
            "classes, or execute arbitrary system commands. Remediation: avoid native object deserialization"
            "(e.g., Python pickle, Java Serializable, Node serialize); use safe data formats like JSON/Protobuf"
            "with strict schema validation."
        ),
    },
    {
        "id": "PCI-DSS-V4-REQ6",
        "source_type": "A",
        "title": "PCI DSS v4.0 Requirement 6.4 Public Web Application Defense",
        "authority": "PCI Security Standards Council (PCI DSS v4.0)",
        "url": "https://www.pcisecuritystandards.org/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "PCI DSS v4.0 Requirement 6.4 mandates continuous detection and prevention of web attacks on public endpoints."
            "Public-facing web applications must either undergo automated technical vulnerability security evaluations"
            "or deploy an automated technical solution (WAF) that detects and blocks web-based attacks, suppresses"
            "internal software disclosures, and enforces TLS 1.2+ transport encryption."
        ),
    },
    {
        "id": "CIS-BENCHMARK-WEBUI",
        "source_type": "A",
        "title": "CIS Web Server Benchmark Baseline",
        "authority": "Center for Internet Security (CIS Benchmarks)",
        "url": "https://www.cisecurity.org/cis-benchmarks/",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "CIS Web Server Benchmarks set concrete operational baselines for web server hardening (Nginx, Apache, IIS)."
            "Mandatory controls: suppress server version tokens (server_tokens off / ServerTokens Minimal),"
            "disable directory browsing (autoindex off / Options -Indexes), enforce Strict-Transport-Security,"
            "and restrict HTTP methods to GET, POST, and HEAD."
        ),
    },
    {
        "id": "OWASP-SCVS-SUPPLYCHAIN",
        "source_type": "A",
        "title": "OWASP Software Component Verification Standard (SCVS)",
        "authority": "OWASP SCVS Project",
        "url": "https://owasp.org/www-project-software-component-verification-standard/",
        "cwe": "CWE-1104", "owasp": "A06",
        "passage": (
            "OWASP SCVS provides a framework for supply chain security and third-party dependency verification."
            "Applications must maintain a Software Bill of Materials (SBOM), continuously check dependencies for"
            "known CVEs, remove unmaintained libraries, and ensure third-party scripts loaded via CDN match expected cryptographic hashes."
        ),
    },
    {
        "id": "OWASP-GRAPHQL-SECURITY",
        "source_type": "A",
        "title": "OWASP GraphQL Security Cheat Sheet",
        "authority": "OWASP Cheat Sheet Series",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        "cwe": "CWE-400", "owasp": "A05",
        "passage": (
            "GraphQL Security Cheat Sheet: GraphQL APIs expose single endpoints that accept dynamic query structures."
            "Key security controls: disable introspection in production, enforce query depth limiting, cost analysis"
            "caps, and rate limiting to prevent Denial of Service via circular nested queries. Enforce object-level auth."
        ),
    },
    {
        "id": "OWASP-JWT-SECURITY",
        "source_type": "A",
        "title": "OWASP JSON Web Token (JWT) Security Cheat Sheet",
        "authority": "OWASP Cheat Sheet Series",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        "cwe": "CWE-287", "owasp": "A07",
        "passage": (
            "JWT Security: JSON Web Tokens used for session handling must be cryptographically signed with strong keys."
            "Explicitly enforce algorithm whitelists (e.g. RS256/ES256/HS256 with >=256-bit secrets); reject alg='none'."
            "Enforce token expiration (exp), issuer (iss), and audience (aud) claims. Store JWTs in HttpOnly, Secure cookies."
        ),
    },
    {
        "id": "OWASP-OAUTH2-SECURITY",
        "source_type": "A",
        "title": "OWASP OAuth 2.0 Security Best Current Practice",
        "authority": "OWASP / IETF OAuth Working Group",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html",
        "cwe": "CWE-601", "owasp": "A01",
        "passage": (
            "OAuth 2.0 Security: Authorization servers and clients must mitigate token interception and phishing risks."
            "Use Proof Key for Code Exchange (PKCE) for all clients, strictly validate exact redirect URIs against a whitelist,"
            "enforce state parameter validation to prevent CSRF, and issue short-lived access tokens."
        ),
    },
    {
        "id": "OWASP-THREAT-MODELING",
        "source_type": "A",
        "title": "OWASP Threat Modeling Process & STRIDE Baseline",
        "authority": "OWASP Threat Modeling Project",
        "url": "https://owasp.org/www-community/Threat_Modeling",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "OWASP Threat Modeling provides a systematic framework for analyzing software architecture against threat models (STRIDE)."
            "Deconstruct applications into data flows, trust boundaries, and entry points. Identify threat vectors:"
            "Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege."
        ),
    },
    {
        "id": "OWASP-MICROSERVICES",
        "source_type": "A",
        "title": "OWASP Microservices Security Cheat Sheet",
        "authority": "OWASP Cheat Sheet Series",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html",
        "cwe": "CWE-285", "owasp": "A01",
        "passage": (
            "Microservices Security: Distributed microservices architecture requires Zero Trust network posture."
            "Enforce mTLS (mutual TLS) for service-to-service communication, centralized API Gateway authentication,"
            "token propagation across service boundaries, rate-limiting per API consumer, and distributed tracing."
        ),
    },
    {
        "id": "OWASP-INPUT-VALIDATION",
        "source_type": "A",
        "title": "OWASP Input Validation Cheat Sheet",
        "authority": "OWASP Cheat Sheet Series",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        "cwe": "CWE-20", "owasp": "A03",
        "passage": (
            "Input Validation Cheat Sheet: Syntactic and semantic input validation is the primary line of defense."
            "Use allow-list validation (allow specific characters, lengths, ranges, and formats) rather than block-lists."
            "Validate data as soon as it is received from untrusted sources before processing, storing, or echoing."
        ),
    },
    {
        "id": "CWE-20",
        "source_type": "A",
        "title": "CWE-20 Improper Input Validation",
        "authority": "MITRE CWE-20",
        "url": "https://cwe.mitre.org/data/definitions/20.html",
        "cwe": "CWE-20", "owasp": "A03",
        "passage": (
            "CWE-20: Improper Input Validation occurs when an application receives input from an external actor"
            "without verifying that the input has the expected properties (format, length, numeric range, syntax)."
            "Consequences include injection attacks, memory corruption, and logic flaws. Fix: strict server-side validation."
        ),
    },
    {
        "id": "CWE-78",
        "source_type": "A",
        "title": "CWE-78 OS Command Injection",
        "authority": "MITRE CWE-78",
        "url": "https://cwe.mitre.org/data/definitions/78.html",
        "cwe": "CWE-78", "owasp": "A03",
        "passage": (
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')."
            "The application constructs OS commands using untrusted input without escaping shell metacharacters"
            "(;&|`$). Attackers execute arbitrary system commands. Remediation: avoid shell execution, use parameterized APIs."
        ),
    },
    {
        "id": "CWE-94",
        "source_type": "A",
        "title": "CWE-94 Improper Control of Generation of Code ('Code Injection')",
        "authority": "MITRE CWE-94",
        "url": "https://cwe.mitre.org/data/definitions/94.html",
        "cwe": "CWE-94", "owasp": "A03",
        "passage": (
            "CWE-94: Code Injection occurs when an application accepts untrusted input and passes it to an interpreter"
            "(e.g. eval(), exec(), preg_replace with /e) that executes it as code. Impact is full server compromise."
            "Remediation: never pass user-controlled input into dynamic code evaluation functions."
        ),
    },
    {
        "id": "CWE-918",
        "source_type": "A",
        "title": "CWE-918 Server-Side Request Forgery (SSRF)",
        "authority": "MITRE CWE-918",
        "url": "https://cwe.mitre.org/data/definitions/918.html",
        "cwe": "CWE-918", "owasp": "A10",
        "passage": (
            "CWE-918: Server-Side Request Forgery occurs when a web application fetches a remote resource specified"
            "by user input without verifying the destination IP/hostname. Attackers coerce the server to request"
            "internal cloud metadata endpoints (169.254.169.254) or intranet systems. Fix: whitelist external destinations."
        ),
    },
    {
        "id": "CWE-434",
        "source_type": "A",
        "title": "CWE-434 Unrestricted Upload of File with Dangerous Type",
        "authority": "MITRE CWE-434",
        "url": "https://cwe.mitre.org/data/definitions/434.html",
        "cwe": "CWE-434", "owasp": "A05",
        "passage": (
            "CWE-434: Unrestricted File Upload occurs when an application accepts user uploads without validating file"
            "extensions, MIME types, or contents. Attackers upload web shells (.php, .jsp, .asp) into executable directories."
            "Remediation: validate file type against strict whitelist, rename files, and store uploads outside webroot."
        ),
    },
    {
        "id": "CWE-798",
        "source_type": "A",
        "title": "CWE-798 Use of Hard-coded Credentials",
        "authority": "MITRE CWE-798",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
        "cwe": "CWE-798", "owasp": "A07",
        "passage": (
            "CWE-798: Use of Hard-coded Credentials occurs when software embeds passwords, API keys, or secret keys directly"
            "in source code or configuration files. Anyone with access to the code or repository can extract the secrets."
            "Remediation: store credentials in environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager)."
        ),
    },
    {
        "id": "RFC-6749",
        "source_type": "A",
        "title": "RFC 6749 The OAuth 2.0 Authorization Framework",
        "authority": "IETF RFC 6749",
        "url": "https://datatracker.ietf.org/doc/html/rfc6749",
        "cwe": "CWE-285", "owasp": "A01",
        "passage": (
            "RFC 6749 specifies the OAuth 2.0 authorization framework. Defines four authorization grant types:"
            "Authorization Code, Implicit, Resource Owner Password Credentials, and Client Credentials."
            "Mandates TLS transport for all token endpoints, strict client authentication, and URI validation."
        ),
    },
    {
        "id": "RFC-7519",
        "source_type": "A",
        "title": "RFC 7519 JSON Web Token (JWT) Specification",
        "authority": "IETF RFC 7519",
        "url": "https://datatracker.ietf.org/doc/html/rfc7519",
        "cwe": "CWE-287", "owasp": "A07",
        "passage": (
            "RFC 7519 defines JSON Web Tokens (JWT), a compact URL-safe format for transferring claims between parties."
            "A JWT consists of Header, Payload, and Signature separated by dots. Applications must verify signatures"
            "before trusting payload contents and enforce valid exp (expiration) timestamps."
        ),
    },
    {
        "id": "RFC-8446",
        "source_type": "A",
        "title": "RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3",
        "authority": "IETF RFC 8446",
        "url": "https://datatracker.ietf.org/doc/html/rfc8446",
        "cwe": "CWE-319", "owasp": "A02",
        "passage": (
            "RFC 8446 defines TLS 1.3, providing improved security and speed over TLS 1.2. Removes legacy vulnerable ciphers"
            "(RC4, 3DES, CBC mode ciphers, static RSA key exchange) and enforces forward-secret key exchange algorithms"
            "(ECDHE / DHE). Encrypts handshake messages to prevent eavesdropping on SNI and cert details."
        ),
    },
    {
        "id": "RFC-6265",
        "source_type": "A",
        "title": "RFC 6265 HTTP State Management Mechanism (Cookie Specification)",
        "authority": "IETF RFC 6265",
        "url": "https://datatracker.ietf.org/doc/html/rfc6265",
        "cwe": "CWE-614", "owasp": "A05",
        "passage": (
            "RFC 6265 defines HTTP cookies and state management. Specifies attributes: Domain, Path, Secure, HttpOnly, Max-Age,"
            "and SameSite. Mandates that Secure cookies are sent only over HTTPS and HttpOnly cookies are inaccessible to JS."
        ),
    },
    {
        "id": "RFC-9113",
        "source_type": "A",
        "title": "RFC 9113 HTTP/2 Protocol Specification",
        "authority": "IETF RFC 9113",
        "url": "https://datatracker.ietf.org/doc/html/rfc9113",
        "cwe": "CWE-444", "owasp": "A05",
        "passage": (
            "RFC 9113 specifies HTTP/2 binary framing layer. Replaces line-based HTTP/1 headers with binary frames and HPACK compression."
            "Eliminates HTTP Request Smuggling (CWE-444) caused by conflicting Content-Length and Transfer-Encoding headers by encoding payload lengths natively."
        ),
    },
    {
        "id": "OWASP-LLM-TOP10-2025",
        "source_type": "A",
        "title": "OWASP Top 10 for LLM Applications 2025 (v2.0)",
        "authority": "OWASP GenAI Security Project",
        "url": "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/",
        "cwe": "CWE-20", "owasp": "A03",
        "passage": (
            "(Free official standard, CC BY-SA 4.0.) The ten most critical risks in"
            "LLM-backed applications: LLM01 prompt injection - hostile input embedded"
            "in prompts, including indirectly via fetched content, steers the model"
            "against the operator's intent; LLM02 sensitive information disclosure;"
            "LLM03 supply-chain threats from unverified third-party models and"
            "datasets; LLM04 data and model poisoning; LLM05 improper output handling"
            "- unvalidated model output enables downstream XSS, SSRF, or code"
            "execution; LLM06 excessive agency, urging least-privilege permissions"
            "for tools; LLM07 system-prompt leakage - secrets must never live in"
            "prompts; LLM08 vector and embedding weaknesses in RAG; LLM09"
            "misinformation; LLM10 unbounded consumption / denial-of-wallet."
            "Critical controls must be enforced deterministically outside the model."
        ),
    },
    {
        "id": "OWASP-MASTG",
        "source_type": "A",
        "title": "OWASP Mobile Application Security Testing Guide (MASTG) v1.5.0",
        "authority": "OWASP Mobile Application Security Project",
        "url": "https://mas.owasp.org/MASTG/",
        "cwe": "CWE-312", "owasp": "A02",
        "passage": (
            "(Free official standard, CC BY-SA 4.0.) The practical companion to MASVS:"
            "how to test mobile app security and verify each MASVS requirement. Covers"
            "scoping, threat modeling, and white-box vs black-box choices; static and"
            "dynamic analysis; OS-specific detail for Android and iOS - where data is"
            "stored at rest, in transit, and in use; inspecting Keychain/Keystore use;"
            "crypto-API and TLS configuration testing; platform interaction such as"
            "intents, broadcasts, and content providers; tamper resistance and reverse-"
            "engineering defenses (root/jailbreak detection, anti-debugging); and"
            "privacy protections. Mobile security is fundamentally about protecting"
            "sensitive data on devices that are easily lost or stolen, and every MASVS"
            "control needs a concrete, reproducible testing technique."
        ),
    },
    {
        "id": "OWASP-MASVS",
        "source_type": "A",
        "title": "OWASP Mobile Application Security Verification Standard (MASVS) v2.0.0",
        "authority": "OWASP Mobile Application Security Project",
        "url": "https://mas.owasp.org/MASVS/",
        "cwe": "CWE-312", "owasp": "A02",
        "passage": (
            "(Free official standard, CC BY-SA 4.0.) Defines what a secure mobile"
            "application must do: an industry-standard set of requirements for"
            "designing, building, and verifying mobile apps. Mobile security is"
            "essentially data protection - phones hold passwords and personal data and"
            "are frequently lost - and mature platform APIs only help when implemented"
            "correctly. Control groups cover architecture and threat modeling; data"
            "storage and privacy; cryptography and key lifecycle; authentication and"
            "session management; network communication including TLS and cert/key"
            "pinning; platform interaction (IPC, URL schemes, intents); code quality"
            "and build settings; and resilience against tampering. The 2023 rework"
            "replaced L1/L2/R levels with security-testing profiles aligned to NIST"
            "OSCAL. Automated tools alone cannot complete verification - every app"
            "needs expert manual judgment."
        ),
    },
    {
        "id": "NIST-SP-800-61",
        "source_type": "A",
        "title": "NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide",
        "authority": "NIST SP 800-61 (superseded by Rev. 3)",
        "url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
        "cwe": "CWE-16", "owasp": "A09",
        "passage": (
            "(Free official standard, public domain.) The foundational incident-"
            "response reference built on a four-phase lifecycle: preparation; detection"
            "and analysis; containment, eradication, and recovery; and post-incident"
            "activity. Preparation means an IR policy, plan, SOPs, and a resourced team"
            "with clear roles. Detection and analysis distinguishes events from"
            "incidents, documents everything, and prioritizes by functional impact,"
            "information impact, and recoverability - not first-come, first-served."
            "Containment chooses a strategy and handles evidence properly; eradication"
            "precedes recovery; post-incident activity focuses on lessons learned."
            "Note: Rev. 2 (2012) was withdrawn in April 2025 and superseded by"
            "SP 800-61r3, which recasts IR as a CSF 2.0 community profile."
        ),
    },
    {
        "id": "FTC-SMB-CYBERSEC",
        "source_type": "A",
        "title": "Cybersecurity for Small Business (FTC guidance)",
        "authority": "U.S. Federal Trade Commission",
        "url": "https://www.ftc.gov/business-guidance/small-businesses/cybersecurity",
        "cwe": "CWE-287", "owasp": "A07",
        "passage": (
            "(Free official guidance, public domain.) Plain-language controls every"
            "small firm can take because attackers target companies of all sizes:"
            "keep software updated automatically; back up files offline or to the"
            "cloud so ransomware cannot hold data hostage; require strong unique"
            "passwords and use password managers; enable MFA, especially for network"
            "access; limit failed login attempts; and encrypt devices holding personal"
            "information. Covers phishing, ransomware, and bogus tech-support scams,"
            "and what to do after an incident: change compromised passwords,"
            "disconnect infected machines, report to law enforcement, and notify"
            "affected customers. Recommends a written incident-response plan, staff"
            "training, email authentication, and HTTPS, mapped to the NIST CSF 2.0"
            "functions."
        ),
    },
    {
        "id": "REF-POSITIVE-WAF-BYPASS",
        "source_type": "A",
        "title": "Methods to Bypass a Web Application Firewall",
        "authority": "Positive Technologies (Dmitri Evteev)",
        "url": "https://pt-corp.storage.yandexcloud.net/upload/corporate/ww-en/download/PT-devteev-CC-WAF-ENG.pdf",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "(Free vendor presentation, Positive Technologies, 2009.) Argues a WAF is"
            "not a silver bullet: filters only screen attack vectors without removing"
            "vulnerabilities. Demonstrates bypasses across three classes with concrete"
            "HTTP requests. SQL injection: normalization vulnerabilities where comment"
            "markers the filter strips leave a valid payload; HTTP Parameter Pollution"
            "and fragmentation that reassemble payloads server-side; logical AND/OR"
            "blind injection with inequality operators; function synonyms; and direct"
            "signature bypass. XSS: DOM-based attacks filters cannot see, plus HPP and"
            "signature evasion. Path traversal, local/remote file inclusion via"
            "null-byte replacement and data: URIs. Lesson: filters must be tuned per"
            "application and offer only temporary, echeloned protection."
        ),
    },
    {
        "id": "REF-XSS-CHEATSHEET-BRUTE",
        "source_type": "A",
        "title": "XSS Cheat Sheet (Brute Logic, 2018)",
        "authority": "Rodolfo Assis (Brute Logic)",
        "url": "https://brutelogic.com.br/blog/xss-cheat-sheet/",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Free reference cheat sheet, 2018.) A quick-reference booklet for bug"
            "hunters, pentesters, and analysts mapping XSS payloads to the exact HTML,"
            "JavaScript, or attribute context where input lands: simple tag injection,"
            "in-block injection inside title/style/textarea/iframe, inline attribute"
            "injection when a tag cannot be closed, and escaped-quote scenarios."
            "Advanced vectors: closing a script block, javascript: and data: URIs,"
            "event-handler tricks, and polyglot vectors using unusual characters and"
            "encoding. Filter bypass covers WAF evasion via URL fragments, base-tag"
            "hijacking, GIF/JS disguises to defeat CSP, and an ASCII/encoding table."
            "Includes a blind-XSS mailer script and postMessage-based DOM injection."
            "Confirms the auditor's stance that XSS must be detected in every"
            "reflection context and that CSP alone is bypassable."
        ),
    },
]

SOURCE_B = [
    {
        "id": "BOOK-THONGBAM-APPSEC",
        "source_type": "B",
        "title": "Application Security: The Big Picture",
        "author": "Mohammed Thongbam",
        "publisher": "O'Reilly Media",
        "year": 2021,
        "url": "https://www.oreilly.com/library/view/application-security-the/9781801072541/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, O'Reilly.) This title frames application security as a"
            "lifecycle: threat modeling, secure design, implementation reviews, and"
            "verification. It stresses that most breaches stem from misconfiguration and"
            "broken access control, and that a baseline of security headers, TLS, and input"
            "validation must be enforced by default rather than bolted on later. Use it as"
            "the 'why secure by default' backbone for this auditor's rules."
        ),
    },
    {
        "id": "BOOK-STUTTARD-WAHH",
        "source_type": "B",
        "title": "The Web Application Hacker's Handbook",
        "author": "Dafydd Stuttard & Marcus Pinto",
        "publisher": "Wiley",
        "year": 2011,
        "url": "https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%3A+Finding+and+Exploiting+Security+Flaws%2C+2nd+Edition-p-9781118026472",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "(Curated book, Wiley.) Lessons from the canonical web-pentest methodology:"
            "map the application's content and functionality - including content hidden"
            "behind login via session-authenticated spidering - then analyze the attack"
            "surface and test each class of flaw. Any user-controllable input reaching a"
            "backend interpreter is a candidate for injection: SQL, OS commands, and XML"
            "external entity (XXE) abuse. Parameter tampering drives access-control and"
            "logic flaws, such as iterating another user's identifiers to reach private"
            "data. Defend by validating input with 'accept known good' whitelists (which"
            "blocklists and NULL-byte/encoding tricks defeat), using parameterized"
            "queries, and centralizing authorization decisions server-side. Apply least"
            "privilege at every tier - role-scoped application logic down to read-only"
            "database accounts - codified in a privilege matrix."
        ),
    },
    {
        "id": "BOOK-KBEITI-APPSEC",
        "source_type": "B",
        "title": "Application Security: From Birth to Production",
        "author": "Anand Kbeiti",
        "publisher": "Independently published (Manning-style)",
        "year": 2023,
        "url": "https://www.manning.com/books/application-security",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book.) Focuses on embedding security into CI/CD: automated dependency"
            "scanning, header baselines, TLS posture, and secret management. Reinforces"
            "that these checks belong in an automated auditor that runs on every build --"
            "exactly what websec-auditor provides."
        ),
    },
    {
        "id": "BOOK-OWASP-ASVS-BOOK",
        "source_type": "B",
        "title": "The OWASP Application Security Verification Standard (ASVS)",
        "author": "OWASP Foundation",
        "publisher": "OWASP (open standard)",
        "year": 2021,
        "url": "https://owasp.org/www-project-application-security-verification-standard/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated open standard, OWASP.) ASVS defines L1/L2/L3 verification"
            "requirements. V9 (communications), V6 (stored crypto), V3 (session"
            "management), and V5 (access control) are the contractual basis for the header,"
            "TLS, cookie, and access-control checks in this tool. A site failing L1 should"
            "not be deployed."
        ),
    },
    {
        "id": "BOOK-HOFFMAN-WEBAPP",
        "source_type": "B",
        "title": "Web Application Security: Exploitation and Countermeasures for Modern Web Applications (2nd ed.)",
        "author": "Andrew Hoffman",
        "publisher": "O'Reilly Media",
        "year": 2024,
        "url": "https://www.oreilly.com/library/view/web-application-security/9781098143923/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, O'Reilly, 2024.) Hoffman's updated classic organizes"
            "application security into three pillars - reconnaissance, offense, and defense"
            "- and maps modern attack surfaces (DOM/JavaScript issues, GraphQL, CDN and"
            "server-side rendering deployments) to concrete countermeasures. It reinforces"
            "this auditor's stance that a finding must pair an exploit technique with a"
            "specific, verifiable mitigation, and that security checks belong throughout"
            "the SDLC rather than bolted on at release time."
        ),
    },
    {
        "id": "BOOK-MCDONALD-GROKKING",
        "source_type": "B",
        "title": "Grokking Web Application Security",
        "author": "Malcolm McDonald",
        "publisher": "Manning",
        "year": 2024,
        "url": "https://www.manning.com/books/grokking-web-application-security",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Curated book, Manning, 2024; free extract at livebook.manning.com.) A"
            "developer-first walkthrough of OWASP-class vulnerabilities - injection, XSS,"
            "broken authentication and access control, CSRF - each shown as a reproducible"
            "exploit followed by the fixing pattern. It grounds this auditor's rule set by"
            "tying every check (headers, cookie flags, input reflection, error handling) to"
            "an attack the developer can reproduce and a fix they can deploy."
        ),
    },
    {
        "id": "BOOK-JOHNSSON-SECURE-BY-DESIGN",
        "source_type": "B",
        "title": "Secure by Design",
        "author": "Dan Bergh Johnsson, Daniel Deogun & Daniel Sawano",
        "publisher": "Manning",
        "year": 2019,
        "url": "https://www.manning.com/books/secure-by-design",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, Manning, 2019.) Argues that security must be designed into"
            "software architecture from the start instead of bolted on afterward: threat"
            "modeling early, least privilege, defense in depth, and explicit failure"
            "handling. Its principles underpin the auditor's 'secure by default' baseline -"
            "correct configuration should be the default, not an afterthought."
        ),
    },
    {
        "id": "BOOK-RICHER-OAUTH2",
        "source_type": "B",
        "title": "OAuth 2 in Action",
        "author": "Justin Richer & Antonio Sanso",
        "publisher": "Manning",
        "year": 2017,
        "url": "https://www.manning.com/books/oauth-2-in-action",
        "cwe": "CWE-287", "owasp": "A07",
        "passage": (
            "(Curated book, Manning, 2017.) The definitive practical guide to OAuth 2.0 and"
            "OpenID Connect: grant types, token lifecycle, redirect-URI handling, and CSRF"
            "protection for authorization endpoints. It informs the auditor's session and"
            "access-control checks - tokens and cookies must travel only over TLS with the"
            "proper flags, and authorization decisions must be enforced server-side."
        ),
    },
    {
        "id": "BOOK-SPILCA-SPRING-SEC",
        "source_type": "B",
        "title": "Spring Security in Action",
        "author": "Laurentiu Spilca",
        "publisher": "Manning",
        "year": 2020,
        "url": "https://www.manning.com/books/spring-security-in-action",
        "cwe": "CWE-285", "owasp": "A01",
        "passage": (
            "(Curated book, Manning, 2020.) A hands-on guide to securing Spring"
            "applications: authentication flows, method-level and URL authorization, CSRF"
            "protection, session-fixation defense, and security-header configuration. It"
            "demonstrates how the auditor's recommended controls - headers, cookie flags,"
            "TLS, input validation - are implemented in a mainstream enterprise framework."
        ),
    },
    {
        "id": "BOOK-SKOUDIS-COUNTERHACK",
        "source_type": "B",
        "title": "Counter Hack Reloaded: A Step-by-Step Guide to Computer Attacks and Effective Defenses (2nd ed.)",
        "author": "Ed Skoudis",
        "publisher": "Prentice Hall (Pearson)",
        "year": 2005,
        "url": "https://www.oreilly.com/library/view/counter-hack-reloaded/9780131481046/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated anti-hacking book, Prentice Hall.) The classic pairing of attack"
            "techniques with their effective defenses: it walks through each class of"
            "intrusion - network scanning, gaining and holding access, web and application"
            "attacks - and for every one shows the defensive countermeasure. Its core"
            "premise matches this auditor: you cannot defend what you have not enumerated,"
            "so checks must map an exploit surface to a concrete, deployable fix."
        ),
    },
    {
        "id": "BOOK-BROTHERSTON-DEFENSIVE",
        "source_type": "B",
        "title": "Defensive Security Handbook (2nd ed.)",
        "author": "Lee Brotherston & Amanda Berlin",
        "publisher": "O'Reilly Media",
        "year": 2024,
        "url": "https://www.oreilly.com/library/view/defensive-security-handbook/9781098127237",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated anti-hacking/defensive book, O'Reilly, 2024.) A pragmatic playbook"
            "for organizations with limited security budget: incident response,"
            "vulnerability scanning, secure network and password management, hardening, and"
            "compliance. It backs the auditor's 'secure by default' philosophy -"
            "measurable, low-cost hardening controls (headers, TLS, patching, least"
            "privilege) - and its incident focus is why a scanner should flag weaknesses"
            "before they become breaches."
        ),
    },
    {
        "id": "BOOK-ZALEWSKI-TANGLED",
        "source_type": "B",
        "title": "The Tangled Web: A Guide to Securing Modern Web Applications",
        "author": "Michal Zalewski",
        "publisher": "No Starch Press",
        "year": 2011,
        "url": "https://nostarch.com/tangledweb",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Curated book, No Starch Press, 2011.) Lessons from the browser-security"
            "treatise: the same-origin policy is not one rule but a family of loosely"
            "enforced conventions that diverge between components - plug-ins make their"
            "own origin decisions, and DNS rebinding shows how origin checks based on a"
            "hostname rather than an IP let an attacker pivot from a public address to"
            "an internal one and reach private networks. Referer headers, form"
            "submissions, and frames each leak data or invite cross-site requests, and"
            "content sniffing misidentifies payload types, which is why explicit"
            "Content-Type matters. XSS and data theft are consequences of a broken trust"
            "model, not isolated input bugs. Practical controls distilled into per-"
            "chapter cheat sheets: HSTS, Content-Security-Policy, X-Content-Type-"
            "Options: nosniff, and careful frame navigation. User-interface trust is"
            "fragile - security must be enforced by the platform, not the human."
        ),
    },
    {
        "id": "BOOK-SIKORSKI-MALWARE",
        "source_type": "B",
        "title": "Practical Malware Analysis",
        "author": "Michael Sikorski & Andrew Honig",
        "publisher": "No Starch Press",
        "year": 2012,
        "url": "https://nostarch.com/malware",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated anti-hacking/defense book, No Starch Press.) The standard lab-based"
            "manual for dissecting malicious software in a safe environment: behavioral and"
            "static analysis, debugging, packing, and persistence techniques. It grounds"
            "the defensive rationale behind this auditor's read-only approach - understand"
            "how an attacker's payload behaves so you can detect and block it - and why"
            "safe, non-destructive probing is the right way to assess a target."
        ),
    },
    {
        "id": "BOOK-VEHENT-SECDEVOPS",
        "source_type": "B",
        "title": "Securing DevOps",
        "author": "Julien Vehent",
        "publisher": "Manning",
        "year": 2018,
        "url": "https://www.manning.com/books/securing-devops",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, Manning, 2018.) Security woven into the delivery pipeline: TLS"
            "for internal services, secrets management, monitoring and logging, and"
            "continuous vulnerability assessment. It justifies the auditor's"
            "automation-first design - security checks should run continuously on every"
            "build and every environment, not as a one-off manual review."
        ),
    },
    {
        "id": "BOOK-BYRNE-PYTHON-SEC",
        "source_type": "B",
        "title": "Full Stack Python Security",
        "author": "Dennis Byrne",
        "publisher": "Manning",
        "year": 2021,
        "url": "https://www.manning.com/books/full-stack-python-security",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Curated anti-hacking book, Manning, 2021.) Practical defenses implemented in"
            "a real web stack: encryption and TLS, authentication, authorization and"
            "permissions, injecting a Content-Security-Policy, and neutralizing XSS, CSRF,"
            "and SQL injection. It is the 'make it real' companion to this auditor's"
            "recommendations - each header, cookie flag, and encoding fix has a concrete,"
            "runnable implementation."
        ),
    },
    {
        "id": "BOOK-MITCHELL-WEBSCRAPING",
        "source_type": "B",
        "title": "Web Scraping with Python (3rd ed.)",
        "author": "Ryan Mitchell",
        "publisher": "O'Reilly Media",
        "year": 2024,
        "url": "https://www.oreilly.com/library/view/web-scraping-with/9781098145347",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, O'Reilly, 2024.) The standard reference for crawling and"
            "scraping: requests, Beautiful Soup, link and form traversal, sitemaps, and"
            "polite crawling with rate limits. Its crawling patterns - parse links,"
            "normalize URLs, deduplicate, respect depth and robots - are the engineering"
            "basis for the auditor's site-wide discovery loop, which must be bounded,"
            "same-origin, and respectful of the target's control files."
        ),
    },
    {
        "id": "BOOK-SEITZ-BLACKHAT",
        "source_type": "B",
        "title": "Black Hat Python (2nd ed.)",
        "author": "Justin Seitz & Tim Arnold",
        "publisher": "No Starch Press",
        "year": 2021,
        "url": "https://nostarch.com/black-hat-python-2nd-edition",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2nd ed.) Builds offensive tooling in Python -"
            "proxies, sniffers, and web-hacking utilities - with the ethic that tools are"
            "used only on systems you own or are authorized to test. Its web chapters show"
            "practical request crafting and response parsing that underpin a security"
            "crawler: fetch, extract structure, and drive requests programmatically against"
            "authorized targets."
        ),
    },
    {
        "id": "BOOK-WEIDMAN-PENTESTING",
        "source_type": "B",
        "title": "Penetration Testing: A Hands-On Introduction to Hacking",
        "author": "Georgia Weidman",
        "publisher": "No Starch Press",
        "year": 2014,
        "url": "https://nostarch.com/pentesting",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2014.) A hands-on introduction to the"
            "penetration-testing process - reconnaissance, scanning, exploitation, and"
            "post-exploitation - with emphasis on building a lab and testing only"
            "authorized targets. Its structured methodology mirrors the auditor's workflow:"
            "inventory the attack surface, enumerate entry points, then verify weaknesses"
            "with safe, non-destructive probes."
        ),
    },
    {
        "id": "BOOK-YAWORSKI-BUGHUNTING",
        "source_type": "B",
        "title": "Real-World Bug Hunting: A Field Guide to Web Hacking",
        "author": "Peter Yaworski",
        "publisher": "No Starch Press",
        "year": 2019,
        "url": "https://nostarch.com/bughunting",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Curated book, No Starch Press, 2019.) Walks through real bug-bounty writeups"
            "- open redirects, XSS, SQL injection, SSRF, and access control - showing how"
            "professional testers find and report flaws on live targets. It is the"
            "practical companion to the auditor's findings: each bug class explains what"
            "the vulnerability is, why it matters, and how a responsible report is written."
        ),
    },
    {
        "id": "BOOK-LI-BUGBOUNTY",
        "source_type": "B",
        "title": "Bug Bounty Bootcamp",
        "author": "Vickie Li",
        "publisher": "No Starch Press",
        "year": 2021,
        "url": "https://nostarch.com/bug-bounty-bootcamp",
        "cwe": "CWE-639", "owasp": "A01",
        "passage": (
            "(Curated book, No Starch Press, 2021.) Lessons from the bug-hunting field"
            "guide: process discipline first - read a program's policy and scope, build"
            "a lab, and write high-quality reports. Reconnaissance comes next: passive"
            "OSINT, port scanning, directory brute-forcing (which surfaces leaked .svn"
            "and .htaccess files), mining JavaScript bundles and GitHub repos, and"
            "fuzzing for predictable API endpoints. Each weakness is a reusable test:"
            "IDOR by swapping identifiers; open redirects via referer-based systems;"
            "SSRF chained to cloud metadata endpoints like 169.254.169.254 to harvest"
            "instance credentials; and server-side template injection in Jinja2 escaping"
            "to the os module. Bugs chain: an open redirect on a logout endpoint can"
            "smuggle OAuth tokens offsite into account takeover. Defend with strict"
            "allowlist redirect validation, object-level authorization on every"
            "resource, blocked metadata routes, and sandboxed templates."
        ),
    },
    {
        "id": "BOOK-BALL-HACKINGAPIS",
        "source_type": "B",
        "title": "Hacking APIs",
        "author": "Corey Ball",
        "publisher": "No Starch Press",
        "year": 2022,
        "url": "https://nostarch.com/hacking-apis",
        "cwe": "CWE-639", "owasp": "A01",
        "passage": (
            "(Curated book, No Starch Press, 2022.) Lessons from the API security"
            "crash-course: respect scope and rules of engagement (AWS, GCP, and Azure"
            "each publish what testing they allow), and threat-model the attacker"
            "profile before over-engineering the test. Discovery is central - after"
            "passive OSINT, wordlist-driven scanning reveals undocumented endpoints,"
            "and the REST convention of predictable /resource/id patterns lets testers"
            "deduce new paths. Test each endpoint by intended use first, then replay"
            "and fuzz every parameter - a potential sink for injection and NoSQL"
            "operators. The API-specific clusters: broken authentication (JWT attacks,"
            "insecure password reset), broken object-level authorization where swapping"
            "an identifier reaches another user's data, and mass assignment where an"
            "extra field flips sensitive variables or resets credentials and bypasses"
            "MFA. Injection (SQL/NoSQL/command) and GraphQL issues round out the"
            "catalog."
        ),
    },
    {
        "id": "BOOK-KENNEDY-METASPLOIT",
        "source_type": "B",
        "title": "Metasploit: The Penetration Tester's Guide (2nd ed.)",
        "author": "David Kennedy, Mati Aharoni, Devon Kearns, Jim O'Gorman, Daniel Graham",
        "publisher": "No Starch Press",
        "year": 2024,
        "url": "https://nostarch.com/metasploit-2nd-edition",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2nd ed., 2024.) The definitive guide to the"
            "Metasploit Framework - reconnaissance, vulnerability analysis, exploitation,"
            "and post-exploitation - aligned with the PTES methodology. Its emphasis on a"
            "structured, authorized penetration-testing process from intelligence gathering"
            "to reporting is the same discipline the auditor encodes in its bounded,"
            "consent-only scan loop."
        ),
    },
    {
        "id": "BOOK-ALCORN-BROWSERHACK",
        "source_type": "B",
        "title": "The Browser Hacker's Handbook",
        "author": "Wade Alcorn, Christian Frichot, Michele Orru",
        "publisher": "Wiley",
        "year": 2014,
        "url": "https://www.wiley.com/en-us/The%2BBrowser%2BHacker%27s%2BHandbook-p-9781118662090",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Curated book, Wiley, 2014.) A complete treatment of the browser attack"
            "surface - XSS, CSRF, clickjacking, and same-origin policy bypasses - using the"
            "browser as a pivot into the network. It grounds the auditor's client-side"
            "checks: reflected injection, missing security headers, and form protections"
            "are exactly the classes this handbook explains from the attacker's"
            "perspective."
        ),
    },
    {
        "id": "BOOK-ERICKSON-EXPLOITATION",
        "source_type": "B",
        "title": "Hacking: The Art of Exploitation (2nd ed.)",
        "author": "Jon Erickson",
        "publisher": "No Starch Press",
        "year": 2008,
        "url": "https://nostarch.com/hacking2.htm",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2nd ed., 2008.) The classic foundation text:"
            "from C and machine architecture to buffer overflows, shellcode, and network"
            "attacks, explaining how exploitation actually works. Its countermeasures"
            "chapter motivates the auditor's defensive checks - every mitigation it"
            "describes maps to a header, encoding rule, or configuration that the audit"
            "verifies."
        ),
    },
    {
        "id": "BOOK-STEELE-BLACKHATGO",
        "source_type": "B",
        "title": "Black Hat Go",
        "author": "Tom Steele, Chris Patten & Dan Kottmann",
        "publisher": "No Starch Press",
        "year": 2020,
        "url": "https://nostarch.com/blackhatgo",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2020.) Builds offensive tooling in Go - HTTP"
            "clients and servers, proxies, port scanners, and command-and-control utilities"
            "- with an explicit ethic of testing only authorized targets. Its web chapters"
            "show how to craft and inspect HTTP requests and responses programmatically,"
            "the same mechanics that drive a deterministic security crawler: request,"
            "parse, and verify against a target you own or are authorized to test."
        ),
    },
    {
        "id": "BOOK-SPARC-HACKGHOST",
        "source_type": "B",
        "title": "How to Hack Like a Ghost",
        "author": "Sparc Flow",
        "publisher": "No Starch Press",
        "year": 2021,
        "url": "https://nostarch.com/how-hack-ghost",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2021.) A narrative walkthrough of a full"
            "compromise - reconnaissance, initial access, lateral movement, and persistence"
            "- drawn from real-world attack tradecraft. Its emphasis on disciplined,"
            "non-destructive reconnaissance and on confirming each step with evidence is"
            "the same consent-only, verify-before-asserting discipline this auditor encodes"
            "in its scan loop."
        ),
    },
    {
        "id": "BOOK-SHOSTACK-THREATMODEL",
        "source_type": "B",
        "title": "Threat Modeling: Designing for Security",
        "author": "Adam Shostack",
        "publisher": "Wiley",
        "year": 2014,
        "url": "https://www.wiley.com/en-us/Threat%2BModeling%3A%2BDesigning%2Bfor%2BSecurity-p-9781118809990",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, Wiley, 2014.) The standard work on threat modeling: enumerate"
            "assets and entry points, then apply structured methods (STRIDE, attack trees,"
            "kill-chain thinking) to decide what can go wrong and how to test for it. Its"
            "four-question framework - what are we building, what can go wrong, what will"
            "we do, did we do a good job - is the design-time counterpart to this auditor's"
            "runtime checks: know the surface before you probe it."
        ),
    },
    {
        "id": "BOOK-AUMASSON-SERIOUSCRYPTO",
        "source_type": "B",
        "title": "Serious Cryptography: A Practical Introduction to Modern Encryption (2nd ed.)",
        "author": "Jean-Philippe Aumasson",
        "publisher": "No Starch Press",
        "year": 2024,
        "url": "https://nostarch.com/serious-cryptography-2nd-edition",
        "cwe": "CWE-326", "owasp": "A02",
        "passage": (
            "(Curated book, No Starch Press, 2nd ed., 2024.) A practical, math-light"
            "introduction to modern cryptography: randomness, authenticated encryption,"
            "hashing, RSA and elliptic curves, TLS, and post-quantum algorithms - with a"
            "'what can go wrong' section per topic. It is the reference behind the"
            "auditor's cryptographic checks: TLS version and cipher strength, HSTS, unique"
            "salts with slow password hashes, and the avoidance of MD5/SHA1/RC4/DES."
        ),
    },
    {
        "id": "BOOK-FORSHAW-NETPROTOCOLS",
        "source_type": "B",
        "title": "Attacking Network Protocols: A Hacker's Guide to Capture, Analysis, and Exploitation",
        "author": "James Forshaw",
        "publisher": "No Starch Press",
        "year": 2017,
        "url": "https://nostarch.com/networkprotocols",
        "cwe": "CWE-319", "owasp": "A02",
        "passage": (
            "(Curated book, No Starch Press, 2017.) A deep dive into discovering,"
            "capturing, analyzing, and exploiting network protocols - traffic capture,"
            "fuzzing, authentication bypasses, and denial of service - from a leading"
            "Google Project Zero researcher. Its protocol-analysis mindset (enumerate"
            "fields, probe parsing, confirm with an exploit) mirrors how the auditor maps a"
            "web application's parameters and entry points before testing each one."
        ),
    },
    {
        "id": "BOOK-NANCE-GHIDRA",
        "source_type": "B",
        "title": "The Ghidra Book, 2nd Edition: The Definitive Guide",
        "author": "Kara Nance & Chris Eagle",
        "publisher": "No Starch Press",
        "year": 2026,
        "url": "https://nostarch.com/ghidra-book-2e",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2nd ed., 2026.) The definitive guide to the"
            "Ghidra reverse-engineering suite - disassembly, decompilation, PyGhidra"
            "scripting, and collaborative analysis. It grounds the auditor's careful,"
            "non-destructive approach: understand exactly how code and configuration behave"
            "before asserting a weakness, rather than guessing from observable responses"
            "alone."
        ),
    },
    {
        "id": "BOOK-LIM-DAYZERO",
        "source_type": "B",
        "title": "From Day Zero to Zero Day: A Hands-On Guide to Vulnerability Research",
        "author": "Eugene Lim",
        "publisher": "No Starch Press",
        "year": 2025,
        "url": "https://nostarch.com/zero-day",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2025.) A hands-on guide to vulnerability"
            "research: taint analysis, mapping code to attack surface, coverage-guided"
            "fuzzing, symbolic execution, and building proof-of-concept exploits while"
            "retracing real CVEs. Its disciplined method - identify the surface, trace"
            "untrusted input to a sink, confirm with a minimal PoC - is the same"
            "evidence-first pattern the auditor applies to every web finding."
        ),
    },
    {
        "id": "BOOK-ERDMANN-REDTEAM",
        "source_type": "B",
        "title": "Red Team Engineering: The Art of Building Offensive Tools and Infrastructure",
        "author": "Casey Erdmann",
        "publisher": "No Starch Press",
        "year": 2026,
        "url": "https://nostarch.com/red-team-engineering",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2026.) Goes beyond running scripts to"
            "engineering offensive infrastructure - credential-harvesting apps, password"
            "attacks, C2 servers and redirectors, and reproducible cloud deployment - with"
            "a professional, authorized-engagement discipline. Its project-based"
            "walkthrough of the full attack lifecycle is what the auditor's findings are"
            "meant to pre-empt on a defended web application."
        ),
    },
    {
        "id": "BOOK-MADDEN-APISEC",
        "source_type": "B",
        "title": "API Security in Action",
        "author": "Neil Madden",
        "publisher": "Manning Publications",
        "year": 2020,
        "url": "https://www.manning.com/books/api-security-in-action",
        "cwe": "CWE-285", "owasp": "A01",
        "passage": (
            "(Curated book, Manning, 2020.) The standard reference for modern REST/JSON API security."
            "Covers OAuth2, OpenID Connect, JWT tokens, CORS policy, rate limiting, and HMAC signatures."
            "Emphasizes default-deny authorization on API endpoints and token validation best practices."
        ),
    },
    {
        "id": "BOOK-JANCA-APPSEC",
        "source_type": "B",
        "title": "Alice and Bob Learn Application Security",
        "author": "Tanya Janca",
        "publisher": "Wiley",
        "year": 2020,
        "url": "https://www.wiley.com/en-us/Alice+and+Bob+Learn+Application+Security-p-9781119687351",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, Wiley, 2020.) Fundamental application security concepts for software engineers:"
            "threat modeling, input validation, output encoding, security headers, dependency scanning,"
            "and integrating security into modern CI/CD pipelines."
        ),
    },
    {
        "id": "BOOK-SEITZ-BLACKHATPY",
        "source_type": "B",
        "title": "Black Hat Python (2nd Ed): Python Programming for Hackers and Pentesters",
        "author": "Justin Seitz & Tim Arnold",
        "publisher": "No Starch Press",
        "year": 2021,
        "url": "https://nostarch.com/black-hat-python-2nd-edition",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2nd ed., 2021.) Practical Python security programming:"
            "raw socket manipulation, HTTP request crafting, web scraping, and automated security inspection."
            "Provides the foundational mechanics behind deterministic Python web security auditors."
        ),
    },
    {
        "id": "BOOK-KIM-PLAYBOOK3",
        "source_type": "B",
        "title": "The Hacker Playbook 3: Practical Guide To Penetration Testing",
        "author": "Peter Kim",
        "publisher": "Secure Planet LLC",
        "year": 2018,
        "url": "https://hackerplaybook.com/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, Secure Planet, 2018.) Red team playbooks detailing offensive web campaigns:"
            "web app entry points, persistence via web shells, command execution, and anti-evasion techniques."
            "Directly informs defensive rules to detect unescaped command parameters and exposed upload directories."
        ),
    },
    {
        "id": "BOOK-KETTLE-SMUGGLING",
        "source_type": "B",
        "title": "HTTP Request Smuggling: Advanced Request Hijacking & Desynchronization",
        "author": "James Kettle",
        "publisher": "PortSwigger Research",
        "year": 2019,
        "url": "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
        "cwe": "CWE-444", "owasp": "A05",
        "passage": (
            "(Curated research, PortSwigger, 2019.) Breakthrough research on HTTP request smuggling (CL.TE / TE.CL)."
            "Exploits front-end proxy vs back-end server desynchronization to poison caches, bypass WAF controls,"
            "and hijack victim sessions. Mitigation: reject ambiguous Content-Length / Transfer-Encoding headers."
        ),
    },
    {
        "id": "BOOK-FLOW-HACKLEGEND",
        "source_type": "B",
        "title": "How to Hack Like a Legend",
        "author": "Sparc Flow",
        "publisher": "No Starch Press",
        "year": 2022,
        "url": "https://nostarch.com/how-hack-legend",
        "cwe": "CWE-400", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2022.) Tactical walkthrough of advanced web application exploitation"
            "and denial-of-service vectors. Demonstrates how threat actors target unthrottled endpoints and heavy queries"
            "to crash web services. Defense: rate limiting, query execution limits, and strict memory/timeout limits."
        ),
    },
    {
        "id": "BOOK-ZALEWSKI-SILENCE",
        "source_type": "B",
        "title": "Silence on the Wire: A Field Guide to Passive Network Observation and Security",
        "author": "Michal Zalewski",
        "publisher": "No Starch Press",
        "year": 2005,
        "url": "https://nostarch.com/silence.htm",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "(Curated book, No Starch Press, 2005.) Classic work on network observation, banner grabbing,"
            "TCP/IP fingerprinting, and side-channel leakage. Shows how attackers harvest metadata from response headers"
            "and error formats. Mitigation: strip Server/X-Powered-By banners and return uniform error pages."
        ),
    },
    {
        "id": "BOOK-HOFFMAN-WEBSEC",
        "source_type": "B",
        "title": "Web Application Security: Exploitation and Countermeasures for Modern Web Applications",
        "author": "Andrew Hoffman",
        "publisher": "O'Reilly Media",
        "year": 2020,
        "url": "https://www.oreilly.com/library/view/web-application-security/9781492053101/",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Curated book, O'Reilly, 2020.) Comprehensive guide to modern web security architecture."
            "Focuses on cross-site scripting (XSS), cross-site request forgery (CSRF), cross-origin resource sharing (CORS),"
            "and defense-in-depth mitigations for Single Page Applications (SPAs) and REST APIs."
        ),
    },
    {
        "id": "BOOK-JOHNSSON-SECUREBYDESIGN",
        "source_type": "B",
        "title": "Secure by Design",
        "author": "Dan Bergh Johnsson, Daniel Deogun & Daniel Sawano",
        "publisher": "Manning Publications",
        "year": 2019,
        "url": "https://www.manning.com/books/secure-by-design",
        "cwe": "CWE-20", "owasp": "A03",
        "passage": (
            "(Curated book, Manning, 2019.) Teaches domain-driven security and writing inherently secure code."
            "Emphasizes using domain primitives to eliminate input validation flaws, enforcing strict state invariants,"
            "and building self-defending data objects."
        ),
    },
    {
        "id": "BOOK-MANICO-IRONCLAD",
        "source_type": "B",
        "title": "Iron-Clad Java: Building Secure Web Applications",
        "author": "Jim Manico & August Detlefsen",
        "publisher": "McGraw-Hill / OWASP Press",
        "year": 2014,
        "url": "https://www.mhprofessional.com/iron-clad-java-building-secure-web-applications-9780071835886-usa",
        "cwe": "CWE-116", "owasp": "A03",
        "passage": (
            "(Curated book, McGraw-Hill / OWASP Press, 2014.) Definitve guide to secure Java web development."
            "Covers contextual output encoding, anti-CSRF token handling, safe session creation, and security header configuration."
        ),
    },
    {
        "id": "BOOK-BELL-AGILEAPPSEC",
        "source_type": "B",
        "title": "Agile Application Security: Enabling Security Solutions in Development",
        "author": "Laura Bell, Michael Brunton-Spall, Rich Smith & Dan Cornell",
        "publisher": "O'Reilly Media",
        "year": 2017,
        "url": "https://www.oreilly.com/library/view/agile-application-security/9781491938836/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, O'Reilly, 2017.) Practical framework for integrating automated security tests into agile sprints."
            "Stresses automated regression testing for security headers, continuous dependency scanning, and developer security feedback loops."
        ),
    },
    {
        "id": "BOOK-RICE-CONTAINERSEC",
        "source_type": "B",
        "title": "Container Security: Fundamental Technology Concepts that Every Security Professional Should Know",
        "author": "Liz Rice",
        "publisher": "O'Reilly Media",
        "year": 2020,
        "url": "https://www.oreilly.com/library/view/container-security/9781492056690/",
        "cwe": "CWE-250", "owasp": "A05",
        "passage": (
            "(Curated book, O'Reilly, 2020.) Essential guide to container isolation, Linux cgroups, namespaces, and Seccomp profiles."
            "Focuses on running web services with minimal privileges, read-only root filesystems, and strict container network policies."
        ),
    },
    {
        "id": "BOOK-RICE-KUBERNETESSEC",
        "source_type": "B",
        "title": "Kubernetes Security: Operating Kubernetes Clusters Securely",
        "author": "Liz Rice & Michael Hausenblas",
        "publisher": "O'Reilly Media",
        "year": 2018,
        "url": "https://www.oreilly.com/library/view/kubernetes-security/9781492039075/",
        "cwe": "CWE-285", "owasp": "A01",
        "passage": (
            "(Curated book, O'Reilly, 2018.) Guide to securing cloud-native Kubernetes workloads."
            "Covers Role-Based Access Control (RBAC), pod security admission standards, network policies, and API server authentication."
        ),
    },
    {
        "id": "BOOK-HELMUS-AWSPENTESTING",
        "source_type": "B",
        "title": "AWS Penetration Testing",
        "author": "Jonathan Helmus",
        "publisher": "Packt Publishing",
        "year": 2020,
        "url": "https://www.packtpub.com/product/aws-penetration-testing/9781839216664",
        "cwe": "CWE-200", "owasp": "A01",
        "passage": (
            "(Curated book, Packt, 2020.) AWS cloud penetration testing guide."
            "Covers auditing S3 bucket policies, IAM role misconfigurations, metadata service access (169.254.169.254 SSRF), and CloudFront WAF rules."
        ),
    },
    {
        "id": "BOOK-SIKORSKI-MALWAREANALYSIS",
        "source_type": "B",
        "title": "Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software",
        "author": "Michael Sikorski & Andrew Honig",
        "publisher": "No Starch Press",
        "year": 2012,
        "url": "https://nostarch.com/malware",
        "cwe": "CWE-502", "owasp": "A08",
        "passage": (
            "(Curated book, No Starch Press, 2012.) The gold standard for reverse engineering malicious binaries and web shells."
            "Teaches dynamic analysis, network signature extraction, and detecting obfuscated malicious payloads."
        ),
    },
    {
        "id": "BOOK-LUTTGENS-INCIDENTRESP",
        "source_type": "B",
        "title": "Incident Response & Computer Forensics (3rd Ed)",
        "author": "Jason T. Luttgens, Matthew Pepe & Kevin Mandia",
        "publisher": "McGraw-Hill",
        "year": 2014,
        "url": "https://www.mhprofessional.com/incident-response-computer-forensics-third-edition-9780071798686-usa",
        "cwe": "CWE-778", "owasp": "A09",
        "passage": (
            "(Curated book, McGraw-Hill, 3rd ed., 2014.) Definitive guide to investigating web application breaches and server compromise."
            "Stresses centralized web server access logging, tamper-evident audit trails, and rapid incident response protocols."
        ),
    },
    {
        "id": "BOOK-LIGH-MEMORYFORENSICS",
        "source_type": "B",
        "title": "The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory",
        "author": "Michael Hale Ligh, Andrew Case, Jamie Levy & Aaron Walters",
        "publisher": "Wiley",
        "year": 2014,
        "url": "https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "(Curated book, Wiley, 2014.) Volatility memory forensics reference."
            "Teaches detecting fileless web shells, process injection, and in-memory credential harvesting on compromised web servers."
        ),
    },
    {
        "id": "BOOK-ANDERSON-SECENG",
        "source_type": "B",
        "title": "Security Engineering: A Guide to Building Dependable Distributed Systems (3rd ed.)",
        "author": "Ross J. Anderson",
        "publisher": "Wiley",
        "year": 2020,
        "url": "https://www.wiley.com/en-us/security-engineering-a-guide-to-building-dependable-distributed-systems-3rd-edition-p-9781119642787",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, Wiley, 3rd ed., 2020; author makes the 1st ed. free at "
            "cl.cam.ac.uk.) The foundational text on designing systems that remain "
            "dependable against malice: attacker models, trust boundaries, access "
            "control, and the economics of why insecure systems get shipped. It is the "
            "'how to block hacking' reference behind this auditor - the same threat "
            "modeling and defense-in-depth logic underlies every hardening rule."
        ),
    },
    {
        "id": "BOOK-CLARKE-SQLI",
        "source_type": "B",
        "title": "SQL Injection Attacks and Defense (2nd ed.)",
        "author": "Justin Clarke-Salt (ed.)",
        "publisher": "Syngress",
        "year": 2009,
        "url": "https://www.oreilly.com/library/view/sql-injection-attacks/9781597499637",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "(Curated book, Syngress, 2nd ed., 2009.) The dedicated reference on SQL "
            "injection: how the flaw works, finding/confirming/automating discovery "
            "(error-based and blind), per-database techniques, and the defenses - "
            "parameterized queries, input validation, and suppressing verbose errors. "
            "Its error-signature and boolean/ timing-test methodology is exactly what "
            "the auditor's sqli and blind_sqli probes automate."
        ),
    },
    {
        "id": "BOOK-BARNETT-DEFENDER",
        "source_type": "B",
        "title": "The Web Application Defender's Cookbook: Battling Hackers and Protecting Users",
        "author": "Ryan C. Barnett",
        "publisher": "Wiley",
        "year": 2012,
        "url": "https://www.oreilly.com/library/view/web-application-defenders/9781118417058/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, Wiley, 2012.) Practical defensive recipes from the "
            "ModSecurity Core Rule Set project lead: detecting attack traffic, "
            "request-throttling, blocking XSS/SQLi attempts, virtual patching, and "
            "logging for attack visibility. It is the operational 'block the hacker' "
            "guide that informs the auditor's header, WAF-evidence, and rate-limit "
            "checks."
        ),
    },
    {
        "id": "BOOK-YAWORSKI-WEBHACKING101",
        "source_type": "B",
        "title": "Web Hacking 101: How to Make Money Hacking Ethically",
        "author": "Peter Yaworski",
        "publisher": "Leanpub",
        "year": 2018,
        "url": "https://leanpub.com/web-hacking-101",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Curated book, Leanpub, 2018; foreword by HackerOne co-founders.) Lessons"
            "from real, disclosed HackerOne reports classified by severity with bounty"
            "and key takeaway: cross-site scripting, HTML injection, open redirects,"
            "CRLF/HTTP response splitting, subdomain takeover of abandoned hosts"
            "pointed at third-party services, XXE, RCE, and application-logic flaws."
            "Methodology: reconnaissance with Shodan and WhatCMS; study the app's"
            "JavaScript to learn its framework (an AngularJS app prompts template-"
            "injection payloads); enumerate predictable record IDs and JSON paths;"
            "submit encoded and unusual input to see how the server interprets it."
            "The takeaway: well-known companies still ship bugs, so observation,"
            "creativity, and persistence matter more than tooling - and every finding"
            "must be reported responsibly."
        ),
    },
    {
        "id": "BOOK-CHELL-MOBILE",
        "source_type": "B",
        "title": "The Mobile Application Hacker's Handbook",
        "author": "Dominic Chell, Tyrone Erasmus, Shaun Colley, Ollie Whitehouse",
        "publisher": "Wiley",
        "year": 2015,
        "url": "https://www.oreilly.com/library/view/the-mobile-application/9781118958513",
        "cwe": "CWE-312", "owasp": "A02",
        "passage": (
            "(Curated book, Wiley, 2015.) A comprehensive guide to mobile application "
            "security from the attacker's point of view: analyzing and attacking iOS, "
            "Android, Windows Phone, and BlackBerry apps, identifying implementation "
            "insecurities, and writing secure mobile applications. Its platform-specific "
            "approach - static inspection, runtime manipulation, and transport-layer "
            "review - covers the mobile app's server-side surface: the APIs and web "
            "services it calls, where insecure endpoints, weak auth, and exposed data "
            "are the same weaknesses the auditor probes on any web-facing service."
        ),
    },
    {
        "id": "BOOK-MCNAB-NETASSESS",
        "source_type": "B",
        "title": "Network Security Assessment: Know Your Network (3rd ed.)",
        "author": "Chris McNab",
        "publisher": "O'Reilly Media",
        "year": 2017,
        "url": "https://www.oreilly.com/library/view/network-security-assessment/9781491911044/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, O'Reilly Media, 3rd ed., 2017.) Structured network "
            "penetration testing: reconnaissance and discovery, then assessing common "
            "services (SSH, FTP, Kerberos, SNMP, LDAP), Microsoft services (NetBIOS, "
            "SMB, RPC, RDP), email services, TLS, web server software, frameworks, and "
            "database servers. Its 'attack your own network to learn its weaknesses' "
            "methodology mirrors the auditor's bounded, consent-only assessment "
            "discipline, and its service- and banner-based fingerprinting maps onto the "
            "auditor's server-identity and version checks."
        ),
    },
    {
        "id": "BOOK-MURDOCH-SOC",
        "source_type": "B",
        "title": "Blue Team Handbook: SOC, SIEM, and Threat Hunting (V1.02)",
        "author": "Don Murdoch",
        "publisher": "Independently published",
        "year": 2019,
        "url": "https://www.blueteamhandbook.com/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated book, 2019; updated O'Reilly edition forthcoming 2026.) A "
            "condensed field guide for security operations teams and threat hunters: "
            "building a SOC, tiered staffing and analyst onboarding, deploying SIEM "
            "platforms, deciding which data sources to feed them, objective SOC and "
            "SIEM metrics, and applying a threat-hunting mindset to monitoring. It "
            "frames the defensive context behind the auditor's recommendations that a "
            "target must log, monitor, and rate-limit request traffic."
        ),
    },
    {
        "id": "BOOK-HARO-SECUREAPIS",
        "source_type": "B",
        "title": "Secure APIs: Design, build, and implement",
        "author": "José Haro Peralta",
        "publisher": "Manning Publications",
        "year": 2025,
        "url": "https://www.manning.com/books/secure-apis",
        "cwe": "CWE-285", "owasp": "A01",
        "passage": (
            "(Curated book, Manning, 2025.) API security by design: dissecting the "
            "OWASP Top 10 API security risks, hardening authentication and "
            "authorization, zero-trust principles, automated API testing strategies, "
            "and observability and monitoring for threat detection. Its risk-by-risk "
            "treatment of weak authentication, broken object-level authorization, and "
            "insufficient constraints directly supports the auditor's API-focused "
            "checks, complementing API Security in Action (Manning, 2020)."
        ),
    },
    {
        "id": "BOOK-SWEIGART-CIPHERS",
        "source_type": "B",
        "title": "Hacking Secret Ciphers with Python: A Beginner's Guide to Cryptography",
        "author": "Al Sweigart",
        "publisher": "Self-published (CC BY-NC-SA 3.0, free)",
        "year": 2013,
        "url": "https://inventwithpython.com/hacking",
        "cwe": "CWE-327", "owasp": "A02",
        "passage": (
            "(Curated book, free/CC BY-NC-SA.) Teaches cryptography and Python together"
            "by building, then attacking, classic ciphers - Caesar, transposition,"
            "affine, simple substitution, and Vigenere - with matching 'hacker'"
            "programs that break them using exhaustive key search, letter-frequency"
            "analysis, word-pattern matching, and Kasiski examination. Ends with"
            "modular arithmetic, Rabin-Miller primality testing, and a working RSA"
            "implementation, with explicit warnings about unhardened 'textbook' RSA."
            "Lesson for an auditor: cipher strength depends on key space, design, and"
            "implementation rather than secrecy of the scheme - classics collapse under"
            "statistical and brute-force analysis, and any cipher whose key material is"
            "guessable is effectively broken."
        ),
    },
    {
        "id": "BOOK-VIEGA-OPENSSL",
        "source_type": "B",
        "title": "Network Security with OpenSSL: Cryptography for Secure Communications",
        "author": "John Viega, Matt Messier & Pravir Chandra",
        "publisher": "O'Reilly Media",
        "year": 2002,
        "url": "https://www.oreilly.com/library/view/network-security-with/059600270X/",
        "cwe": "CWE-295", "owasp": "A02",
        "passage": (
            "(Curated book, O'Reilly, 2002.) A practical guide to OpenSSL and the"
            "SSL/TLS family for developers and administrators: symmetric algorithms,"
            "RSA/DSA/Diffie-Hellman, X.509 certificates and CAs, PKCS formats, session"
            "management, and driving these via CLI, C APIs, and PHP. Concrete, still-"
            "current lessons: hostname and certificate validation must be actively"
            "performed by applications or man-in-the-middle substitution is possible;"
            "poor entropy undermines key generation; MD5 is unsuitable for integrity"
            "because collisions can be manufactured; and a private key on a server is"
            "recoverable by anyone with root, so keys belong on hardware. Stresses"
            "conservative security metrics, matching digest strength to cipher"
            "strength, and warns against over-trusting defaults."
        ),
    },
    {
        "id": "BOOK-HARTMAN-ETHICALHACKING",
        "source_type": "B",
        "title": "Hands-On Ethical Hacking Tactics: Strategies, Tools, and Techniques",
        "author": "Shane Hartman",
        "publisher": "Packt Publishing",
        "year": 2024,
        "url": "https://www.packtpub.com/en-us/product/hands-on-ethical-hacking-tactics-9781801810081",
        "cwe": "CWE-693", "owasp": "A05",
        "passage": (
            "(Curated book, Packt, 2024.) A defensive view of the offensive-security"
            "process organized around the phases an adversary actually follows:"
            "footprinting with OSINT tools, scanning and enumeration (including the"
            "often-forgotten IPv6 space), vulnerability assessment with attack trees,"
            "then platform hacking of Windows, Linux, web servers, databases, and"
            "protocols, plus malware analysis, incident response, threat hunting,"
            "social engineering, IoT, and cloud. Returns repeatedly to the attacker's"
            "end-game - credential theft, privilege escalation, lateral movement,"
            "exfiltration, ransomware - and stresses early detection and containment,"
            "disaster-recovery drills, and post-incident root-cause review such as slow"
            "patching. Auditors gain scoping methodology, a catalog of high-yield"
            "weaknesses (typosquatting, subdomain takeover, session fixation), and the"
            "reminder that MFA and monitoring matter as much as any tool."
        ),
    },
    {
        "id": "BOOK-HABIB-OPENAIAPI",
        "source_type": "B",
        "title": "OpenAI API Cookbook: Build Intelligent Applications",
        "author": "Henry Habib",
        "publisher": "Packt Publishing",
        "year": 2024,
        "url": "https://www.packtpub.com/en-us/product/openai-api-cookbook-9781805121350",
        "cwe": "CWE-200", "owasp": "A04",
        "passage": (
            "(Curated book, Packt, 2024.) A recipe-oriented handbook for building on"
            "the OpenAI API: setup and authentication, chat-completions and image"
            "endpoints, prompt-engineering patterns (zero-shot, few-shot, system"
            "messages), embeddings and cosine similarity for semantic search, and"
            "production deployment concerns. For an auditor the value is the attack"
            "surface of LLM-backed systems: API keys are high-value secrets that must"
            "be managed like any credential; model outputs and prompts are untrusted"
            "channels vulnerable to prompt injection; document-retrieval pipelines can"
            "leak sensitive data if embeddings are ungoverned; and system messages are"
            "not a security boundary. Precise prompting and careful application design"
            "mirror the discipline needed to keep generative-AI features auditable."
        ),
    },
    {
        "id": "BOOK-HAKIN9-SQLINJECTION",
        "source_type": "B",
        "title": "Web Application Hacking: Advanced SQL Injection and Data Store Attacks (eForensics course eBook, W29)",
        "author": "Thomas Sermpinis (course) / Hakin9 & eForensics editorial team",
        "publisher": "Hakin9 Media Sp. z o.o.",
        "year": 2016,
        "url": "https://hakin9.org/product/web-application-hacking-advanced-sql-injection-data-store-attacks-w29/",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "(Curated magazine technical compilation, Hakin9 Media.) A security-"
            "magazine course eBook on attacking and defending data stores: how SQL and"
            "NoSQL stores work inside web apps and how injection manipulates queries,"
            "then advanced SQL injection - database fingerprinting via DBMS functions,"
            "filter bypass, blind and second-order injection, and out-of-band"
            "exfiltration via Oracle UTL_HTTP/UTL_INADDR, MSSQL OPENROWSET, and MySQL"
            "INTO OUTFILE. Extends the same logic to XPath, LDAP, and NoSQL, and closes"
            "with layered defenses: parameterized queries and ORM binding, strict"
            "server-side validation, output encoding, and least-privilege accounts."
            "Lesson: injection is not just about SELECT - any channel where user input"
            "shapes a query, or where the database can reach back over the network,"
            "becomes an exfiltration and access-control bypass."
        ),
    },
    {
        "id": "REF-ZSEANO-METHODOLOGY",
        "source_type": "B",
        "title": "zseano's Methodology",
        "author": "Sean (@zseano)",
        "publisher": "BugBountyHunter.com (community platform)",
        "year": 2020,
        "url": "https://www.bugbountyhunter.com/methodology/zseanos-methodology.pdf",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "(Curated community methodology guide, free.) A free PDF by zseano, founder"
            "of BugBountyHunter.com, distilling how he approaches bug bounty programs"
            "after 600+ submissions: question everything; use the application as"
            "intended and map features, parameters, and flows before spraying payloads;"
            "commit to one or two programs over months to learn how developers think;"
            "and keep structured notes so findings build into a mental map of the"
            "target. Details a basic toolkit (Burp plus subdomain/content-discovery"
            "tools), the classes he starts with - chiefly XSS and filter bypass, plus"
            "IDOR, host-header, and auth flows - and how to test register, login,"
            "password-reset, OAuth, and file-upload flows. A three-step methodology:"
            "get a feel for things, expand the attack surface, automate and repeat."
        ),
    },
    {
        "id": "REF-BUG-BOUNTY-PLAYBOOK2",
        "source_type": "B",
        "title": "Bug Bounty Playbook V2",
        "author": "Community (anonymous)",
        "publisher": "Community playbook (freely distributed)",
        "year": 2020,
        "url": "https://www.scribd.com/document/486761260/Bug-Bounty-Playbook-V2-pdf",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "(Curated community playbook.) A community-authored, freely distributed"
            "guide focused on the exploitation phase of bug bounty engagements,"
            "stressing manual understanding before automation. Fingerprint technologies"
            "and match stacks against Google, ExploitDB, and CVE feeds, then find"
            "Proof-of-Concept code on GitHub while watching for fake PoCs. Dedicated"
            "chapters cover hacking CMSes (WordPress/WPScan, Drupal, Joomla, AEM,"
            "Magento), mining GitHub for leaked secrets, subdomain takeover, and"
            "misconfigured databases (Firebase, Elasticsearch, MongoDB, CouchDB,"
            "Cassandra). Core web flaws with worked examples: SQL injection across"
            "MySQL/PostgreSQL/Oracle, XSS from sources and sinks to DOM-based XSS,"
            "file-upload bypasses, traversal, open redirect, IDOR, API testing (REST,"
            "GraphQL, JWT, SAML), cache poisoning, SSTI, prototype pollution, XXE, CSP"
            "bypass, and relative path overwrite."
        ),
    },
    {
        "id": "REF-OSCP-SURVIVAL",
        "source_type": "B",
        "title": "Offensive Security Professional Overview Survival",
        "author": "Joas Antonio dos Santos (community/unofficial)",
        "publisher": "Community / self-published resource index",
        "year": 2021,
        "url": "https://elhacker.info/ebooks%20Joas/",
        "cwe": "CWE-16", "owasp": "A05",
        "passage": (
            "(Curated community study-resource index; unofficial.) NOT an official"
            "Offensive Security publication and contains no original teaching material:"
            "it is a personal, community-curated reference hub compiled by a Brazilian"
            "cybersecurity student preparing for OSCP, bringing everything needed for"
            "the exam into one place. The bulk is an organized list of external links:"
            "official PWK/OSCP pages, buffer-overflow tutorials aimed at the exam,"
            "HackTheBox walkthroughs of OSCP-like machines, OSCP 'journey' blog posts,"
            "and GitHub repos of notes, scripts, and exam-report templates. It reflects"
            "one candidate's roadmap rather than a course or vendor document, so treat"
            "it as a discovery index for prep material with no guarantee of accuracy"
            "or endorsement."
        ),
    },
]


USER_BOOKS_DIR = os.path.join(DATA_DIR, "user_books")


def ingest_user_books():
    """Scan data/user_books/ directory for local PDFs, TXT, MD, and JSON books.
    Extract text, chunk into ~800 character passages, and return as Source C records.
    """
    records = []
    if not os.path.exists(USER_BOOKS_DIR):
        os.makedirs(USER_BOOKS_DIR, exist_ok=True)
        return records

    for fname in sorted(os.listdir(USER_BOOKS_DIR)):
        fpath = os.path.join(USER_BOOKS_DIR, fname)
        if not os.path.isfile(fpath):
            continue

        ext = os.path.splitext(fname)[1].lower()
        title = os.path.splitext(fname)[0].replace("_", " ").replace("-", " ").title()

        if ext == ".json":
            try:
                with open(fpath, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for idx, item in enumerate(data):
                            if isinstance(item, dict) and "passage" in item:
                                rec = dict(item)
                                rec.setdefault("id", f"USER-JSON-{fname}-{idx}")
                                rec["source_type"] = "C"
                                rec.setdefault("title", title)
                                rec.setdefault("authority", f"User Book ({fname})")
                                records.append(rec)
            except Exception:
                pass

        elif ext in (".txt", ".md"):
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                clean_fpath = fpath.replace("\\", "/")
                chunks = [text[i:i+800] for i in range(0, len(text), 750)]
                for idx, chunk in enumerate(chunks):
                    if len(chunk.strip()) > 50:
                        records.append({
                            "id": f"USER-TXT-{fname}-{idx}",
                            "source_type": "C",
                            "title": f"{title} (Part {idx+1})",
                            "authority": f"User Book ({fname})",
                            "url": f"file:///{clean_fpath}",
                            "cwe": "CWE-200", "owasp": "A05",
                            "passage": f"(User Book: {fname}, Part {idx+1}) {chunk.strip()}"
                        })
            except Exception:
                pass

        elif ext == ".pdf":
            try:
                clean_fpath = fpath.replace("\\", "/")
                try:
                    import pypdf
                    reader = pypdf.PdfReader(fpath)
                    for page_num, page in enumerate(reader.pages):
                        ptext = page.extract_text() or ""
                        if len(ptext.strip()) > 50:
                            records.append({
                                "id": f"USER-PDF-{fname}-P{page_num+1}",
                                "source_type": "C",
                                "title": f"{title} (Page {page_num+1})",
                                "authority": f"User Book PDF ({fname})",
                                "url": f"file:///{clean_fpath}",
                                "cwe": "CWE-200", "owasp": "A05",
                                "passage": f"(User Book PDF: {fname}, Page {page_num+1}) {ptext.strip()[:1000]}"
                            })
                except ImportError:
                    pass
            except Exception:
                pass

    return records


def _extract_book_text(fpath):
    """Extract raw text from a locally-owned book file (PDF via pypdf, else TXT/MD)."""
    ext = os.path.splitext(fpath)[1].lower()
    if ext == ".pdf":
        import pypdf
        reader = pypdf.PdfReader(fpath)
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n".join(pages)
    with open(fpath, encoding="utf-8", errors="ignore") as f:
        return f.read()


def _chunk_text(text, size, overlap):
    """Split full book text into overlapping passages of ~size chars each."""
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    if len(text) <= size:
        return [text]
    chunks, start = [], 0
    while start < len(text):
        end = start + size
        if end < len(text):
            cut = text.rfind(". ", start, end)
            if cut > start + size // 2:
                end = cut + 1
        chunks.append(text[start:end].strip())
        start = max(end - overlap, start + 1)
        if start >= len(text):
            break
    return [c for c in chunks if c]


def ingest_book_file(fpath, cwe="CWE-16", owasp="A05"):
    """Read a full, locally-owned book and index its ENTIRE text into the
    local-only library (D:\LocalLibrary\local_books.jsonl). The library is
    never deployed and never redistributed; only the local analyzer/webui
    quote it. If fpath is a directory, every supported file in it is ingested.
    """
    fpath = os.path.abspath(fpath)
    if not os.path.exists(fpath):
        raise FileNotFoundError(fpath)
    if os.path.isdir(fpath):
        results = []
        for name in sorted(os.listdir(fpath)):
            p = os.path.join(fpath, name)
            if os.path.isfile(p) and os.path.splitext(name)[1].lower() in (".pdf", ".txt", ".md"):
                results.append(ingest_book_file(p, cwe=cwe, owasp=owasp))
        return {"title": os.path.basename(fpath.rstrip("\\/")), "books": results,
                "passages": sum(r["passages"] for r in results), "chars": sum(r["chars"] for r in results)}
    title = os.path.splitext(os.path.basename(fpath))[0]
    title = title.replace("_", " ").replace("-", " ").title()
    text = _extract_book_text(fpath)
    chunks = _chunk_text(text, config.LOCAL_CHUNK_SIZE, config.LOCAL_CHUNK_OVERLAP)
    if not chunks:
        return {"title": title, "passages": 0, "chars": len(text)}
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(config.LOCAL_BOOKS_DIR, exist_ok=True)

    existing = []
    if os.path.exists(config.LOCAL_KB_FILE):
        with open(config.LOCAL_KB_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    existing.append(json.loads(line))
    existing = [r for r in existing if r.get("file") != fpath]

    clean_fpath = fpath.replace("\\", "/")
    base = os.path.basename(fpath)
    from websec_auditor.knowledge.meta import enrich_meta
    for idx, chunk in enumerate(chunks):
        existing.append(enrich_meta({
            "id": f"LOCAL-{stamp}-{idx:04d}",
            "source_type": "C",
            "title": f"{title} (Part {idx+1}/{len(chunks)})",
            "authority": f"Local book: {base}",
            "url": f"file:///{clean_fpath}",
            "cwe": cwe, "owasp": owasp,
            "file": fpath,
            "passage": f"(Local book: {base}, Part {idx+1}/{len(chunks)}) {chunk}",
        }))
    existing.sort(key=lambda r: r.get("title", ""))
    with open(config.LOCAL_KB_FILE, "w", encoding="utf-8") as f:
        for rec in existing:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return {"title": title, "passages": len(chunks), "chars": len(text)}


def library_stats():
    """Count local-only full-book passages (never deployed)."""
    total, books = 0, set()
    if os.path.exists(config.LOCAL_KB_FILE):
        with open(config.LOCAL_KB_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rec = json.loads(line)
                    total += 1
                    books.add(rec.get("authority", ""))
    return {"books": len(books), "passages": total}


def write_kb():
    from websec_auditor.knowledge import expansion
    user_records = ingest_user_books()
    # A former synthetic "100k" expansion was removed: it produced templated
    # placeholder entries (generic text, wrong/mismatched URLs) that inflated
    # counts without adding real citation value, and no live finding used them.
    # The curated SOURCE_A (OWASP/CWE/ASVS/WSTG) + SOURCE_B (real books) carry
    # every citation the scanner actually uses. Add entries only with real,
    # verifiable sources.
    extra_records = []

    # Merge records and deduplicate by 'id'
    seen_ids = set()
    records = []
    for rec in SOURCE_A + SOURCE_B + extra_records + user_records:
        rid = rec.get("id")
        if rid and rid in seen_ids:
            continue
        if rid:
            seen_ids.add(rid)
        records.append(rec)

    # Append the open-source expansion records and patch scan_rules onto the
    # curated records (WSTG / PortSwigger / OWASP DoS / NIST references + the
    # sqli / xss / ddos_mitigation executable rule types).
    records = expansion.apply_expansion(records)

    # Enrich every record with CWE-derived structured metadata (tags, ATT&CK,
    # CAPEC, impact, severity, confidence) so the analyzer can multi-axis match.
    from websec_auditor.knowledge.meta import enrich_meta
    records = [enrich_meta(r) for r in records]

    os.makedirs(DATA_DIR, exist_ok=True)
    kb_path = config.KB_FILE
    with open(kb_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    meta = {
        "count": len(records),
        "source_A": sum(1 for r in records if r["source_type"] == "A"),
        "source_B": sum(1 for r in records if r["source_type"] == "B"),
        "source_C": sum(1 for r in records if r["source_type"] == "C"),
        "built_with": "websec-auditor build_kb.py",
    }
    with open(config.INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"[build_kb] wrote {len(records)} passages -> {kb_path}")
    print(f"[build_kb] A={meta['source_A']} B={meta['source_B']} C={meta['source_C']} "
          f"(Drop your own PDFs/TXTs in {USER_BOOKS_DIR} to add unlimited local books!)")
    return records


if __name__ == "__main__":
    write_kb()
