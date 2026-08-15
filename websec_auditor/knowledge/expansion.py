"""Open-source knowledge-base expansion for websec-auditor.

Adds genuinely-sourced, freely-available references (OWASP WSTG & Cheat Sheets,
PortSwigger Web Security Academy, MITRE CWE, NIST) in the project's standard
format, plus new EXECUTABLE rule types the scanner and the self-study loop can
run:

  * "sqli"           -> benign SQL-injection surface probes (CWE-89 / WSTG-INPV-05)
  * "xss"            -> benign non-executing reflection probes (CWE-79 / WSTG-INPV-01)
  * "ddos_mitigation"-> passive WAF/rate-limit posture check (ATT&CK T1498 / OWASP DoS)

Passages are our OWN paraphrased explanations of public standards (facts +
guidance), attributed with source name + URL. No copyrighted text is copied.
"""

from __future__ import annotations

# Default probe surfaces used by the engine when a rule does not pin its own.
DEFAULT_SQLI_PARAMS = ["q", "id", "search", "name"]
DEFAULT_XSS_PARAMS = ["q", "search", "name", "page", "id"]

# New standalone records (source_type "A").
OPEN_KB_RECORDS = [
    {
        "id": "WSTG-INPV-05-SQLI",
        "source_type": "A",
        "title": "WSTG-INPV-05: Testing for SQL Injection",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "WSTG-INPV-05 covers SQL injection testing: submit a benign single quote "
            "and boolean/union-style payloads to each parameter and inspect the "
            "response for SQL error signatures that confirm the input reaches the "
            "query builder. Verbose database errors both leak schema and prove the "
            "injection surface exists (CWE-200). The fix is parameterized queries "
            "and bound parameters, never string concatenation."
        ),
        "scan_rules": [
            {"type": "sqli", "name": "sql-injection", "severity": "high",
             "cwe": "CWE-89", "owasp": "A03",
             "markers": ["'", "' OR '1'='1"],
             "error_patterns": [
                 r"you have an error in your sql syntax",
                 r"unclosed quotation mark",
                 r"ora-\d{5}",
                 r"sqlite3?\.[a-z_]+ error|sqlite_error",
                 r"sqlstate\[",
                 r"postgresql.*error|psql::|pg_query\(\)",
                 r"microsoft ole ?db provider for sql server",
                 r"mysql_fetch|mysqli|syntax error near",
             ],
             "remediation": "Use parameterized queries / prepared statements; suppress verbose database errors."}
        ],
    },
    {
        "id": "PORT-SQLI-CHEATSHEET",
        "source_type": "A",
        "title": "PortSwigger SQL Injection Cheat Sheet",
        "authority": "PortSwigger Web Security Academy (SQLi)",
        "url": "https://portswigger.net/web-security/sql-injection/cheat-sheet",
        "cwe": "CWE-89", "owasp": "A03",
        "passage": (
            "PortSwigger's SQLi cheat sheet catalogs the classic probes: a single "
            "quote to break out of a string literal, boolean payloads such as "
            "1=1 vs 1=2 to confirm the predicate reaches SQL, and UNION selects to "
            "exfiltrate columns. A scanner can safely confirm the *surface* by "
            "detecting SQL error signatures without executing any data-changing "
            "statement."
        ),
    },
    {
        "id": "WSTG-INPV-01-XSS",
        "source_type": "A",
        "title": "WSTG-INPV-01: Testing for Reflected Cross-Site Scripting",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.html",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "WSTG-INPV-01: to test reflected XSS, insert a unique marker into a "
            "parameter and check whether the response echoes it back unencoded and "
            "unfiltered. If a benign inert tag (e.g. <websec_xss_probe>) is returned "
            "verbatim, an attacker's script would be too, making it a confirmed XSS "
            "surface. Mitigations are context-aware output encoding plus a "
            "Content-Security-Policy."
        ),
        "scan_rules": [
            {"type": "xss", "name": "reflected-xss-surface", "severity": "medium",
             "cwe": "CWE-79", "owasp": "A03",
             "markers": ["<websec_xss_probe_9f6b2>", "\"><websec_xss_probe_9f6b2>"],
             "remediation": "Context-aware output-encode all reflected input and deploy a Content-Security-Policy."}
        ],
    },
    {
        "id": "PORT-XSS-CHEATSHEET",
        "source_type": "A",
        "title": "PortSwigger Cross-Site Scripting Cheat Sheet",
        "authority": "PortSwigger Web Security Academy (XSS)",
        "url": "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
        "cwe": "CWE-79", "owasp": "A03",
        "passage": (
            "PortSwigger's XSS cheat sheet details the payload families for each "
            "reflection context (HTML, attribute, URL, script, event handlers) and "
            "the matching encoding fix. Reflected input echoed inside an attribute "
            "without encoding lets an attacker break out with a closing quote and "
            "inject an event handler; the detection marker '\\\" ><websec_xss_probe>' "
            "confirms exactly that context. A Content-Security-Policy with "
            "script-src 'self' and no 'unsafe-inline' contains any residual bug."
        ),
    },
    {
        "id": "OWASP-DOS-CHEATSHEET",
        "source_type": "A",
        "title": "OWASP Denial of Service Cheat Sheet",
        "authority": "OWASP Cheat Sheet Series",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
        "cwe": "CWE-400", "owasp": "A05",
        "passage": (
            "The OWASP DoS Cheat Sheet covers application-layer denial of service: "
            "HTTP floods, Slowloris keeping sockets open, huge payloads consuming "
            "memory, and expensive operations (regex, XML entity expansion). Core "
            "defenses: rate limiting per IP/account, connection and request-size "
            "timeouts, a WAF or managed edge, and capping expensive operations. A "
            "site that exposes no rate-limiting evidence and no WAF/CDN layer is "
            "more exposed to application-layer floods."
        ),
        "scan_rules": [
            {"type": "ddos_mitigation", "name": "ddos-mitigation-posture",
             "severity": "low", "cwe": "CWE-400", "owasp": "A05",
             "waf_headers": [
                 "cf-ray", "server: cloudflare", "x-sucuri-id", "akamai",
                 "x-amz-cf-id", "x-azure-ref", "x-qw", "x-vercel-id", "x-cache",
                 "via: 1.1 google", "x-fastly",
             ],
             "ratelimit_headers": [
                 "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
                 "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
             ],
             "remediation": "Deploy a WAF/CDN, enforce per-IP rate limiting and request size caps, and set connection timeouts."}
        ],
    },
    {
        "id": "NIST-SP-800-115",
        "source_type": "A",
        "title": "NIST SP 800-115 Technical Guide to Information Security Testing",
        "authority": "NIST SP 800-115",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-115/final",
        "cwe": "CWE-20", "owasp": "A05",
        "passage": (
            "NIST SP 800-115 is the authoritative methodology for technical security "
            "testing: discovery, vulnerability verification, and exploitation "
            "performed ONLY with written authorization, using the least-intrusive "
            "technique that yields evidence. It explicitly requires documenting "
            "assumptions and not damaging the target. This auditor's probes follow "
            "that discipline: read-only requests and benign markers that confirm a "
            "weakness exists without delivering a payload."
        ),
    },
    {
        "id": "WSTG-SESS-04-FIXATION",
        "source_type": "A",
        "title": "WSTG-SESS-04: Testing for Session Fixation",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Session_Fixation.html",
        "cwe": "CWE-384", "owasp": "A07",
        "passage": (
            "WSTG-SESS-04: session fixation occurs when the server accepts a "
            "client-supplied session identifier instead of issuing a fresh one on "
            "authentication. Defenses: generate a new session id at login, reject "
            "unauthenticated session values, and mark cookies Secure + HttpOnly + "
            "SameSite. Session cookies that lack these flags weaken the barrier "
            "against hijacking and fixation."
        ),
        "scan_rules": [
            {"type": "cookie_flag", "flag": "Secure", "severity": "high",
             "cwe": "CWE-384", "owasp": "A07",
             "remediation": "Issue a fresh server-side session id on login and set the Secure flag on session cookies."},
            {"type": "cookie_flag", "flag": "HttpOnly", "severity": "high",
             "cwe": "CWE-384", "owasp": "A07",
             "remediation": "Regenerate the session id at authentication and set HttpOnly so client script cannot read it."},
        ],
    },
    {
        "id": "OWASP-RATELIMIT-BRUTEFORCE",
        "source_type": "A",
        "title": "OWASP Authentication Cheat Sheet: brute-force protection",
        "authority": "OWASP Cheat Sheet Series",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        "cwe": "CWE-307", "owasp": "A07",
        "passage": (
            "The OWASP Authentication Cheat Sheet requires rate limiting and "
            "credential-stuffing defenses on login endpoints: per-account and "
            "per-IP throttling, lockout policies, and CAPTCHAs after repeated "
            "failures. An exposed login or API endpoint with no rate-limiting "
            "evidence invites brute force (CWE-307). RateLimit-* headers are the "
            "observable signal that such protection is active."
        ),
        "scan_rules": [
            {"type": "ddos_mitigation", "name": "brute-force-rate-limit-posture",
             "severity": "low", "cwe": "CWE-307", "owasp": "A07",
             "waf_headers": [
                 "cf-ray", "server: cloudflare", "x-sucuri-id", "akamai",
                 "x-amz-cf-id", "x-vercel-id", "x-cache",
             ],
             "ratelimit_headers": [
                 "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
                 "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
             ],
             "remediation": "Enforce per-account and per-IP rate limiting, account lockout, and CAPTCHA after repeated failures."}
        ],
    },
    {
        "id": "WSTG-INPV-07-PATHTRAV",
        "source_type": "A",
        "title": "WSTG-INPV-07: Testing for Path Traversal / Local File Inclusion",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_Path_Traversal.html",
        "cwe": "CWE-22", "owasp": "A03",
        "passage": (
            "WSTG-INPV-07 covers path traversal / local file inclusion: a parameter "
            "that becomes a filesystem path without validation lets an attacker read "
            "arbitrary files by supplying '../' sequences (and their encoded and "
            "double-encoded variants) to walk out of the web root. Detection: submit "
            "benign traversal payloads and look for file content signatures such as "
            "the Unix 'root:' passwd line or the Windows WIN.INI '[extensions]' "
            "section. Remediation: validate against an allow-list of permitted files "
            "and never build filesystem paths from user input."
        ),
        "scan_rules": [
            {"type": "path_traversal", "name": "path-traversal-lfi-surface",
             "severity": "high", "cwe": "CWE-22", "owasp": "A03",
             "payloads": [
                 "../../../../../../etc/passwd",
                 "..%2f..%2f..%2f..%2fetc/passwd",
                 "....//....//....//....//etc/passwd",
                 "..\\\\..\\\\..\\\\windows\\\\win.ini",
                 "..%5c..%5c..%5cwindows%5cwin.ini",
             ],
             "signatures": ["root:x:0:0", "[extensions]", "[fonts]", "boot loader"],
             "remediation": "Validate file parameters against an allow-list and never build filesystem paths from user input."}
        ],
    },
    {
        "id": "WSTG-SESS-05-CSRF",
        "source_type": "A",
        "title": "WSTG-SESS-05: Testing for Cross-Site Request Forgery",
        "authority": "OWASP Web Security Testing Guide v4.2 / OWASP CSRF Cheat Sheet",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery.html",
        "cwe": "CWE-352", "owasp": "A01",
        "passage": (
            "WSTG-SESS-05 / the OWASP CSRF Prevention Cheat Sheet: every state-changing "
            "request (login, password change, payment) must be proven to originate "
            "from the authenticated user. The accepted defense is a per-session, "
            "server-validated anti-CSRF token embedded in every state-changing form, "
            "paired with SameSite=Lax/Strict cookies. A POST/PUT/DELETE form that "
            "carries no token can be replayed cross-site on a victim's session "
            "(CWE-352)."
        ),
        "scan_rules": [
            {"type": "csrf_token", "name": "state-changing-form-csrf-token",
             "severity": "high", "cwe": "CWE-352", "owasp": "A01",
             "token_names": ["csrf", "_token", "token", "authenticity_token",
                             "__requestverificationtoken", "xsrf", "csrf_token"],
             "remediation": "Embed a per-session, server-validated anti-CSRF token in every state-changing form and set SameSite=Lax or Strict cookies."}
        ],
    },
    {
        "id": "OWASP-RATELIMIT-DEEP",
        "source_type": "A",
        "title": "OWASP DoS & Authentication Cheat Sheets: rate limiting as a control",
        "authority": "OWASP Cheat Sheet Series",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        "cwe": "CWE-307", "owasp": "A07",
        "passage": (
            "Rate limiting is the observable defense against application-layer floods "
            "and credential brute force: an endpoint that tolerates many rapid "
            "requests without any 429/Retry-After backoff is not enforcing the "
            "control. A scanner verifies the control with a short burst of requests "
            "and records whether the target pushes back; absence of any backoff "
            "signal is a hardening gap worth reporting."
        ),
        "scan_rules": [
            {"type": "rate_limiting", "name": "rate-limit-backoff-posture",
             "severity": "medium", "cwe": "CWE-307", "owasp": "A07",
             "probe_count": 5, "window_sleep": 0.2,
             "remediation": "Enforce per-IP/per-account rate limits with 429 + Retry-After on sensitive and login endpoints."}
        ],
    },
    {
        "id": "WSTG-INFO-02-BANNERS",
        "source_type": "A",
        "title": "WSTG-INFO-02: Fingerprint Web Server & Review Server Banners",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.html",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "WSTG-INFO-02: banner grabbing reads Server and X-Powered-By headers to "
            "fingerprint the software and its version, which the tester then maps to "
            "known-vulnerable builds. The defensive countermeasure is to strip or "
            "obfuscate these banners so the technology stack is not advertised."
        ),
    },
    {
        "id": "CWE-327",
        "source_type": "A",
        "title": "CWE-327 Use of a Broken or Risky Cryptographic Algorithm",
        "authority": "MITRE CWE-327",
        "url": "https://cwe.mitre.org/data/definitions/327.html",
        "cwe": "CWE-327", "owasp": "A02",
        "passage": (
            "CWE-327: the software uses a broken or risky cryptographic algorithm or "
            "protocol (MD5, SHA-1 for security purposes, DES, RC4, ECB mode, keys "
            "under 128 bits). These primitives are publicly breakable or have known "
            "practical attacks, so they provide no real confidentiality or integrity. "
            "Detection: static review for hashing of credentials with md5/sha1, "
            "Cipher.getInstance('DES'/'AES/ECB'), or uses of random rather than a "
            "CSPRNG for secrets. Remediation: use SHA-256/384, Argon2/bcrypt/scrypt/"
            "PBKDF2 for password storage, AES-GCM, and os.urandom/secrets for tokens."
        ),
    },
    {
        "id": "CWE-532",
        "source_type": "A",
        "title": "CWE-532 Insertion of Sensitive Information into Log File",
        "authority": "MITRE CWE-532",
        "url": "https://cwe.mitre.org/data/definitions/532.html",
        "cwe": "CWE-532", "owasp": "A09",
        "passage": (
            "CWE-532: the software writes sensitive information (passwords, session "
            "tokens, API keys, credit-card data) to a log file or console that is "
            "readable by parties who should not see it. Logs are routinely collected, "
            "aggregated, and searched, so an attacker who reaches any log sink obtains "
            "usable credentials. Detection: static review for print/log calls that "
            "pass a password/token/secret variable. Remediation: log only "
            "non-sensitive identifiers, redact or mask secrets, and treat log "
            "repositories as sensitive data stores."
        ),
    },
    {
        "id": "OWASP-CODE-REVIEW-GUIDE",
        "source_type": "A",
        "title": "OWASP Code Review Guide + SAST methodology",
        "authority": "OWASP Code Review Guide / SAST",
        "url": "https://owasp.org/www-project-code-review-guide/",
        "cwe": "CWE-20", "owasp": "A03",
        "passage": (
            "Static application security testing (SAST) reviews source code without "
            "executing it: trace each untrusted input (request params, headers, "
            "cookies, file uploads) from its source to a dangerous sink (SQL query, "
            "HTML output, OS command, URL fetch, deserializer) and flag the tainted "
            "flow. Pattern-based scanners catch the common, mechanically-detectable "
            "flaws - string-concatenated SQL, unencoded HTML sinks, eval/exec, "
            "user-controlled file paths and URLs - while human review covers logic "
            "flaws. Every static finding must be triaged for exploitability and "
            "remediated with the class-level fix (parameterized queries, context "
            "output encoding, allow-list validation, least privilege), then "
            "confirmed with a dynamic test."
        ),
    },
    {
        "id": "WSTG-TESTGEN-PENTEST",
        "source_type": "A",
        "title": "Generating regression / Burp / fuzz tests from findings",
        "authority": "OWASP WSTG v4.2 + NIST SP 800-115",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/",
        "cwe": "CWE-20", "owasp": "A03",
        "passage": (
            "A finding is not finished until it can be reproduced and re-checked. The "
            "WSTG input-validation chapters (WSTG-INPV-01 through 07) and NIST SP "
            "800-115 both require confirming a suspected weakness with a concrete, "
            "reproducible test against an authorized target. Practical artifacts: a "
            "raw HTTP request with Burp Intruder positional markers and a payload "
            "list (SQLi boolean/error payloads, inert XSS reflection markers, "
            "traversal payloads), a Python/curl fuzzer that replays the probes and "
            "reports which ones reproduce the finding, and the standards citation "
            "each payload is grounded in. Tests run only against targets the tester "
            "owns or is authorized to scan."
        ),
    },
    {
        "id": "OWASP-API-2023-GRAPHQL",
        "source_type": "A",
        "title": "OWASP API8:2023 Security Misconfiguration - GraphQL Introspection",
        "authority": "OWASP API Security Top 10:2023",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "OWASP API8:2023: Unprotected GraphQL endpoints often leave introspection "
            "enabled in production environments. Attackers can query __schema to map "
            "all types, queries, mutations, and backend logic, greatly accelerating "
            "exploitation. Remediation: disable schema introspection and GraphiQL IDEs "
            "in production, and enforce query depth/cost limits."
        ),
        "scan_rules": [
            {"type": "sensitive_paths", "paths": ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/altair", "/playground"],
             "severity": "medium", "cwe": "CWE-200", "owasp": "A05",
             "name": "GraphQL Schema Introspection & Surface",
             "remediation": "Disable introspection queries in production and restrict GraphQL IDE interfaces to internal networks."}
        ],
    },
    {
        "id": "RFC-9116-SECURITY-TXT",
        "source_type": "A",
        "title": "RFC 9116: A File Format to Aid in Security Vulnerability Disclosure",
        "authority": "IETF RFC 9116",
        "url": "https://www.rfc-editor.org/rfc/rfc9116",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "RFC 9116 defines the standard location (/.well-known/security.txt) for web "
            "sites to publish their vulnerability disclosure policies and reporting "
            "contacts. Without security.txt, security researchers have no clear, "
            "authorized channel to report discovered vulnerabilities securely."
        ),
        "scan_rules": [
            {"type": "sensitive_paths", "paths": ["/.well-known/security.txt", "/security.txt"],
             "severity": "info", "cwe": "CWE-200", "owasp": "A05",
             "name": "Security.txt Vulnerability Disclosure Policy",
             "remediation": "Publish a valid RFC 9116 security.txt at /.well-known/security.txt with Contact and Expires directives."}
        ],
    },
    {
        "id": "WSTG-INFO-03-ROBOTS",
        "source_type": "A",
        "title": "WSTG-INFO-03: Review Webserver Metafiles for Information Leakage",
        "authority": "OWASP Web Security Testing Guide v4.2",
        "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage.html",
        "cwe": "CWE-200", "owasp": "A05",
        "passage": (
            "WSTG-INFO-03 covers information leakage in robots.txt, sitemap.xml, and "
            "security metafiles. Administrators often disallow sensitive admin panels, "
            "staging paths, and internal APIs in robots.txt, inadvertently revealing "
            "high-value attack surfaces to adversaries."
        ),
        "scan_rules": [
            {"type": "sensitive_paths", "paths": ["/robots.txt", "/sitemap.xml"],
             "severity": "info", "cwe": "CWE-200", "owasp": "A05",
             "name": "Webserver Metafiles & Sitemap Surface",
             "remediation": "Audit robots.txt and sitemap.xml to ensure private paths and admin routes are not listed publicly."}
        ],
    },
    {
        "id": "CWE-611-XXE",
        "source_type": "A",
        "title": "CWE-611: Improper Restriction of XML External Entity Reference (XXE)",
        "authority": "MITRE CWE / OWASP Top 10 A05",
        "url": "https://cwe.mitre.org/data/definitions/611.html",
        "cwe": "CWE-611", "owasp": "A05",
        "passage": (
            "XML External Entity (XXE) vulnerabilities occur when XML parsers process "
            "untrusted XML documents containing references to external entities (DTD). "
            "Attackers can read local files, execute SSRF attacks, or cause denial "
            "of service (Billion Laughs attack). Remediation: disable external entity "
            "resolution and DTD processing in all XML parsers."
        ),
    },
    {
        "id": "CWE-1321-PROTOTYPE-POLLUTION",
        "source_type": "A",
        "title": "CWE-1321: Improperly Controlled Modification of Object Prototype Attributes",
        "authority": "MITRE CWE / OWASP Top 10 A03",
        "url": "https://cwe.mitre.org/data/definitions/1321.html",
        "cwe": "CWE-1321", "owasp": "A03",
        "passage": (
            "Prototype pollution in JavaScript happens when user input modifies "
            "Object.prototype (via __proto__ or constructor.prototype) through "
            "recursive merge or clone functions. This alters the behavior of all objects "
            "in the runtime and can lead to remote code execution, authentication bypass, "
            "or denial of service."
        ),
    },
    {
        "id": "CWE-1336-SSTI",
        "source_type": "A",
        "title": "CWE-1336: Improper Neutralization of Special Elements in Template Engine (SSTI)",
        "authority": "MITRE CWE / OWASP Top 10 A03",
        "url": "https://cwe.mitre.org/data/definitions/1336.html",
        "cwe": "CWE-1336", "owasp": "A03",
        "passage": (
            "Server-Side Template Injection (SSTI) occurs when user input is concatenated "
            "directly into template strings instead of passed as data context. Attackers "
            "can inject template directives to execute arbitrary server-side code (RCE) "
            "in Jinja2, EJS, Pug, Twig, or Freemarker."
        ),
    },
    {
        "id": "CWE-209-ERROR-LEAK",
        "source_type": "A",
        "title": "CWE-209: Generation of Error Message Containing Sensitive Information",
        "authority": "MITRE CWE / OWASP Top 10 A05",
        "url": "https://cwe.mitre.org/data/definitions/209.html",
        "cwe": "CWE-209", "owasp": "A05",
        "passage": (
            "CWE-209 covers verbose application errors, unhandled exception traces, and "
            "debug banners shown to clients. These leak server software versions, source "
            "code paths, database structure, and internal network architecture."
        ),
    },
    {
        "id": "OWASP-API-2023-BOLA",
        "source_type": "A",
        "title": "OWASP API1:2023 Broken Object Level Authorization (BOLA / IDOR)",
        "authority": "OWASP API Security Top 10:2023",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "cwe": "CWE-285", "owasp": "A01",
        "passage": (
            "BOLA is the most common and severe vulnerability in modern APIs. It happens "
            "when an endpoint relies on an object identifier (e.g. /api/users/123/orders) "
            "supplied by the client without validating that the authenticated user owns "
            "or has permission to access that specific object."
        ),
    },
    {
        "id": "NIST-SP-800-63B-AUTH",
        "source_type": "A",
        "title": "NIST SP 800-63B: Digital Identity Guidelines - Authentication & Rate Limiting",
        "authority": "NIST SP 800-63B / OWASP ASVS v4.0.3",
        "url": "https://pages.nist.gov/800-63-3/sp800-63b.html",
        "cwe": "CWE-307", "owasp": "A07",
        "passage": (
            "NIST SP 800-63B Section 5.2.2 mandates that verifiers implement rate-limiting "
            "and account throttling mechanisms to defend against automated brute-force "
            "password guessing and credential stuffing attacks on authentication endpoints."
        ),
        "scan_rules": [
            {"type": "rate_limiting", "name": "Authentication Rate Limiting (NIST SP 800-63B)",
             "severity": "medium", "cwe": "CWE-307", "owasp": "A07",
             "remediation": "Deploy IP-based and user-based rate limiting on authentication endpoints."}
        ],
    },
    {
        "id": "NIST-SP-800-53-SC-8",
        "source_type": "A",
        "title": "NIST SP 800-53 SC-8: Transmission Confidentiality and Integrity",
        "authority": "NIST SP 800-53 Rev. 5",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        "cwe": "CWE-319", "owasp": "A02",
        "passage": (
            "NIST SP 800-53 Control SC-8 requires that information systems protect the "
            "confidentiality and integrity of transmitted information using strong, "
            "industry-standard cryptographic protocols (TLS 1.2/1.3) and enforce strict "
            "transport security policies to prevent eavesdropping and interception."
        ),
        "scan_rules": [
            {"type": "missing_header", "header": "strict-transport-security",
             "name": "Strict Transport Security Enforced (NIST SC-8)",
             "severity": "high", "cwe": "CWE-319", "owasp": "A02",
             "remediation": "Deploy Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."}
        ],
    },
    {
        "id": "NIST-SP-800-53-SI-10",
        "source_type": "A",
        "title": "NIST SP 800-53 SI-10: Information Input Validation",
        "authority": "NIST SP 800-53 Rev. 5",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        "cwe": "CWE-20", "owasp": "A03",
        "passage": (
            "NIST SP 800-53 Control SI-10 requires verifying the syntax and semantics of "
            "all information inputs (parameters, headers, payloads) before processing. Inputs "
            "that fail validation must be rejected immediately to prevent injection and corruption."
        ),
        "scan_rules": [
            {"type": "xss", "name": "Input Validation & Output Encoding (NIST SI-10)",
             "severity": "medium", "cwe": "CWE-20", "owasp": "A03",
             "remediation": "Enforce strict server-side schema validation and context-aware output encoding."}
        ],
    },
    {
        "id": "ISO-27001-A-8-28",
        "source_type": "A",
        "title": "ISO/IEC 27001:2022 Control 8.28: Secure Coding",
        "authority": "ISO/IEC 27001:2022 / ISO/IEC 27002:2022",
        "url": "https://www.iso.org/standard/27001",
        "cwe": "CWE-693", "owasp": "A05",
        "passage": (
            "ISO/IEC 27001:2022 Control 8.28 establishes that secure coding principles "
            "must be applied to software development. Web architectures must deploy "
            "defense-in-depth HTTP security headers (CSP, HSTS, X-Content-Type-Options) "
            "to restrict client-side exploit execution."
        ),
        "scan_rules": [
            {"type": "missing_header", "header": "x-content-type-options",
             "name": "MIME-Type Sniffing Protection (ISO 27001)",
             "severity": "medium", "cwe": "CWE-693", "owasp": "A05",
             "remediation": "Deploy X-Content-Type-Options: nosniff on all HTTP responses."}
        ],
    },
    {
        "id": "ISO-27001-A-8-26",
        "source_type": "A",
        "title": "ISO/IEC 27001:2022 Control 8.26: Application Security Requirements",
        "authority": "ISO/IEC 27001:2022 / ISO/IEC 27002:2022",
        "url": "https://www.iso.org/standard/27001",
        "cwe": "CWE-327", "owasp": "A02",
        "passage": (
            "ISO/IEC 27001:2022 Control 8.26 requires identifying and specifying information "
            "security requirements for new applications. Critical data in transit must be "
            "encrypted using approved modern cipher suites without deprecated algorithms."
        ),
        "scan_rules": [
            {"type": "code_review", "name": "Secure Cryptographic Algorithm (ISO 27001)",
             "severity": "medium", "cwe": "CWE-327", "owasp": "A02",
             "languages": ["python", "javascript", "java", "php"],
             "pattern": r"(hashlib\.(md5|sha1)|crypto\.createHash\s*\(\s*['\"](md5|sha1)['\"]\s*\)|Cipher\.getInstance\s*\(\s*['\"](DES|RC4)['\"]\s*\))",
             "remediation": "Enforce AES-256-GCM / SHA-256 in all application crypto modules."}
        ],
    },
    {
        "id": "ISO-27001-A-8-12",
        "source_type": "A",
        "title": "ISO/IEC 27001:2022 Control 8.12: Data Leakage Prevention",
        "authority": "ISO/IEC 27001:2022 / ISO/IEC 27002:2022",
        "url": "https://www.iso.org/standard/27001",
        "cwe": "CWE-209", "owasp": "A05",
        "passage": (
            "ISO/IEC 27001:2022 Control 8.12 states data leakage prevention measures must be "
            "applied to prevent unauthorized extraction or disclosure. Server error handlers "
            "must suppress internal exception stacktraces, database schemas, and debug logs."
        ),
        "scan_rules": [
            {"type": "code_review", "name": "Exception Sanitization (ISO 27001)",
             "severity": "medium", "cwe": "CWE-209", "owasp": "A05",
             "languages": ["python", "javascript", "php"],
             "pattern": r"(app\.debug\s*=\s*True|DEBUG\s*=\s*True|traceback\.print_exc\s*\(\))",
             "remediation": "Implement custom generic error templates to prevent stack trace leaks."}
        ],
    },
    {
        "id": "W3C-PERMISSIONS-POLICY",
        "source_type": "A",
        "title": "W3C Permissions-Policy: Restricting Browser Hardware APIs",
        "authority": "W3C Permissions Policy Specification",
        "url": "https://www.w3.org/TR/permissions-policy-1/",
        "cwe": "CWE-693", "owasp": "A05",
        "passage": (
            "The W3C Permissions-Policy HTTP header allows web developers to selectively "
            "enable, disable, and modify the behavior of browser APIs and hardware features "
            "(camera, microphone, geolocation, payment, accelerometer) to reduce attack surfaces."
        ),
        "scan_rules": [
            {"type": "missing_header", "header": "permissions-policy",
             "name": "Permissions-Policy Hardware Restriction",
             "severity": "low", "cwe": "CWE-693", "owasp": "A05",
             "remediation": "Deploy Permissions-Policy: camera=(), microphone=(), geolocation=()."}
        ],
    },
    {
        "id": "W3C-REFERRER-POLICY",
        "source_type": "A",
        "title": "W3C Referrer-Policy: Protecting URL Privacy and Sensitive Query Tokens",
        "authority": "W3C Referrer Policy Specification",
        "url": "https://www.w3.org/TR/referrer-policy/",
        "cwe": "CWE-116", "owasp": "A05",
        "passage": (
            "W3C Referrer-Policy governs how much referrer information is sent in the Referer "
            "header. Without 'strict-origin-when-cross-origin' or 'no-referrer', sensitive URL "
            "tokens, session identifiers, and user paths leak to third-party analytics and trackers."
        ),
        "scan_rules": [
            {"type": "missing_header", "header": "referrer-policy",
             "name": "Referrer-Policy URL Privacy",
             "severity": "low", "cwe": "CWE-116", "owasp": "A05",
             "remediation": "Deploy Referrer-Policy: strict-origin-when-cross-origin."}
        ],
    },
    {
        "id": "W3C-COOP-COEP",
        "source_type": "A",
        "title": "W3C Cross-Origin Isolation: COOP and COEP Defense",
        "authority": "W3C HTML Living Standard / MDN Web Security",
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        "cwe": "CWE-346", "owasp": "A05",
        "passage": (
            "Cross-Origin-Opener-Policy (COOP) and Cross-Origin-Embedder-Policy (COEP) "
            "enable cross-origin isolation, defending web applications against side-channel "
            "attacks like Spectre and XS-Leaks (cross-site search/leakage)."
        ),
        "scan_rules": [
            {"type": "missing_header", "header": "cross-origin-opener-policy",
             "name": "Cross-Origin-Opener-Policy Isolation",
             "severity": "low", "cwe": "CWE-346", "owasp": "A05",
             "remediation": "Deploy Cross-Origin-Opener-Policy: same-origin."}
        ],
    },
    {
        "id": "CWE-548-DIR-INDEXING",
        "source_type": "A",
        "title": "CWE-548: Exposure of Information Through Directory Listing",
        "authority": "MITRE CWE / OWASP ASVS v4.0.3",
        "url": "https://cwe.mitre.org/data/definitions/548.html",
        "cwe": "CWE-548", "owasp": "A05",
        "passage": (
            "Directory indexing exposes directory contents when no index document is found. "
            "Attackers can traverse uploaded assets, backup scripts, and temporary files. "
            "Web servers must disable automatic index generation (Options -Indexes in Apache, "
            "autoindex off in Nginx)."
        ),
        "scan_rules": [
            {"type": "dirlisting", "name": "Directory Indexing / Browsing Exposure",
             "severity": "medium", "cwe": "CWE-548", "owasp": "A05",
             "remediation": "Disable directory browsing (autoindex off / Options -Indexes)."}
        ],
    },
    {
        "id": "CWE-942-CROSSDOMAIN",
        "source_type": "A",
        "title": "CWE-942: Permissive Cross-Domain Policy with Wildcard Domains",
        "authority": "MITRE CWE / OWASP WSTG v4.2",
        "url": "https://cwe.mitre.org/data/definitions/942.html",
        "cwe": "CWE-942", "owasp": "A01",
        "passage": (
            "Overly permissive crossdomain.xml or clientaccesspolicy.xml files that contain "
            "<allow-access-from domain=\"*\" /> permit external RIA clients and Flash runtimes "
            "to read authenticated user data across origins. Remove or strictly whitelist domains."
        ),
        "scan_rules": [
            {"type": "crossdomain_policy", "name": "Cross-Domain Policy Wildcard Exposure",
             "severity": "high", "cwe": "CWE-942", "owasp": "A01",
             "remediation": "Restrict cross-domain policies to explicit authorized origins."}
        ],
    },
    {
        "id": "CWE-601-OPEN-REDIRECT",
        "source_type": "A",
        "title": "CWE-601: URL Redirection to Untrusted Site (Open Redirect)",
        "authority": "MITRE CWE / OWASP Top 10 A01",
        "url": "https://cwe.mitre.org/data/definitions/601.html",
        "cwe": "CWE-601", "owasp": "A01",
        "passage": (
            "Open redirection occurs when an application accepts untrusted input as a target "
            "URL for a redirect without validation. Attackers use this to craft authentic-looking "
            "phishing links that redirect victims to malicious credential-harvesting sites."
        ),
        "scan_rules": [
            {"type": "open_redirect", "name": "Open URL Redirection Surface",
             "severity": "medium", "cwe": "CWE-601", "owasp": "A01",
             "remediation": "Validate redirection targets against a strict whitelist of relative paths."}
        ],
    },
    {
        "id": "CWE-798-HARDCODED-CREDENTIALS",
        "source_type": "A",
        "title": "CWE-798: Use of Hard-coded Credentials and API Keys",
        "authority": "MITRE CWE / OWASP Top 10 A07",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
        "cwe": "CWE-798", "owasp": "A07",
        "passage": (
            "Hardcoded passwords, cryptographic keys, and API tokens in source code or client-side "
            "JavaScript bundles can be easily extracted by attackers. Secrets must always be "
            "injected dynamically from secure environment variables or secret vaults."
        ),
        "scan_rules": [
            {"type": "code_review", "name": "Hardcoded Secrets & API Keys",
             "severity": "high", "cwe": "CWE-798", "owasp": "A07",
             "languages": ["python", "javascript", "php", "java", "go"],
             "pattern": r"(api[_-]?key|secret[_-]?key|password)\s*=\s*['\"][^'\"]{6,}['\"]",
             "remediation": "Store secrets in environment variables or cloud secret managers."}
        ],
    },
    {
        "id": "CWE-502-DESERIALIZATION",
        "source_type": "A",
        "title": "CWE-502: Deserialization of Untrusted Data",
        "authority": "MITRE CWE / OWASP Top 10 A08",
        "url": "https://cwe.mitre.org/data/definitions/502.html",
        "cwe": "CWE-502", "owasp": "A08",
        "passage": (
            "Deserializing untrusted data without validation allows attackers to instantiate "
            "arbitrary classes, manipulate application state, or execute remote code (RCE) "
            "using gadget chains in Python (pickle), Java (ObjectInputStream), or PHP (unserialize)."
        ),
        "scan_rules": [
            {"type": "code_review", "name": "Python Pickle / Insecure Object Deserialization",
             "severity": "high", "cwe": "CWE-502", "owasp": "A08",
             "languages": ["python", "php", "javascript"],
             "pattern": r"(pickle\.loads?\s*\(|yaml\.load\s*\([^,)]+\)|unserialize\s*\(|node-serialize)",
             "remediation": "Use safe JSON serialization and avoid native object deserializers."}
        ],
    },
    {
        "id": "CWE-94-CODE-INJECTION",
        "source_type": "A",
        "title": "CWE-94: Improper Control of Generation of Code (Code Injection)",
        "authority": "MITRE CWE / OWASP Top 10 A03",
        "url": "https://cwe.mitre.org/data/definitions/94.html",
        "cwe": "CWE-94", "owasp": "A03",
        "passage": (
            "Code injection occurs when an application constructs all or part of a code segment "
            "using untrusted input without neutralization (e.g. eval(), Function(), exec()). "
            "Attackers can execute arbitrary instructions within the process context."
        ),
        "scan_rules": [
            {"type": "code_review", "name": "Dynamic Code Evaluation Surface",
             "severity": "high", "cwe": "CWE-94", "owasp": "A03",
             "languages": ["javascript", "python", "php"],
             "pattern": r"(\beval\s*\(|new\s+Function\s*\(|create_function\s*\()",
             "remediation": "Refactor logic to eliminate eval() and dynamic code compilation."}
        ],
    },
    {
        "id": "OWASP-API3-2023-BOPLA",
        "source_type": "A",
        "title": "OWASP API3:2023 Broken Object Property Level Authorization",
        "authority": "OWASP API Security Top 10:2023",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "cwe": "CWE-213", "owasp": "A01",
        "passage": (
            "API3:2023 covers endpoints that expose sensitive object properties (Mass Assignment "
            "or Excessive Data Exposure). Attackers can inspect API responses to read confidential "
            "fields (e.g. password_hash, internal_role) or overwrite admin flags in requests."
        ),
        "scan_rules": [
            {"type": "stateful_api", "name": "API Object Property Exposure",
             "severity": "medium", "cwe": "CWE-213", "owasp": "A01",
             "remediation": "Enforce explicit response data transfer objects (DTOs) and input field allowlists."}
        ],
    },
    {
        "id": "OWASP-API4-2023-UNRESTRICTED",
        "source_type": "A",
        "title": "OWASP API4:2023 Unrestricted Resource Consumption",
        "authority": "OWASP API Security Top 10:2023",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        "cwe": "CWE-770", "owasp": "A05",
        "passage": (
            "API4:2023 occurs when API requests do not restrict execution timeouts, payload sizes, "
            "or pagination limits. Attackers can submit complex nested queries or large page sizes "
            "to exhaust server CPU, memory, and database connections."
        ),
        "scan_rules": [
            {"type": "rate_limiting", "name": "API Resource Consumption Throttling",
             "severity": "medium", "cwe": "CWE-770", "owasp": "A05",
             "remediation": "Cap request payload sizes and set mandatory max page limits on all collections."}
        ],
    },
    {
        "id": "OWASP-API7-2023-SSRF",
        "source_type": "A",
        "title": "OWASP API7:2023 Server-Side Request Forgery on API Endpoints",
        "authority": "OWASP API Security Top 10:2023",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
        "cwe": "CWE-918", "owasp": "A10",
        "passage": (
            "API7:2023 covers API workflows (webhooks, remote image fetching, PDF generators) "
            "where the API fetches resources from client-supplied URLs without blocking private "
            "IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254 cloud metadata services)."
        ),
        "scan_rules": [
            {"type": "open_redirect", "name": "API SSRF Surface",
             "severity": "high", "cwe": "CWE-918", "owasp": "A10",
             "remediation": "Implement strict IP-level DNS resolution checks and reject private/loopback destinations."}
        ],
    },
    {
        "id": "CWE-77-COMMAND-INJECTION",
        "source_type": "A",
        "title": "CWE-77: Improper Neutralization of Special Elements used in a Command",
        "authority": "MITRE CWE / OWASP Top 10 A03",
        "url": "https://cwe.mitre.org/data/definitions/77.html",
        "cwe": "CWE-77", "owasp": "A03",
        "passage": (
            "Command injection happens when an application passes unsanitized user input to a "
            "system shell (system(), popen(), exec(), child_process.exec()). Attackers append "
            "shell metacharacters (; | & ` $) to execute arbitrary OS commands."
        ),
        "scan_rules": [
            {"type": "code_review", "name": "OS Command Execution Surface",
             "severity": "high", "cwe": "CWE-77", "owasp": "A03",
             "languages": ["python", "javascript", "php"],
             "pattern": r"(subprocess\.(Popen|run|call)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\(|shell_exec\s*\()",
             "remediation": "Pass arguments as explicit arrays without invoking a command shell."}
        ],
    },
    {
        "id": "CWE-327-BROKEN-CRYPTO",
        "source_type": "A",
        "title": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "authority": "MITRE CWE / OWASP Top 10 A02",
        "url": "https://cwe.mitre.org/data/definitions/327.html",
        "cwe": "CWE-327", "owasp": "A02",
        "passage": (
            "Using broken cryptographic algorithms (MD5, SHA-1, DES, RC4) or weak random number "
            "generators (random(), Math.random()) compromises confidentiality and token unpredictability. "
            "Modern standards require SHA-256/SHA-3, AES-GCM, and CSPRNGs (os.urandom, crypto.randomBytes)."
        ),
        "scan_rules": [
            {"type": "code_review", "name": "Cryptographic Algorithm Robustness",
             "severity": "medium", "cwe": "CWE-327", "owasp": "A02",
             "languages": ["python", "javascript", "php"],
             "pattern": r"(hashlib\.(md5|sha1)\s*\(|crypto\.createHash\s*\(\s*['\"](md5|sha1)['\"]\s*\))",
             "remediation": "Migrate deprecated hashing/ciphers to SHA-256 and AES-GCM."}
        ],
    },
    {
        "id": "RFC-7489-DMARC",
        "source_type": "A",
        "title": "RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)",
        "authority": "IETF RFC 7489 / M3AAWG Best Practices",
        "url": "https://datatracker.ietf.org/doc/html/rfc7489",
        "cwe": "CWE-358", "owasp": "A05",
        "passage": (
            "DMARC allows domain owners to publish explicit authentication policies (p=reject or p=quarantine) "
            "instructing receiving mail transfer agents how to handle unauthorized emails spoofing their domain. "
            "Without DMARC enforcement, attackers can forge sender headers for phishing and BEC attacks."
        ),
        "scan_rules": [],
    },
    {
        "id": "RFC-7208-SPF",
        "source_type": "A",
        "title": "RFC 7208: Sender Policy Framework (SPF) for Authorizing Email",
        "authority": "IETF RFC 7208 / NIST SP 800-177",
        "url": "https://datatracker.ietf.org/doc/html/rfc7208",
        "cwe": "CWE-358", "owasp": "A05",
        "passage": (
            "Sender Policy Framework (SPF) enables domain administrators to designate authorized IP addresses "
            "and mail exchangers permitted to transmit email on behalf of their domain. Using wildcard mechanisms "
            "such as '+all' negates verification and allows unrestricted domain spoofing."
        ),
        "scan_rules": [],
    },
    {
        "id": "CWE-358-SUBDOMAIN",
        "source_type": "A",
        "title": "CWE-358: Subdomain Exposure & Improper Access Control in Staging Assets",
        "authority": "MITRE CWE / OWASP WSTG-CONF-04",
        "url": "https://cwe.mitre.org/data/definitions/358.html",
        "cwe": "CWE-358", "owasp": "A05",
        "passage": (
            "Unmanaged DNS records, orphaned CNAME pointers, and publicly exposed staging subdomains "
            "(dev., test., staging.) often bypass security controls and leave services susceptible to "
            "subdomain takeover, credential theft, and unauthorized API exploitation."
        ),
        "scan_rules": [],
    },
]

# scan_rules appended onto existing curated records (kept in build_kb.py).
ADD_SCAN_RULES = {
    "OWASP-A03-INJECTION": [
        {"type": "sqli", "name": "sql-injection-surface", "severity": "high",
         "cwe": "CWE-89", "owasp": "A03",
         "markers": ["'", "' OR '1'='1"],
         "error_patterns": [
             r"you have an error in your sql syntax",
             r"unclosed quotation mark",
             r"ora-\d{5}",
             r"sqlite3?\.[a-z_]+ error|sqlite_error",
             r"sqlstate\[",
             r"postgresql.*error|psql::|pg_query\(\)",
             r"microsoft ole ?db provider for sql server",
             r"mysql_fetch|mysqli|syntax error near",
         ],
         "remediation": "Use parameterized queries / prepared statements; suppress verbose database errors."},
        {"type": "xss", "name": "reflected-xss-surface", "severity": "medium",
         "cwe": "CWE-79", "owasp": "A03",
         "markers": ["<websec_xss_probe_9f6b2>", "\"><websec_xss_probe_9f6b2>"],
         "remediation": "Context-aware output-encode all reflected input and deploy a Content-Security-Policy."},
    ],
    "ATTACK-T1498-DOS": [
        {"type": "ddos_mitigation", "name": "ddos-mitigation-posture",
         "severity": "low", "cwe": "CWE-400", "owasp": "A05",
         "waf_headers": [
             "cf-ray", "server: cloudflare", "x-sucuri-id", "akamai",
             "x-amz-cf-id", "x-azure-ref", "x-qw", "x-vercel-id", "x-cache",
             "via: 1.1 google", "x-fastly",
         ],
         "ratelimit_headers": [
             "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
             "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
         ],
         "remediation": "Deploy a WAF/CDN, enforce per-IP rate limiting and request size caps, and set connection timeouts."},
    ],
    "WSTG-INPV-05-SQLI": [
        {"type": "blind_sqli", "name": "blind-sqli-surface", "severity": "high",
         "cwe": "CWE-89", "owasp": "A03",
         "delay": 2.0,
         "timing_payloads": [
             "' OR SLEEP(2)-- ",
             "' OR pg_sleep(2)-- ",
             "' OR WAITFOR DELAY '0:0:2'-- ",
             "' OR DBMS_PIPE.RECEIVE_MESSAGE('x',2)-- ",
         ],
         "bool_true": "' AND '1'='1",
         "bool_false": "' AND '1'='2",
         "remediation": "Use parameterized queries / prepared statements; suppress verbose database errors."},
    ],
    "OWASP-RATELIMIT-BRUTEFORCE": [
        {"type": "rate_limiting", "name": "rate-limit-backoff-posture",
         "severity": "medium", "cwe": "CWE-307", "owasp": "A07",
         "probe_count": 5, "window_sleep": 0.2,
         "remediation": "Enforce per-IP/per-account rate limits with 429 + Retry-After on sensitive and login endpoints."},
    ],
    "CWE-89": [
        {"type": "code_review", "name": "sql-string-concat", "severity": "high",
         "cwe": "CWE-89", "owasp": "A03", "languages": ["python", "php", "javascript", "java"],
         "pattern": r"[\"']\s*(SELECT|INSERT|UPDATE|DELETE)\b[^\"']{0,160}[\"']{1,2}\s*(?:%|\+|\.format\s*\(|\.join\s*\(|f[\"']|\{)",  # noqa: E501
         "confidence": "medium",
         "description": "SQL built by string concatenation/interpolation.",
         "remediation": "Use parameterized queries / prepared statements everywhere; never build SQL by concatenation."},
        {"type": "code_review", "name": "execute-fstring-sql", "severity": "high",
         "cwe": "CWE-89", "owasp": "A03", "languages": ["python"],
         "pattern": r"\.execute\s*\(\s*f[\"']\s*(SELECT|INSERT|UPDATE|DELETE)",
         "confidence": "high",
         "description": "DB-API execute() called with an f-string starting a SQL statement.",
         "remediation": "Pass parameters as a separate argument tuple to execute(sql, params); never inline values."},
        {"type": "code_review", "name": "php-query-var-concat", "severity": "high",
         "cwe": "CWE-89", "owasp": "A03", "languages": ["php"],
         "pattern": r"(mysql_query|mysqli_query|pg_query|sqlsrv_query|query)\s*\(\s*[\"'][^\"']*[\"']\s*\.\s*\$",
         "confidence": "high",
         "description": "SQL query concatenated with a PHP variable.",
         "remediation": "Use PDO prepared statements / mysqli parameter binding."},
        {"type": "code_review", "name": "js-template-literal-sql", "severity": "high",
         "cwe": "CWE-89", "owasp": "A03", "languages": ["javascript"],
         "pattern": r"(query|execute|rawQuery)\s*\(\s*`[^`]*\$\{",
         "confidence": "high",
         "description": "SQL built with a JS template literal that interpolates a value.",
         "remediation": "Use the driver's parameter placeholders (? / :name) and never interpolate into SQL."},
        {"type": "code_review", "name": "java-statement-execute-concat", "severity": "high",
         "cwe": "CWE-89", "owasp": "A03", "languages": ["java"],
         "pattern": r"(executeQuery|executeUpdate|execute)\s*\(\s*[\"'][^\"']*\+\s*\w+",
         "confidence": "medium",
         "description": "JDBC execute() with a string-concatenated SQL statement.",
         "remediation": "Use PreparedStatement with '?' placeholders and setString()/setInt() binding."},
    ],
    "CWE-79": [
        {"type": "code_review", "name": "innerHTML-assign", "severity": "high",
         "cwe": "CWE-79", "owasp": "A03", "languages": ["javascript"],
         "pattern": r"\.innerHTML\s*=\s*(?![\"'][^\"']*[\"']\s*$)\S",
         "confidence": "medium",
         "description": "innerHTML assigned a dynamic value; no context-aware encoding.",
         "remediation": "Use textContent / createElement + text nodes, or encode with an HTML-escape context."},
        {"type": "code_review", "name": "insertadjacenthtml", "severity": "high",
         "cwe": "CWE-79", "owasp": "A03", "languages": ["javascript"],
         "pattern": r"insertAdjacentHTML\s*\(",
         "confidence": "low",
         "description": "insertAdjacentHTML() parses markup from strings; tainted input becomes XSS.",
         "remediation": "Insert text nodes, or escape HTML before parsing; apply CSP."},
        {"type": "code_review", "name": "document-write", "severity": "medium",
         "cwe": "CWE-79", "owasp": "A03", "languages": ["javascript"],
         "pattern": r"document\.write\s*\(",
         "confidence": "medium",
         "description": "document.write() renders raw markup at page load.",
         "remediation": "Build the DOM with textContent and safe DOM APIs; avoid document.write entirely."},
        {"type": "code_review", "name": "react-dangerouslysetinnerhtml", "severity": "high",
         "cwe": "CWE-79", "owasp": "A03", "languages": ["javascript", "typescript"],
         "pattern": r"dangerouslySetInnerHTML",
         "confidence": "high",
         "description": "React dangerouslySetInnerHTML bypasses React's escaping.",
         "remediation": "Prefer React children; if unavoidable, sanitize with an allow-listed HTML sanitizer."},
        {"type": "code_review", "name": "vue-v-html", "severity": "high",
         "cwe": "CWE-79", "owasp": "A03", "languages": ["html", "javascript"],
         "pattern": r"\bv-html\b",
         "confidence": "high",
         "description": "Vue v-html renders raw HTML from bound data.",
         "remediation": "Use interpolation {{ }} or v-text, or sanitize the bound value server-side."},
        {"type": "code_review", "name": "jinja-safe-filter", "severity": "medium",
         "cwe": "CWE-79", "owasp": "A03", "languages": ["python", "html"],
         "pattern": r"\|\s*safe\b",
         "confidence": "low",
         "description": "Jinja2 |safe (or autoescape disabled) suppresses HTML autoescaping.",
         "remediation": "Keep autoescape on; mark only trusted markup safe, never user input."},
        {"type": "code_review", "name": "ejs-unescaped-output", "severity": "medium",
         "cwe": "CWE-79", "owasp": "A03", "languages": ["html", "javascript"],
         "pattern": r"<%-",
         "confidence": "low",
         "description": "EJS <%- outputs unescaped HTML.",
         "remediation": "Use <%= for escaped output, or HTML-escape the interpolated value."},
    ],
    "CWE-918": [
        {"type": "code_review", "name": "urlopen-user-input", "severity": "high",
         "cwe": "CWE-918", "owasp": "A10", "languages": ["python"],
         "pattern": r"(urllib\.request\.)?urlopen\s*\(\s*[a-z_]\w*",
         "confidence": "medium",
         "description": "urlopen() fed a variable (request-derived URLs can reach internal hosts).",
         "remediation": "Allow-list permitted schemes/hosts, block link-local/loopback/cloud metadata IPs, and resolve+validate before fetch."},
        {"type": "code_review", "name": "requests-user-supplied-url", "severity": "high",
         "cwe": "CWE-918", "owasp": "A10", "languages": ["python"],
         "pattern": r"requests\.(get|post|put|patch|head)\s*\(\s*(request\.|req\.|url|target|uri|link|href|redirect)",
         "confidence": "medium",
         "description": "Outbound request URL taken from request/user-controlled input.",
         "remediation": "Never send user-supplied URLs directly; apply a strict allow-list and block private ranges."},
        {"type": "code_review", "name": "js-fetch-user-url", "severity": "high",
         "cwe": "CWE-918", "owasp": "A10", "languages": ["javascript"],
         "pattern": r"(fetch|axios\.\w+|request\.\w+|got)\s*\(\s*(url|target|req\.|request\.|ctx\.|params)",
         "confidence": "medium",
         "description": "Client/server fetch to a user-controlled URL (SSRF in server-side code).",
         "remediation": "Validate the scheme and host against an allow-list; prohibit private IPs and metadata endpoints."},
        {"type": "code_review", "name": "php-file-get-contents-var", "severity": "high",
         "cwe": "CWE-918", "owasp": "A10", "languages": ["php"],
         "pattern": r"file_get_contents\s*\(\s*\$",
         "confidence": "medium",
         "description": "file_get_contents() with a PHP variable can be abused to fetch local files/SSRF.",
         "remediation": "Validate scheme/host with an allow-list and reject file://, 127.0.0.1 and RFC1918 ranges."},
        {"type": "code_review", "name": "java-openconnection-var", "severity": "medium",
         "cwe": "CWE-918", "owasp": "A10", "languages": ["java"],
         "pattern": r"\.openConnection\s*\(\s*\w+",
         "confidence": "medium",
         "description": "openConnection() on a variable URL derived from untrusted input.",
         "remediation": "Resolve and allow-list the host before connecting; block private/loopback addresses."},
    ],
    "CWE-78": [
        {"type": "code_review", "name": "python-command-shell", "severity": "high",
         "cwe": "CWE-78", "owasp": "A03", "languages": ["python"],
         "pattern": r"(os\.system\s*\(|os\.popen\s*\(|subprocess\.(run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True)",
         "confidence": "high",
         "description": "OS command executed through the shell.",
         "remediation": "Call executables directly with an argument list (shell=False), never with user input."},
        {"type": "code_review", "name": "php-command-exec", "severity": "high",
         "cwe": "CWE-78", "owasp": "A03", "languages": ["php"],
         "pattern": r"\b(system|shell_exec|passthru|proc_open|popen)\s*\([^)]*\$",
         "confidence": "high",
         "description": "PHP command execution built from a variable.",
         "remediation": "Avoid OS command execution; use libraries with allow-lists and escapeshellarg only as a last resort."},
        {"type": "code_review", "name": "node-child-process-exec", "severity": "high",
         "cwe": "CWE-78", "owasp": "A03", "languages": ["javascript"],
         "pattern": r"child_process\.(exec|execSync|spawnSync)\s*\([^)]*shell\s*=\s*True|child_process\.(exec|execSync)\s*\(",
         "confidence": "medium",
         "description": "Node executes OS commands via the shell.",
         "remediation": "Use spawn() with an args array and shell:false; never pass user input to a shell string."},
        {"type": "code_review", "name": "java-runtime-exec", "severity": "high",
         "cwe": "CWE-78", "owasp": "A03", "languages": ["java"],
         "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(",
         "confidence": "medium",
         "description": "Java executes OS commands; variable arguments may be tainted.",
         "remediation": "Prefer library APIs; if required, validate each argument against an allow-list."},
    ],
    "CWE-94": [
        {"type": "code_review", "name": "python-eval-exec", "severity": "high",
         "cwe": "CWE-94", "owasp": "A03", "languages": ["python"],
         "pattern": r"\beval\s*\(|\bexec\s*\(|(?<!re\.)\bcompile\s*\(|\bexecfile\s*\(",
         "confidence": "high",
         "description": "Dynamic Python code evaluation; tainted input becomes RCE.",
         "remediation": "Never eval/exec user input; use allow-listed parsers (ast) or proper data serialization."},
        {"type": "code_review", "name": "js-eval", "severity": "high",
         "cwe": "CWE-94", "owasp": "A03", "languages": ["javascript"],
         "pattern": r"\beval\s*\(|new\s+Function\s*\(",
         "confidence": "high",
         "description": "Dynamic JS evaluation via eval/Function.",
         "remediation": "Avoid eval entirely; use JSON.parse and safe parsers."},
    ],
    "CWE-798": [
        {"type": "code_review", "name": "hardcoded-password", "severity": "high",
         "cwe": "CWE-798", "owasp": "A07", "languages": ["python", "php", "javascript", "java", "ruby", "go"],
         "pattern": r"\b(password|passwd|pwd|pass|db_passwd)\s*[=:]\s*[\"'][^\"']{3,}[\"']",
         "confidence": "medium",
         "description": "Hardcoded password/credential literal in source.",
         "remediation": "Store secrets in a vault/env vars; rotate any committed credential immediately."},
        {"type": "code_review", "name": "hardcoded-api-key", "severity": "high",
         "cwe": "CWE-798", "owasp": "A07", "languages": ["python", "php", "javascript", "java", "ruby", "go"],
         "pattern": r"\b(api[_-]?key|apikey|secret|secret_key|secret_key_id|access_key|private_key|token)\s*[=:]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']",
         "confidence": "medium",
         "description": "Hardcoded API key/secret literal.",
         "remediation": "Move secrets to environment variables or a secret manager; rotate the exposed key."},
        {"type": "code_review", "name": "default-credentials", "severity": "medium",
         "cwe": "CWE-798", "owasp": "A07", "languages": ["generic"],
         "pattern": r"(username|user|admin|login|root)\s*[=:]\s*[\"'](admin|root|password|123456|toor|changeme)[\"']",
         "confidence": "low",
         "description": "Well-known default credential pair.",
         "remediation": "Force unique credentials on first use and disable default accounts."},
    ],
    "OWASP-API-2023-AUTH": [
        {"type": "code_review", "name": "jwt-alg-none", "severity": "high",
         "cwe": "CWE-287", "owasp": "A07", "languages": ["javascript", "java", "python", "go"],
         "pattern": r"[\"']alg[\"']\s*:\s*[\"']none[\"']|\bsecretOrPublicKey\b|verify\s*\([^)]*,\s*[\"']none[\"']",
         "confidence": "high",
         "description": "JWT signed/verified with alg 'none' or secret used as public key.",
         "remediation": "Pin the accepted algorithm to RS256/ES256 and reject 'none'; use a verified library default."},
        {"type": "code_review", "name": "insecure-authz-comment", "severity": "low",
         "cwe": "CWE-285", "owasp": "A01", "languages": ["generic"],
         "pattern": r"#\s*(TODO|FIXME|HACK)[^\n]*(auth|permission|role|admin|access control)",
         "confidence": "low",
         "description": "Pending authorization/access-control code marked for review.",
         "remediation": "Implement and test access control before merge; enforce least privilege."},
    ],
    "CWE-295": [
        {"type": "code_review", "name": "tls-verification-disabled", "severity": "high",
         "cwe": "CWE-295", "owasp": "A02", "languages": ["python", "javascript", "go"],
         "pattern": r"verify\s*=\s*False|VERIFY_NONE|CERT_NONE|check_hostname\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*=\s*true|TLSInsecureSkipVerify\s*=\s*true",  # noqa: E501
         "confidence": "high",
         "description": "TLS certificate validation disabled.",
         "remediation": "Always verify certificates and hostname; never disable in production."},
    ],
    "CWE-502-DESERIALIZATION": [
        {"type": "code_review", "name": "python-pickle-load", "severity": "high",
         "cwe": "CWE-502", "owasp": "A08", "languages": ["python"],
         "pattern": r"pickle\.loads?\s*\(|\bcPickle\b",
         "confidence": "high",
         "description": "pickle.loads() on (possibly untrusted) data executes code on decode.",
         "remediation": "Never deserialize untrusted data with pickle; use JSON and validate the schema."},
        {"type": "code_review", "name": "yaml-unsafe-load", "severity": "medium",
         "cwe": "CWE-502", "owasp": "A08", "languages": ["python"],
         "pattern": r"yaml\.load\s*\(",
         "confidence": "medium",
         "description": "yaml.load() without a safe loader can instantiate arbitrary Python objects.",
         "remediation": "Use yaml.safe_load or a schema-bound parser."},
        {"type": "code_review", "name": "php-unserialize", "severity": "high",
         "cwe": "CWE-502", "owasp": "A08", "languages": ["php"],
         "pattern": r"unserialize\s*\(",
         "confidence": "high",
         "description": "unserialize() on untrusted data enables object-injection gadgets.",
         "remediation": "Deserialize only signed, allow-listed payloads; prefer JSON."},
        {"type": "code_review", "name": "java-objectinputstream", "severity": "high",
         "cwe": "CWE-502", "owasp": "A08", "languages": ["java"],
         "pattern": r"ObjectInputStream|readObject\s*\(",
         "confidence": "high",
         "description": "Java native deserialization of (possibly) untrusted input.",
         "remediation": "Use allow-listed deserialization (filtered stream / safe encodings like JSON)."},
        {"type": "code_review", "name": "node-serialize", "severity": "high",
         "cwe": "CWE-502", "owasp": "A08", "languages": ["javascript"],
         "pattern": r"node-serialize|serialize\.unserialize\s*\(",
         "confidence": "high",
         "description": "node-serialize unserialize executes JavaScript in the payload.",
         "remediation": "Do not unserialize untrusted buffers; use JSON with schema validation."},
    ],
    "CWE-327": [
        {"type": "code_review", "name": "weak-hash-credential", "severity": "medium",
         "cwe": "CWE-327", "owasp": "A02", "languages": ["python", "php", "javascript", "java", "ruby"],
         "pattern": r"(hashlib\.md5|hashlib\.sha1|\.sha1\s*\(|\bmd5\s*\(|\bsha1\s*\(|MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-1)[\"'])",
         "confidence": "medium",
         "description": "MD5/SHA-1 used (common for credential hashing / integrity where collision resistance matters).",
         "remediation": "Use Argon2/bcrypt/scrypt/PBKDF2 for passwords and SHA-256+ for integrity."},
        {"type": "code_review", "name": "weak-cipher", "severity": "high",
         "cwe": "CWE-327", "owasp": "A02", "languages": ["java", "python"],
         "pattern": r"Cipher\.getInstance\s*\(\s*[\"'](DES|DESede|RC4|AES/ECB|AES/CBC/NoPadding)|ECB_MODE|DES\.new\b",
         "confidence": "medium",
         "description": "Legacy/weak cipher or ECB mode (no diffusion across blocks).",
         "remediation": "Use AES-GCM (authenticated encryption) with unique nonces."},
        {"type": "code_review", "name": "random-secret-source", "severity": "medium",
         "cwe": "CWE-330", "owasp": "A02", "languages": ["python", "javascript", "java", "php"],
         "pattern": r"random\.(randint|choice|choices|random|shuffle|uniform)\s*\([^)]*(token|otp|secret|password|nonce|salt)",
         "confidence": "low",
         "description": "Non-CSPRNG random used near a security token/secret.",
         "remediation": "Use os.urandom / secrets / crypto.randomBytes for tokens, nonces and keys."},
    ],
    "WSTG-INPV-07-PATHTRAV": [
        {"type": "code_review", "name": "file-open-tainted-path", "severity": "medium",
         "cwe": "CWE-22", "owasp": "A01", "languages": ["python", "javascript", "ruby"],
         "pattern": r"\bopen\s*\([^)]*(request\.|req\.|param|path|filename|file)[^)]*[+\]]|\bopen\s*\(\s*\w+\s*\+",
         "confidence": "low",
         "description": "File opened from a concatenated / user-influenced path.",
         "remediation": "Resolve to an absolute path and verify it stays inside an allow-listed root."},
        {"type": "code_review", "name": "php-include-tainted", "severity": "high",
         "cwe": "CWE-98", "owasp": "A01", "languages": ["php"],
         "pattern": r"(include|include_once|require|require_once)\s*\(?\s*\$",
         "confidence": "high",
         "description": "PHP include/require from a variable (LFI/RCE risk).",
         "remediation": "Resolve to an allow-listed absolute path; never accept a file path from input."},
    ],
    "CWE-601": [
        {"type": "code_review", "name": "open-redirect-next-param", "severity": "medium",
         "cwe": "CWE-601", "owasp": "A01", "languages": ["python", "javascript", "php", "ruby"],
         "pattern": r"redirect\s*\(\s*(request\.|req\.|params|next|url|return|dest|query\.)|header\s*\(\s*[\"']Location:\s*[^\"']*\$",
         "confidence": "medium",
         "description": "Redirect target taken from a user-controlled parameter.",
         "remediation": "Redirect only to allow-listed internal paths; reject off-site schemes/hosts."},
    ],
    "CWE-434": [
        {"type": "code_review", "name": "php-upload-unvalidated", "severity": "medium",
         "cwe": "CWE-434", "owasp": "A03", "languages": ["php"],
         "pattern": r"move_uploaded_file\s*\(",
         "confidence": "low",
         "description": "Upload handler stores an uploaded file; verify extension/content-type handling.",
         "remediation": "Validate magic bytes, generate a random filename, store outside webroot, and deny script execution."},
    ],
    "CWE-532": [
        {"type": "code_review", "name": "log-sensitized-secret", "severity": "medium",
         "cwe": "CWE-532", "owasp": "A09", "languages": ["python", "javascript", "java", "php"],
         "pattern": r"(logging\.\w+|print|console\.log|logger\.\w+|log\.\w+)\s*\([^)]*(password|passwd|secret|token|api_key|authorization)",
         "confidence": "low",
         "description": "Sensitive value passed to a log/print sink.",
         "remediation": "Log only non-sensitive identifiers; redact secrets before logging."},
    ],
    "OWASP-SCVS-SUPPLYCHAIN": [
        {"type": "dependency_scan", "name": "known-vulnerable-dependency",
         "severity": "high", "cwe": "CWE-1104", "owasp": "A06",
         "confidence": "medium",
         "description": "Third-party dependency resolves to a known vulnerable version.",
         "remediation": "Upgrade to a fixed version, pin exact versions, and re-scan; keep the local advisory seed refreshed."},
    ],
    "CWE-611-XXE": [
        {"type": "code_review", "name": "xxe-xml-parse", "severity": "high",
         "cwe": "CWE-611", "owasp": "A05", "languages": ["python", "java", "php", "javascript"],
         "pattern": r"(etree\.parse\s*\(|etree\.fromstring\s*\(|xml\.dom\.minidom|DocumentBuilderFactory|SAXParserFactory|simplexml_load_string|xml2js\.parseString)",
         "confidence": "medium",
         "description": "XML parsed without explicit external entity resolution disabling.",
         "remediation": "Disable external entity processing (resolve_entities=False / feature disallow-doctype-decl)."},
    ],
    "CWE-1321-PROTOTYPE-POLLUTION": [
        {"type": "code_review", "name": "prototype-pollution-pattern", "severity": "high",
         "cwe": "CWE-1321", "owasp": "A03", "languages": ["javascript", "typescript"],
         "pattern": r"(__proto__|constructor\s*\[\s*[\"']prototype[\"']|\.prototype\b|lodash\.(merge|defaultsDeep|extend)\s*\()",
         "confidence": "medium",
         "description": "Direct assignment or recursive merge targeting __proto__ or prototype.",
         "remediation": "Validate keys against '__proto__' and 'constructor', use Object.create(null), or Map."},
    ],
    "CWE-1336-SSTI": [
        {"type": "code_review", "name": "ssti-template-string", "severity": "high",
         "cwe": "CWE-1336", "owasp": "A03", "languages": ["python", "javascript", "php"],
         "pattern": r"(render_template_string\s*\(|jinja2\.Template\s*\(|ejs\.render\s*\(\s*`|pug\.compile\s*\()",
         "confidence": "high",
         "description": "Template rendered directly from a string (Server-Side Template Injection surface).",
         "remediation": "Pass data as context variables to static template files; never render dynamic strings as templates."},
    ],
    "CWE-295": [
        {"type": "code_review", "name": "disabled-ssl-verification", "severity": "high",
         "cwe": "CWE-295", "owasp": "A02", "languages": ["python", "javascript", "java", "php"],
         "pattern": r"(verify\s*=\s*False|check_hostname\s*=\s*False|_create_unverified_context|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]|TrustAllStrategy|NullTrustManager)",
         "confidence": "high",
         "description": "TLS/SSL certificate validation explicitly disabled (vulnerable to MitM).",
         "remediation": "Enable strict TLS certificate verification; install proper root CA bundles instead of disabling checks."},
    ],
    "CWE-352": [
        {"type": "code_review", "name": "csrf-protection-disabled", "severity": "high",
         "cwe": "CWE-352", "owasp": "A01", "languages": ["python", "javascript", "php"],
         "pattern": r"(@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*:\s*false|csrf_protection\s*=\s*false)",
         "confidence": "high",
         "description": "CSRF protection explicitly disabled on endpoint or application config.",
         "remediation": "Enable CSRF token verification and SameSite cookie policies on all state-changing endpoints."},
    ],
    "CWE-209-ERROR-LEAK": [
        {"type": "code_review", "name": "verbose-debug-exposure", "severity": "medium",
         "cwe": "CWE-209", "owasp": "A05", "languages": ["python", "php", "javascript", "java"],
         "pattern": r"(app\.debug\s*=\s*True|DEBUG\s*=\s*True|display_errors\s*=\s*On|ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]1['\"]\)|traceback\.print_exc\s*\()",
         "confidence": "medium",
         "description": "Debug mode or verbose stack trace printing enabled.",
         "remediation": "Disable debug mode in production; implement global error handlers that return sanitized generic errors."},
    ],
    "CWE-77-COMMAND-INJECTION": [
        {"type": "code_review", "name": "command-injection-shell", "severity": "high",
         "cwe": "CWE-77", "owasp": "A03", "languages": ["python", "javascript", "php", "java"],
         "pattern": r"(subprocess\.(Popen|run|call)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(|child_process\.exec\s*\(|Runtime\.getRuntime\(\)\.exec|passthru\s*\(|shell_exec\s*\()",
         "confidence": "high",
         "description": "OS command constructed or executed with shell invocation enabled.",
         "remediation": "Pass arguments as an explicit array without a shell (shell=False) or use safe native library APIs."},
    ],
    "W3C-PERMISSIONS-POLICY": [
        {"type": "missing_header", "name": "missing-permissions-policy", "severity": "low",
         "cwe": "CWE-693", "owasp": "A05", "header": "permissions-policy",
         "description": "Permissions-Policy header missing; browser hardware APIs remain unconstrained.",
         "remediation": "Deploy Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=() to restrict unneeded APIs."},
    ],
    "W3C-REFERRER-POLICY": [
        {"type": "missing_header", "name": "missing-referrer-policy", "severity": "low",
         "cwe": "CWE-116", "owasp": "A05", "header": "referrer-policy",
         "description": "Referrer-Policy header missing; path or query parameters may leak cross-origin.",
         "remediation": "Deploy Referrer-Policy: strict-origin-when-cross-origin to prevent URL token leakage."},
    ],
    "W3C-COOP-COEP": [
        {"type": "missing_header", "name": "missing-coop-header", "severity": "low",
         "cwe": "CWE-346", "owasp": "A05", "header": "cross-origin-opener-policy",
         "description": "Cross-Origin-Opener-Policy (COOP) missing; window is not isolated from cross-origin popups.",
         "remediation": "Deploy Cross-Origin-Opener-Policy: same-origin to prevent XS-Leaks and Spectre attacks."},
    ],
}


def apply_expansion(records):
    """Append expansion records (dedup by id) and patch scan_rules onto existing
    curated records. Returns the same list, modified in place."""
    by_id = {r.get("id"): r for r in records if r.get("id")}
    # Append OPEN_KB_RECORDS first so ADD_SCAN_RULES can target them too.
    for rec in OPEN_KB_RECORDS:
        if rec.get("id") and rec["id"] in by_id:
            continue
        records.append(rec)
        if rec.get("id"):
            by_id[rec["id"]] = rec
    for rid, rules in ADD_SCAN_RULES.items():
        rec = by_id.get(rid)
        if rec is not None:
            existing = rec.setdefault("scan_rules", [])
            existing.extend(rules)
    return records
