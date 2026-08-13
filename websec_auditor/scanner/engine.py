"""Deterministic, safe security scanner.

Probes (all read-only / benign):
  1. Security headers          (config.REQUIRED_HEADERS + EXTRA_HEADERS)
  2. Header posture quality    (CSP directives, HSTS policy, Content-Type charset)
  3. TLS version + cert expiry (config.MIN_TLS_VERSION / CWE-295)
  4. Cookie hardening          (config.COOKIE_FLAGS) + cacheability (CWE-524)
  5. CORS posture              (wildcard/reflected origin, CWE-942)
  6. Info disclosure           (Server / X-Powered-By, CWE-200)
  7. Plaintext transport       (HTTP target, CWE-319)
  8. Directory listing         (CWE-548)
  9. Reflection probe          (XSS surface, CWE-79)
 10. SQL error signature probe (injection surface indicator, CWE-89)

Every finding carries a source_id that maps to a passage in the knowledge base,
so the analyzer can cite the exact book/standard behind it.

SAFETY: only scan targets the user owns/authorized. No destructive payloads,
no DoS, no fuzzing. Injection checks use a benign marker + error-signature
detection only.
"""
from __future__ import annotations
import os
import re
import ssl
import socket
import json
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict

from websec_auditor import config


@dataclass
class Finding:
    check: str
    name: str
    status: str          # "pass" | "fail" | "warn" | "info"
    severity: str        # "high" | "medium" | "low" | "info"
    detail: str
    source_id: str
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    scheme: str = ""
    findings: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self):
        return {"target": self.target, "scheme": self.scheme,
                "findings": [f.to_dict() for f in self.findings], "raw": self.raw}

    def add(self, f: Finding):
        self.findings.append(f)


def _get(url: str, timeout: int = 10, custom_headers: dict = None, method: str = None):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 websec-auditor/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if custom_headers:
        headers.update(custom_headers)
    req = urllib.request.Request(url, headers=headers, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def load_kb_rules():
    """Load dynamic audit rules directly from the compiled Knowledge Base (data/kb_books.jsonl).
    Each entry in the KB carrying a `scan_rules` array provides test parameters, severity,
    and remediation instructions tied directly to that book/standard passage.
    """
    rules = []
    if not os.path.exists(config.KB_FILE):
        return rules
    try:
        with open(config.KB_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if "scan_rules" in rec:
                    for r in rec["scan_rules"]:
                        r_copy = dict(r)
                        r_copy["source_id"] = rec.get("id", "")
                        r_copy["cwe"] = r_copy.get("cwe") or rec.get("cwe", "")
                        r_copy["owasp"] = r_copy.get("owasp") or rec.get("owasp", "")
                        rules.append(r_copy)
    except Exception:
        pass
    return rules


def check_headers(result: ScanResult, headers: dict, kb_rules=None):
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    header_rules = [r for r in kb_rules if r.get("type") == "header_required"]
    
    if not header_rules:
        for hname, spec in config.REQUIRED_HEADERS.items():
            header_rules.append({
                "name": hname, "severity": spec["severity"], "cwe": spec["cwe"],
                "owasp": spec["owasp"], "source_id": spec["source_id"], "remediation": spec["remediation"]
            })
            
    for rule in header_rules:
        hname = rule["name"].lower()
        if hname in headers:
            result.add(Finding(
                check="security_headers", name=f"Header present: {hname}",
                status="pass", severity="info", detail=f"{hname}: {headers[hname][:80]}",
                source_id=rule["source_id"], cwe=rule["cwe"], owasp=rule["owasp"]))
        else:
            result.add(Finding(
                check="security_headers", name=f"Missing header: {hname}",
                status="fail", severity=rule.get("severity", "medium"),
                detail=f"Response does not include {hname}.",
                source_id=rule["source_id"], cwe=rule["cwe"], owasp=rule["owasp"],
                remediation=rule.get("remediation", "")))


def check_cookies(result: ScanResult, resp, kb_rules=None):
    set_cookie = resp.headers.get_all("Set-Cookie") or []
    if not set_cookie:
        result.add(Finding(
            check="cookies", name="No session cookies set", status="info",
            severity="info", detail="No Set-Cookie header observed on this response.",
            source_id="OWASP-SESSION"))
        return
    combined = " ".join(set_cookie)
    
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    cookie_rules = [r for r in kb_rules if r.get("type") == "cookie_flag"]
    if not cookie_rules:
        for flag, spec in config.COOKIE_FLAGS.items():
            cookie_rules.append({
                "flag": flag, "severity": spec["severity"], "cwe": spec["cwe"],
                "owasp": spec["owasp"], "source_id": spec["source_id"], "remediation": spec["remediation"]
            })
            
    for rule in cookie_rules:
        flag = rule["flag"]
        present = re.search(rf"\b{flag}\b", combined, re.IGNORECASE)
        if present:
            result.add(Finding(
                check="cookies", name=f"Cookie flag present: {flag}",
                status="pass", severity="info", detail=f"{flag} flag found.",
                source_id=rule["source_id"], cwe=rule["cwe"], owasp=rule["owasp"]))
        else:
            result.add(Finding(
                check="cookies", name=f"Missing cookie flag: {flag}",
                status="fail", severity=rule.get("severity", "high"),
                detail=f"A session cookie is missing the {flag} attribute.",
                source_id=rule["source_id"], cwe=rule["cwe"], owasp=rule["owasp"],
                remediation=rule.get("remediation", "")))


def check_scheme(result: ScanResult, scheme: str, host: str):
    """Flag plaintext HTTP transport (CWE-319); dev loopbacks are informational."""
    if scheme != "http":
        return
    local = host in ("127.0.0.1", "localhost", "::1")
    spec = config.PLAINTEXT_RULE
    result.add(Finding(
        check="plaintext", name="Plaintext HTTP transport",
        status="info" if local else "fail",
        severity="info" if local else spec["severity"],
        detail=("Local demo over HTTP (development only)." if local else
                "Site is served over unencrypted HTTP; traffic is sent in plaintext."),
        source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
        remediation="" if local else spec["remediation"]))


def check_csp_quality(result: ScanResult, headers: dict):
    """CSP present but weakened by unsafe-inline/unsafe-eval/wildcards (CWE-79),
    or no clickjacking control present (CWE-1021)."""
    csp = headers.get("content-security-policy")
    if not csp:
        return
    low = csp.lower()
    bad = [d for d in config.CSP_DANGEROUS if d in low]
    bare_star = bool(re.search(r"(?:^|[\s;])'?\*'?(?:[\s;]|$)", csp))
    if bare_star:
        bad.append("*")
    broad = [b for b in config.CSP_BROAD if b in low]
    if bad:
        result.add(Finding(
            check="csp_quality", name="Weak CSP directives", status="fail",
            severity="medium",
            detail=f"CSP permits {', '.join(bad)}; these weaken XSS defenses.",
            source_id="OWASP-CSP", cwe="CWE-79", owasp="A03",
            remediation=("Remove unsafe-inline / unsafe-eval and wildcard sources from CSP; "
                         "add frame-ancestors 'none'.")))
    elif broad:
        result.add(Finding(
            check="csp_quality", name="Broad CSP sources", status="warn",
            severity="low",
            detail=f"CSP allows broad source patterns: {', '.join(broad)}",
            source_id="OWASP-CSP", cwe="CWE-79", owasp="A03",
            remediation=("Replace broad sources (subdomain wildcards, http:) with explicit "
                         "trusted origins.")))
    else:
        result.add(Finding(
            check="csp_quality", name="CSP directives look safe", status="pass",
            severity="info", detail="No unsafe-inline/unsafe-eval/wildcard in CSP.",
            source_id="OWASP-CSP", cwe="CWE-79", owasp="A03"))
    if "frame-ancestors" not in low and "x-frame-options" not in headers:
        result.add(Finding(
            check="csp_quality", name="No clickjacking control", status="warn",
            severity="medium",
            detail="CSP present but lacks frame-ancestors, and X-Frame-Options is absent.",
            source_id="OWASP-CLICKJACK", cwe="CWE-1021", owasp="A05",
            remediation="Add CSP frame-ancestors 'none' (or X-Frame-Options: DENY)."))


def check_hsts_quality(result: ScanResult, headers: dict):
    """HSTS present but weak policy (ASVS 9.2.3 / OWASP TLS cheat sheet)."""
    hsts = headers.get("strict-transport-security")
    if not hsts:
        return
    m = re.search(r"max-age=(\d+)", hsts)
    age = int(m.group(1)) if m else 0
    issues = []
    if age < config.HSTS_MIN_MAX_AGE:
        issues.append(f"max-age={age} (recommend >= {config.HSTS_MIN_MAX_AGE})")
    if "includesubdomains" not in hsts.lower():
        issues.append("missing includeSubDomains")
    if issues:
        result.add(Finding(
            check="hsts_quality", name="HSTS policy is weak", status="warn",
            severity="medium",
            detail="; ".join(issues) + ".",
            source_id="OWASP-TLS", cwe="CWE-319", owasp="A02",
            remediation=f"Use {config.HSTS_SUGGESTED}."))


def check_cors(result: ScanResult, headers: dict):
    """Overly permissive CORS: wildcard or null origin (CWE-942)."""
    acao = headers.get("access-control-allow-origin")
    if not acao:
        return
    acao = acao.strip()
    spec = config.CORS_RULE
    if acao == "*":
        acac = headers.get("access-control-allow-credentials", "").lower() == "true"
        if acac:
            result.add(Finding(
                check="cors", name="Overly permissive CORS: wildcard + credentials", status="fail",
                severity="high",
                detail="Access-Control-Allow-Origin: * with Allow-Credentials lets any "
                       "origin issue credentialed requests and read the responses.",
                source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
                remediation=spec["remediation"]))
        else:
            result.add(Finding(
                check="cors", name="Overly permissive CORS: wildcard origin", status="warn",
                severity=spec["severity"],
                detail="Access-Control-Allow-Origin: * lets any origin read this "
                       "resource (no credentials involved, but the allow-list is empty).",
                source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
                remediation=spec["remediation"]))
    elif acao == "null":
        result.add(Finding(
            check="cors", name="CORS reflects null origin", status="warn",
            severity="low",
            detail="Access-Control-Allow-Origin: null is reflected for sandboxed/file origins.",
            source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
            remediation="Do not return ACAO: null; whitelist specific origins."))


def check_info_disclosure(result: ScanResult, headers: dict):
    """Server / X-Powered-By banners leak stack fingerprint (CWE-200)."""
    for hname, spec in config.DISCLOSURE_HEADERS.items():
        if hname in headers:
            result.add(Finding(
                check="info_disclosure", name=f"Technology disclosure: {hname}",
                status="warn", severity=spec["severity"],
                detail=f"{hname}: {headers[hname][:120]} (advertises server software/version).",
                source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
                remediation=spec["remediation"]))


def check_extra_headers(result: ScanResult, headers: dict):
    """Permissive defaulted headers (Permissions-Policy) + Content-Type charset."""
    for hname, spec in config.EXTRA_HEADERS.items():
        if hname not in headers:
            result.add(Finding(
                check="extra_headers", name=f"Missing header: {hname}",
                status="fail", severity=spec["severity"],
                detail=f"Response does not include {hname}.",
                source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
                remediation=spec["remediation"]))
        else:
            result.add(Finding(
                check="extra_headers", name=f"Header present: {hname}",
                status="pass", severity="info",
                detail=f"{hname}: {headers[hname][:80]}",
                source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"]))
    ct = headers.get("content-type")
    if ct and "text/html" in ct.lower() and "charset" not in ct.lower():
        result.add(Finding(
            check="extra_headers", name="Content-Type missing charset", status="warn",
            severity="low", detail="HTML response Content-Type lacks a charset.",
            source_id="OWASP-SEC-HEADERS", cwe="CWE-16", owasp="A05",
            remediation="Include charset=utf-8 in the Content-Type header."))


def check_cache(result: ScanResult, resp):
    """Session responses must not be cacheable (CWE-524)."""
    set_cookie = resp.headers.get_all("Set-Cookie") or []
    if not set_cookie:
        return
    cc = (resp.headers.get("Cache-Control") or "").lower()
    if "no-store" not in cc:
        spec = config.CACHE_RULE
        result.add(Finding(
            check="cache", name="Session response is cacheable", status="fail",
            severity=spec["severity"],
            detail="Response sets a cookie but Cache-Control does not include no-store.",
            source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
            remediation=spec["remediation"]))


def check_directory_listing(result: ScanResult, body: str):
    """Server directory browsing enabled (CWE-548)."""
    if body and "index of /" in body.lower():
        spec = config.DIRLIST_RULE
        result.add(Finding(
            check="dirlisting", name="Directory listing exposed", status="fail",
            severity=spec["severity"],
            detail="Response body contains 'Index of /' (server directory browsing is enabled).",
            source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
            remediation=spec["remediation"]))


def check_tls(result: ScanResult, host: str, port: int = 443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version()
                ok = ver in ("TLSv1.2", "TLSv1.3")
                result.add(Finding(
                    check="tls", name="TLS version", status="pass" if ok else "fail",
                    severity="info" if ok else "high",
                    detail=f"Negotiated {ver}.",
                    source_id="OWASP-TLS", cwe="CWE-319", owasp="A02",
                    remediation="" if ok else "Disable TLS < 1.2; enforce TLS 1.2+."))
                # cipher info
                try:
                    cipher = ssock.cipher()
                    result.raw["tls_cipher"] = cipher[0] if cipher else None
                except Exception:
                    pass
                # certificate expiry (CWE-295)
                try:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter") if cert else None
                    if not_after:
                        from datetime import datetime, timezone
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp = exp.replace(tzinfo=timezone.utc)
                        days = (exp - datetime.now(timezone.utc)).days
                        if days < 0:
                            result.add(Finding(
                                check="tls_cert", name="TLS certificate expired", status="fail",
                                severity="high", detail=f"Certificate expired {abs(days)} days ago.",
                                source_id="CWE-295", cwe="CWE-295", owasp="A02",
                                remediation="Renew the TLS certificate immediately."))
                        elif days < 30:
                            result.add(Finding(
                                check="tls_cert", name="TLS certificate expiring soon", status="warn",
                                severity="medium", detail=f"Certificate expires in {days} days.",
                                source_id="CWE-295", cwe="CWE-295", owasp="A02",
                                remediation="Renew before expiry; automate certificate renewal."))
                except Exception:
                    pass
    except ssl.SSLError as e:
        result.add(Finding(
            check="tls", name="TLS handshake", status="fail", severity="high",
            detail=f"TLS handshake failed: {e}", source_id="OWASP-TLS",
            cwe="CWE-319", owasp="A02", remediation="Fix TLS configuration."))
    except Exception as e:
        result.add(Finding(
            check="tls", name="TLS handshake", status="warn", severity="medium",
            detail=f"Could not test TLS: {e}", source_id="OWASP-TLS"))


def _scan_body_for_sql_error(result: ScanResult, body: str):
    """Flag verbose SQL error signatures in a response body (CWE-89/200)."""
    if not body:
        return
    low = body.lower()
    for sig in config.SQL_ERROR_SIGNATURES:
        if sig in low:
            result.add(Finding(
                check="sqli_error", name="SQL error signature in response",
                status="fail", severity="high",
                detail=(f"Response contains SQL error signature '{sig}'. "
                        f"Verbose errors leak schema and indicate an "
                        f"injection surface (CWE-200/CWE-89)."),
                source_id="CWE-89", cwe="CWE-89", owasp="A03",
                remediation=("Suppress verbose SQL errors and use "
                             "parameterized queries.")))
            break


def check_framework_errors(result: ScanResult, body: str):
    """Flag verbose framework stack traces / debug error pages (CWE-200 / CWE-16)."""
    if not body:
        return
    low = body.lower()
    for fname, sig in config.FRAMEWORK_ERROR_SIGNATURES:
        if sig in low:
            result.add(Finding(
                check="framework_error", name=f"Framework debug page exposed: {fname}",
                status="fail", severity="high",
                detail=f"Response body contains framework error signature '{sig}'. Debug pages expose stack traces and source snippets.",
                source_id="CWE-200", cwe="CWE-200", owasp="A05",
                remediation="Disable debug mode in production (e.g., DEBUG=False in Django/Flask) and use custom error pages."))
            break


def check_sensitive_files(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """Probe for exposed sensitive configuration and backup files (CWE-200)."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    path_rules = [r for r in kb_rules if r.get("type") == "sensitive_paths"]
    
    paths_to_check = []
    rule_spec = config.SENSITIVE_FILES_RULE
    if path_rules:
        r0 = path_rules[0]
        paths_to_check = r0.get("paths", config.SENSITIVE_PATHS)
        rule_spec = {
            "source_id": r0.get("source_id", "CWE-200-SENSITIVE"),
            "cwe": r0.get("cwe", "CWE-200"),
            "owasp": r0.get("owasp", "A05"),
            "severity": r0.get("severity", "high"),
            "remediation": r0.get("remediation", config.SENSITIVE_FILES_RULE["remediation"])
        }
    else:
        paths_to_check = config.SENSITIVE_PATHS

    def _probe_path(path):
        target_url = origin + path
        try:
            resp = _get(target_url, timeout=3, custom_headers=custom_headers)
            status = getattr(resp, "status", None) or getattr(resp, "code", 200)
            if status == 200:
                body = resp.read(2000).decode("utf-8", "ignore")
                if body and len(body.strip()) > 0 and "404" not in body.lower() and "not found" not in body.lower():
                    return path
        except Exception:
            pass
        return None

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(paths_to_check) or 1)) as executor:
        results = executor.map(_probe_path, paths_to_check)
        exposed = [p for p in results if p is not None]

    if exposed:
        result.add(Finding(
            check="sensitive_files", name="Exposed sensitive files / metadata",
            status="fail", severity=rule_spec["severity"],
            detail=f"Web server allows public HTTP access to sensitive paths: {', '.join(exposed)}",
            source_id=rule_spec["source_id"], cwe=rule_spec["cwe"], owasp=rule_spec["owasp"],
            remediation=rule_spec["remediation"]))
    else:
        result.add(Finding(
            check="sensitive_files", name="No sensitive files exposed",
            status="pass", severity="info",
            detail="Checked common sensitive configuration/backup paths; none exposed.",
            source_id=rule_spec["source_id"], cwe=rule_spec["cwe"], owasp=rule_spec["owasp"]))


def check_http_methods(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """Check for dangerous or enabled HTTP methods via OPTIONS request (CWE-749)."""
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    method_rules = [r for r in kb_rules if r.get("type") == "http_methods"]
    
    spec = config.HTTP_METHODS_RULE
    dangerous_list = ["TRACE", "PUT", "DELETE", "CONNECT"]
    if method_rules:
        r0 = method_rules[0]
        dangerous_list = r0.get("dangerous", dangerous_list)
        spec = {
            "source_id": r0.get("source_id", "CWE-749"),
            "cwe": r0.get("cwe", "CWE-749"),
            "owasp": r0.get("owasp", "A05"),
            "severity": r0.get("severity", "medium"),
            "remediation": r0.get("remediation", config.HTTP_METHODS_RULE["remediation"])
        }

    try:
        resp = _get(base_url, timeout=10, custom_headers=custom_headers, method="OPTIONS")
        allow = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods") or ""
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        dangerous = [m for m in methods if m in dangerous_list]
        if dangerous:
            result.add(Finding(
                check="http_methods", name="Dangerous HTTP methods enabled",
                status="fail", severity=spec["severity"],
                detail=f"Server OPTIONS header advertises enabled methods: {', '.join(methods)}. Dangerous methods found: {', '.join(dangerous)}",
                source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
                remediation=spec["remediation"]))
        elif methods:
            result.add(Finding(
                check="http_methods", name="HTTP methods posture safe",
                status="pass", severity="info",
                detail=f"Allowed methods: {', '.join(methods)} (no TRACE/PUT/DELETE advertised).",
                source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"]))
    except Exception:
        pass


def check_open_redirect(result: ScanResult, base_url: str, params=None, custom_headers: dict = None, kb_rules=None):
    """Safe open redirect probe against discovered or common redirect parameter names (CWE-601)."""
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    redir_rules = [r for r in kb_rules if r.get("type") == "open_redirect"]
    
    spec = config.OPEN_REDIRECT_RULE
    known_param_names = config.REDIRECT_PARAM_NAMES
    if redir_rules:
        r0 = redir_rules[0]
        known_param_names = r0.get("params", known_param_names)
        spec = {
            "source_id": r0.get("source_id", "CWE-601"),
            "cwe": r0.get("cwe", "CWE-601"),
            "owasp": r0.get("owasp", "A01"),
            "severity": r0.get("severity", "medium"),
            "remediation": r0.get("remediation", config.OPEN_REDIRECT_RULE["remediation"])
        }

    candidates = list(params) if params else known_param_names
    matching = [p for p in candidates if p.lower() in known_param_names]
    if not matching and params:
        matching = known_param_names[:3]

    target_payload = "https://example.com"
    for pname in matching:
        sep = "&" if "?" in base_url else "?"
        test_url = f"{base_url}{sep}{urllib.parse.quote(pname)}={urllib.parse.quote(target_payload)}"
        try:
            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            headers = {"User-Agent": "websec-auditor/0.1"}
            if custom_headers:
                headers.update(custom_headers)
            opener = urllib.request.build_opener(NoRedir)
            req = urllib.request.Request(test_url, headers=headers)
            try:
                resp = opener.open(req, timeout=10)
                loc = resp.headers.get("Location", "")
            except urllib.error.HTTPError as e:
                loc = e.headers.get("Location", "")
            
            if loc and ("example.com" in loc or loc.startswith("http://example.com") or loc.startswith("https://example.com")):
                result.add(Finding(
                    check="open_redirect", name="Potential Open Redirect detected",
                    status="fail", severity=spec["severity"],
                    detail=f"Parameter '{pname}' redirected to unvalidated external origin (Location: {loc}).",
                    source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
                    remediation=spec["remediation"]))
                return
        except Exception:
            pass


def check_reflection(result: ScanResult, base_url: str, params=None, custom_headers: dict = None):
    """Two SAFE, non-exploitative probes:
      1) a benign marker probe -> detect unencoded reflection (XSS surface).
      2) a benign single-quote probe -> detect verbose SQL errors in normal
         input handling (injection surface). Neither performs an actual attack.
    The reflection marker is sent through each candidate parameter (default
    'q', or the params the crawler discovered) so every input surface is
    exercised, not just a guessed name.
    """
    import html as _html
    marker = config.SAFE_PROBE_MARKER
    parsed = urllib.parse.urlparse(base_url)
    candidates = list(params) if params else ["q"]

    def _with_param(url: str, pname: str, value: str) -> str:
        """Append ?name=value to a URL WITHOUT touching the existing path."""
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{urllib.parse.quote(pname)}={value}"

    # --- probe 1: reflection marker on each candidate parameter ---
    reflected = False
    probe_bodies = []
    had_body = False
    had_error = False
    for pname in candidates:
        test_url = _with_param(base_url, pname, urllib.parse.quote(marker))
        body = ""
        try:
            resp = _get(test_url, custom_headers=custom_headers)
            body = resp.read(200000).decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            had_error = True
            try:
                body = e.read(200000).decode("utf-8", "ignore")
            except Exception:
                body = ""
        except Exception:
            had_error = True
            body = ""
        if not body:
            continue
        had_body = True
        probe_bodies.append(body)
        marker_escaped = _html.escape(marker)
        if marker in body and marker_escaped not in body:
            result.add(Finding(
                check="xss_reflection", name="Reflected input detected",
                status="fail", severity="medium",
                detail=(f"A benign probe value was echoed back UNENCODED in the "
                        f"response body (parameter '{pname}'). An attacker's script "
                        f"would also be echoed unencoded -> XSS surface."),
                source_id="CWE-79", cwe="CWE-79", owasp="A03",
                remediation=("Contextual-output-encode all reflected input and "
                             "deploy a Content-Security-Policy.")))
            reflected = True
            break

    if reflected:
        for b in probe_bodies:
            _scan_body_for_sql_error(result, b)
    elif had_body:
        body = probe_bodies[0]
        if _html.escape(marker) in body:
            result.add(Finding(
                check="xss_reflection", name="Reflected input is HTML-escaped",
                status="pass", severity="info",
                detail="Probe marker was reflected HTML-escaped (safe).",
                source_id="CWE-79", cwe="CWE-79", owasp="A03"))
        else:
            result.add(Finding(
                check="xss_reflection", name="No reflection",
                status="pass", severity="info",
                detail="Probe marker was not reflected.",
                source_id="CWE-79", cwe="CWE-79", owasp="A03"))
        _scan_body_for_sql_error(result, body)
    elif had_error:
        result.add(Finding(
            check="xss_reflection", name="Reflection probe error", status="warn",
            severity="low", detail="Could not run the reflection probe against "
                                   "any candidate parameter.",
            source_id="CWE-79", cwe="CWE-79", owasp="A03"))

    # --- probe 2: benign single-quote (looks for verbose SQL errors only) ---
    qprobe = _with_param(base_url, "q", "%27")
    try:
        r2 = _get(qprobe, custom_headers=custom_headers)
        b2 = r2.read(200000).decode("utf-8", "ignore")
        _scan_body_for_sql_error(result, b2)
    except urllib.error.HTTPError as e:
        try:
            b2 = e.read(200000).decode("utf-8", "ignore")
            _scan_body_for_sql_error(result, b2)
        except Exception:
            pass
    except Exception:
        pass


def scan_one(result: ScanResult, url: str, timeout: int = 15, params=None, custom_headers: dict = None, kb_rules=None):
    """Run every per-page check against one URL. The caller owns the ScanResult.
    TLS is host-level and checked separately by scan(). Returns an info dict
    {ok, status, headers, body, params} for the caller (e.g. the crawler)."""
    parsed = urllib.parse.urlparse(url)
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    try:
        resp = _get(url, timeout, custom_headers=custom_headers)
    except urllib.error.HTTPError as e:
        resp = e  # even error responses carry headers worth checking
    except Exception as e:
        result.add(Finding(
            check="connectivity", name="Target unreachable", status="fail",
            severity="high", detail=f"Could not reach {url}: {e}",
            source_id="OWASP-A05-MISCONFIG"))
        return {"ok": False, "error": str(e)}
    try:
        body = resp.read(200000).decode("utf-8", "ignore")
    except Exception:
        body = ""
    headers = {k.lower(): v for k, v in resp.headers.items()}
    check_scheme(result, parsed.scheme, parsed.hostname)
    check_headers(result, headers, kb_rules=kb_rules)
    check_extra_headers(result, headers)
    check_cookies(result, resp, kb_rules=kb_rules)
    check_cors(result, headers)
    check_csp_quality(result, headers)
    check_hsts_quality(result, headers)
    check_info_disclosure(result, headers)
    check_cache(result, resp)
    check_directory_listing(result, body)
    check_framework_errors(result, body)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        f1 = executor.submit(check_reflection, result, url, params, custom_headers)
        f2 = executor.submit(check_sensitive_files, result, url, custom_headers, kb_rules)
        f3 = executor.submit(check_http_methods, result, url, custom_headers, kb_rules)
        f4 = executor.submit(check_open_redirect, result, url, params, custom_headers, kb_rules)
        concurrent.futures.wait([f1, f2, f3, f4], timeout=5)
    return {
        "ok": True,
        "status": getattr(resp, "status", None) or getattr(resp, "code", 0),
        "headers": headers, "body": body, "params": params,
    }


def scan(target: str, custom_headers: dict = None, kb_rules=None) -> ScanResult:
    """Scan a target URL. Returns a ScanResult with grounded findings."""
    target = target.strip()
    if not target.startswith("http"):
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    result = ScanResult(target=target, scheme=parsed.scheme)
    info = scan_one(result, target, custom_headers=custom_headers, kb_rules=kb_rules)
    if parsed.scheme == "https" and info.get("ok"):
        check_tls(result, parsed.hostname, 443)
    return result


if __name__ == "__main__":
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "https://self-signed.badssl.com"
    r = scan(tgt)
    print(json.dumps(r.to_dict(), indent=2, default=str))
