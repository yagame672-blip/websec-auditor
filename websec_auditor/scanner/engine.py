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
from websec_auditor import netsafe


# Hard per-scan budget: set at the start of scan_one() and consulted by _get(),
# so a slow / bot-protected target can never push one scan past the Vercel
# serverless maxDuration (60s). The crawler calls scan_one() sequentially, so
# a single module-level deadline is safe.
_BUDGET_DEADLINE = None


def _budget_remaining():
    if _BUDGET_DEADLINE is None:
        return None
    import time
    return _BUDGET_DEADLINE - time.monotonic()


def _budget_exhausted():
    remaining = _budget_remaining()
    return remaining is not None and remaining <= 0


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
    confidence: str = ""  # "high" | "medium" | "low" | "" (evidence strength)

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
    if timeout is None:
        timeout = 10
    remaining = _budget_remaining()
    if remaining is not None and remaining <= 0:
        raise TimeoutError("scan budget exhausted; target too slow or blocking probes")
    if remaining is not None:
        timeout = min(timeout, max(remaining, 1))
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 websec-auditor/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if custom_headers:
        headers.update(custom_headers)
    req = urllib.request.Request(url, headers=headers, method=method)
    # netsafe validates the target (anti-SSRF) and re-validates redirects;
    # certificates are verified first, relaxing only for genuinely broken certs.
    return netsafe.open_verified_first(req, timeout=timeout)


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
                source_id=rule["source_id"], cwe=rule["cwe"], owasp=rule["owasp"],
                confidence="high"))
        else:
            result.add(Finding(
                check="security_headers", name=f"Missing header: {hname}",
                status="fail", severity=rule.get("severity", "medium"),
                detail=f"Response does not include {hname}.",
                source_id=rule["source_id"], cwe=rule["cwe"], owasp=rule["owasp"],
                remediation=rule.get("remediation", ""), confidence="high"))


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
                source_id=rule["source_id"], cwe=rule["cwe"], owasp=rule["owasp"],
                confidence="high"))
        else:
            result.add(Finding(
                check="cookies", name=f"Missing cookie flag: {flag}",
                status="fail", severity=rule.get("severity", "high"),
                detail=f"A session cookie is missing the {flag} attribute.",
                source_id=rule["source_id"], cwe=rule["cwe"], owasp=rule["owasp"],
                remediation=rule.get("remediation", ""), confidence="high"))


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
    """CSP present but weakened by unsafe-eval/wildcards (CWE-79),
    or no clickjacking control present (CWE-1021)."""
    csp = headers.get("content-security-policy")
    if not csp:
        return
    problems = []
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        d = toks[0].lower()
        if d == "style-src-attr":
            continue
        for v in toks[1:]:
            if v == "'unsafe-inline'":
                problems.append((d, "'unsafe-inline'"))
            elif v == "'unsafe-eval'":
                problems.append((d, "'unsafe-eval'"))
            elif v == "'*'" and d in ("default-src", "script-src", "style-src",
                                      "connect-src", "object-src", "frame-src",
                                      "worker-src", "media-src", "child-src"):
                problems.append((d, "wildcard '*'"))
    problems = sorted(set(problems))
    if problems:
        bad_str = "; ".join(f"{d} permits {t}" for d, t in problems)
        tokens = ", ".join(sorted(set(t for _, t in problems)))
        dirs = ", ".join(sorted(set(d for d, _ in problems)))
        rem = f"Remove {tokens} from {dirs}."
        if "frame-ancestors" not in csp.lower() and "x-frame-options" not in headers:
            rem += " Add frame-ancestors 'none' (or X-Frame-Options: DENY)."
        result.add(Finding(
            check="csp_quality", name="Weak CSP directives", status="fail",
            severity="medium",
            detail=f"CSP has weakening directives: {bad_str}.",
            source_id="OWASP-CSP", cwe="CWE-79", owasp="A03",
            remediation=rem, confidence="high"))
        result.raw.setdefault("evidence", []).append(
            {"check": "csp_quality", "header": "content-security-policy",
             "problems": problems, "value": csp[:200]})
    else:
        result.add(Finding(
            check="csp_quality", name="CSP directives look safe", status="pass",
            severity="info", detail="CSP enforces safe script/style execution policy.",
            source_id="OWASP-CSP", cwe="CWE-79", owasp="A03"))
    if "frame-ancestors" not in csp.lower() and "x-frame-options" not in headers:
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
            val = headers[hname][:120]
            has_version = any(char.isdigit() for char in val)
            is_cloud = any(c in val.lower() for c in ("vercel", "cloudflare", "github"))
            if is_cloud and not has_version:
                result.add(Finding(
                    check="info_disclosure", name=f"Technology disclosure: {hname}",
                    status="pass", severity="info",
                    detail=f"{hname}: {val} (Standard cloud platform header).",
                    source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"]))
            else:
                result.add(Finding(
                    check="info_disclosure", name=f"Technology disclosure: {hname}",
                    status="warn", severity=spec["severity"],
                    detail=f"{hname}: {val} (advertises server software/version).",
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
                remediation=spec["remediation"], confidence="high"))
        else:
            result.add(Finding(
                check="extra_headers", name=f"Header present: {hname}",
                status="pass", severity="info",
                detail=f"{hname}: {headers[hname][:80]}",
                source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
                confidence="high"))
    ct = headers.get("content-type")
    if ct and "text/html" in ct.lower() and "charset" not in ct.lower():
        result.add(Finding(
            check="extra_headers", name="Content-Type missing charset", status="warn",
            severity="low", detail="HTML response Content-Type lacks a charset.",
            source_id="OWASP-SEC-HEADERS", cwe="CWE-16", owasp="A05",
            remediation="Include charset=utf-8 in the Content-Type header."))
    rp = headers.get("referrer-policy", "")
    if rp and "unsafe-url" in rp.lower():
        result.add(Finding(
            check="extra_headers", name="Referrer-Policy leaks full URLs", status="warn",
            severity="low",
            detail="Referrer-Policy is set to unsafe-url, which leaks the full query "
                   "string to every cross-origin destination.",
            source_id="OWASP-SEC-HEADERS", cwe="CWE-200", owasp="A05",
            remediation="Use Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
            confidence="high"))


def check_cache(result: ScanResult, resp):
    """Session responses must not be cacheable (CWE-524)."""
    set_cookie = resp.headers.get_all("Set-Cookie") or []
    if not set_cookie:
        return
    cc = (resp.headers.get("Cache-Control") or "").lower()
    if "no-store" not in cc:
        spec = config.CACHE_RULE
        if cc and "no-cache" in cc:
            status, sev = "warn", "low"
            detail = ("Response sets a cookie but Cache-Control is only no-cache "
                      "(browser caches are allowed to store it); prefer no-store.")
        else:
            status, sev = "fail", spec["severity"]
            detail = "Response sets a cookie but Cache-Control does not include no-store."
        result.add(Finding(
            check="cache", name="Session response is cacheable", status=status,
            severity=sev,
            detail=detail,
            source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
            remediation=spec["remediation"], confidence="high"))


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
    except ssl.SSLError as e:
        result.add(Finding(
            check="tls", name="TLS handshake", status="fail", severity="high",
            detail=f"TLS handshake failed: {e}", source_id="OWASP-TLS",
            cwe="CWE-319", owasp="A02", remediation="Fix TLS configuration."))
        return
    except Exception as e:
        result.add(Finding(
            check="tls", name="TLS handshake", status="warn", severity="medium",
            detail=f"Could not test TLS: {e}", source_id="OWASP-TLS"))
        return

    # Certificate trust + expiry need a VERIFYING context: with CERT_NONE,
    # getpeercert() returns {} and these checks can never run (CWE-295).
    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with vctx.wrap_socket(sock, server_hostname=host) as ssock:
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
                    remediation="Renew the TLS certificate immediately.", confidence="high"))
            elif days < 30:
                result.add(Finding(
                    check="tls_cert", name="TLS certificate expiring soon", status="warn",
                    severity="medium", detail=f"Certificate expires in {days} days.",
                    source_id="CWE-295", cwe="CWE-295", owasp="A02",
                    remediation="Renew before expiry; automate certificate renewal.",
                    confidence="high"))
    except ssl.SSLCertVerificationError as e:
        result.add(Finding(
            check="tls_cert", name="TLS certificate not trusted", status="fail",
            severity="high",
            detail=(f"Certificate verification failed against system trust store: "
                    f"{e}. The chain may be broken, self-signed, or for the wrong hostname."),
            source_id="CWE-295", cwe="CWE-295", owasp="A02",
            remediation="Serve a complete, valid certificate chain from a trusted CA.",
            confidence="high"))
    except Exception:
        pass


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
        if _budget_exhausted():
            return
        target_url = origin + path
        try:
            resp = _get(target_url, timeout=3, custom_headers=custom_headers)
            status = getattr(resp, "status", None) or getattr(resp, "code", 200)
            if status == 200:
                body = resp.read(2000).decode("utf-8", "ignore")
                low_body = body.lower().strip()
                if body and len(low_body) > 0 and "404" not in low_body and "not found" not in low_body:
                    # Ignore HTML framework fallback pages (SPA routing fallback)
                    if not low_body.startswith("<!doctype") and "<html" not in low_body and "<body" not in low_body:
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
            remediation=rule_spec["remediation"], confidence="high"))
        result.raw.setdefault("evidence", []).append(
            {"check": "sensitive_files", "paths": exposed})
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
        if _budget_exhausted():
            return
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
                t_o = 10
                remaining = _budget_remaining()
                if remaining is not None:
                    t_o = min(t_o, max(remaining, 1))
                resp = opener.open(req, timeout=t_o)
                loc = resp.headers.get("Location", "")
            except urllib.error.HTTPError as e:
                loc = e.headers.get("Location", "")
            
            if loc and ("example.com" in loc or loc.startswith("http://example.com") or loc.startswith("https://example.com")):
                result.add(Finding(
                    check="open_redirect", name="Potential Open Redirect detected",
                    status="fail", severity=spec["severity"],
                    detail=f"Parameter '{pname}' redirected to unvalidated external origin (Location: {loc}).",
                    source_id=spec["source_id"], cwe=spec["cwe"], owasp=spec["owasp"],
                    remediation=spec["remediation"], confidence="high"))
                result.raw.setdefault("evidence", []).append(
                    {"check": "open_redirect", "parameter": pname,
                     "location": loc, "test_url": test_url})
                return
        except Exception:
            pass


def _append_param(url: str, pname: str, value: str) -> str:
    """Append ?name=value to a URL WITHOUT touching the existing path."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{urllib.parse.quote(pname)}={urllib.parse.quote(value)}"


def _fetch_body(url: str, custom_headers: dict = None, timeout: int = 12) -> str:
    try:
        resp = _get(url, timeout, custom_headers=custom_headers)
        return resp.read(200000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.read(200000).decode("utf-8", "ignore")
        except Exception:
            return ""
    except Exception:
        return ""


def check_sqli(result: ScanResult, base_url: str, params=None, custom_headers: dict = None, kb_rules=None):
    """KB-driven SQL injection surface probe (CWE-89 / WSTG-INPV-05).

    Sends ONLY benign, non-destructive markers (a bare single quote and a
    boolean predicate) to each candidate parameter and looks for SQL error
    signatures in the response. No data-changing statement is ever sent.
    """
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    sqli_rules = [r for r in kb_rules if r.get("type") == "sqli"]
    if not sqli_rules:
        return
    rule = sqli_rules[0]
    candidates = list(params) if params else config.SQLI_PROBE_PARAMS
    markers = rule.get("markers") or config.SQLI_MARKERS
    error_patterns = rule.get("error_patterns") or config.SQL_ERROR_SIGNATURES

    sent = 0
    any_body = False
    for pname in candidates:
        for marker in markers:
            if sent >= config.SQLI_MAX_PROBES:
                return
            if _budget_exhausted():
                return
            sent += 1
            body = _fetch_body(_append_param(base_url, pname, marker), custom_headers)
            if not body:
                continue
            any_body = True
            low = body.lower()
            for pat in error_patterns:
                try:
                    m = re.search(pat, low, re.I)
                    if m:
                        snippet = body[max(0, m.start() - 40):m.end() + 40].strip()
                        result.add(Finding(
                            check="sqli", name="SQL error signature exposed",
                            status="fail", severity=rule.get("severity", "high"),
                            detail=(f"A benign SQL probe on parameter '{pname}' produced "
                                    f"a database error signature matching '{pat}'. Verbose "
                                    f"errors leak schema and confirm an injection surface "
                                    f"(CWE-89/CWE-200)."),
                            source_id=rule.get("source_id", "WSTG-INPV-05-SQLI"),
                            cwe=rule.get("cwe", "CWE-89"), owasp=rule.get("owasp", "A03"),
                            remediation=rule.get("remediation", ""),
                            confidence="high"))
                        result.raw.setdefault("evidence", []).append(
                            {"check": "sqli", "parameter": pname, "pattern": pat,
                             "snippet": snippet})
                        return
                except re.error:
                    continue

    if any_body:
        result.add(Finding(
            check="sqli", name="No SQL error signatures exposed",
            status="pass", severity="info",
            detail=("Benign SQL probe markers on candidate parameters produced no "
                    "database error signatures."),
            source_id=rule.get("source_id", "WSTG-INPV-05-SQLI"),
            cwe=rule.get("cwe", "CWE-89"), owasp=rule.get("owasp", "A03")))
    else:
        result.add(Finding(
            check="sqli", name="SQL probe could not run", status="warn",
            severity="low", detail="Candidate parameters returned no bodies to inspect.",
            source_id=rule.get("source_id", "WSTG-INPV-05-SQLI"),
            cwe=rule.get("cwe", "CWE-89"), owasp=rule.get("owasp", "A03")))


def check_xss(result: ScanResult, base_url: str, params=None, custom_headers: dict = None, kb_rules=None):
    """KB-driven reflected-XSS surface probe (CWE-79 / WSTG-INPV-01).

    Sends benign INERT markers (a harmless custom tag, and a tag-breakout
    variant). If the raw marker is echoed back unencoded, an attacker's script
    would be echoed too -> confirmed XSS surface. Nothing executable is sent.
    """
    import html as _html
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    xss_rules = [r for r in kb_rules if r.get("type") == "xss"]
    if not xss_rules:
        return
    rule = xss_rules[0]
    candidates = list(params) if params else config.XSS_PROBE_PARAMS
    markers = rule.get("markers") or config.XSS_MARKERS

    sent = 0
    any_body = False
    for pname in candidates:
        for marker in markers:
            if sent >= config.XSS_MAX_PROBES:
                break
            if _budget_exhausted():
                return
            sent += 1
            body = _fetch_body(_append_param(base_url, pname, marker), custom_headers)
            if not body:
                continue
            any_body = True
            if marker in body:
                idx = body.find(marker)
                snippet = body[max(0, idx - 40):idx + len(marker) + 40].strip()
                result.add(Finding(
                    check="xss", name="Reflected XSS surface confirmed",
                    status="fail", severity=rule.get("severity", "medium"),
                    detail=(f"A benign inert XSS marker was echoed back UNENCODED on "
                            f"parameter '{pname}'. An attacker's script would be echoed "
                            f"identically -> reflected XSS surface (CWE-79)."),
                    source_id=rule.get("source_id", "WSTG-INPV-01-XSS"),
                    cwe=rule.get("cwe", "CWE-79"), owasp=rule.get("owasp", "A03"),
                    remediation=rule.get("remediation", ""),
                    confidence="high"))
                result.raw.setdefault("evidence", []).append(
                    {"check": "xss", "parameter": pname, "marker": marker,
                     "snippet": snippet})
                return
        if sent >= config.XSS_MAX_PROBES:
            break

    if any_body:
        result.add(Finding(
            check="xss", name="No unencoded reflection detected",
            status="pass", severity="info",
            detail=("Inert XSS markers on candidate parameters were not echoed "
                    "back unencoded."),
            source_id=rule.get("source_id", "WSTG-INPV-01-XSS"),
            cwe=rule.get("cwe", "CWE-79"), owasp=rule.get("owasp", "A03")))
    else:
        result.add(Finding(
            check="xss", name="XSS probe could not run", status="warn",
            severity="low", detail="Candidate parameters returned no bodies to inspect.",
            source_id=rule.get("source_id", "WSTG-INPV-01-XSS"),
            cwe=rule.get("cwe", "CWE-79"), owasp=rule.get("owasp", "A03")))


def check_ddos_mitigation(result: ScanResult, headers: dict, kb_rules=None):
    """KB-driven passive DDoS / brute-force mitigation posture (ATT&CK T1498 /
    OWASP DoS Cheat Sheet). Looks for WAF/CDN and rate-limit header evidence."""
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    ddos_rules = [r for r in kb_rules if r.get("type") == "ddos_mitigation"]
    if not ddos_rules:
        return
    rule = ddos_rules[0]
    waf = rule.get("waf_headers") or config.DDOS_WAF_HEADERS
    rl = rule.get("ratelimit_headers") or config.DDOS_RATELIMIT_HEADERS
    combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    waf_hits = [h for h in waf if h in combined]
    rl_hits = [h for h in rl if h in combined]
    evidence = waf_hits + rl_hits

    if evidence:
        result.add(Finding(
            check="ddos_mitigation", name="DDoS / rate-limit mitigation detected",
            status="pass", severity="info",
            detail=("Response shows mitigation evidence: " + ", ".join(evidence[:3]) +
                    ". A WAF/CDN or rate limiter appears to front the site."),
            source_id=rule.get("source_id", "ATTACK-T1498-DOS"),
            cwe=rule.get("cwe", "CWE-400"), owasp=rule.get("owasp", "A05")))
    else:
        result.add(Finding(
            check="ddos_mitigation", name="No DDoS / rate-limit mitigation evidence",
            status="warn", severity=rule.get("severity", "low"),
            detail=("No WAF/CDN or rate-limiting header evidence observed on this "
                    "response; the site may be more exposed to application-layer "
                    "floods and brute force."),
            source_id=rule.get("source_id", "ATTACK-T1498-DOS"),
            cwe=rule.get("cwe", "CWE-400"), owasp=rule.get("owasp", "A05"),
            remediation=rule.get("remediation", "")))


def _append_param_raw(url: str, pname: str, value: str) -> str:
    """Append ?name=value to a URL WITHOUT touching the existing path and
    WITHOUT re-encoding the value (payloads already carry their own encoding)."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{urllib.parse.quote(pname)}={value}"


def check_blind_sqli(result: ScanResult, base_url: str, params=None, custom_headers: dict = None, kb_rules=None):
    """KB-driven blind SQLi surface probe (CWE-89 / WSTG-INPV-05).

    Time-based: a benign sleep payload that, if it reaches a query planner,
    delays the response measurably. Boolean-based: a true vs false predicate
    that changes the response when the input is concatenated into SQL. All
    probes are read-only; nothing modifies data.
    """
    import time as _time
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    blind_rules = [r for r in kb_rules if r.get("type") == "blind_sqli"]
    if not blind_rules:
        return
    rule = blind_rules[0]
    candidates = list(params) if params else config.SQLI_PROBE_PARAMS
    timing = rule.get("timing_payloads") or config.BLIND_SQLI_TIMING_PAYLOADS
    bool_true = rule.get("bool_true") or config.BLIND_SQLI_BOOL_TRUE
    bool_false = rule.get("bool_false") or config.BLIND_SQLI_BOOL_FALSE
    delay = float(rule.get("delay") or 2.0)
    min_ratio = 3.0

    probed = 0
    any_body = False
    for pname in candidates[:2]:
        if _budget_exhausted():
            return
        baseline_url = _append_param(base_url, pname, "1")
        t0 = _time.perf_counter()
        base_body = _fetch_body(baseline_url, custom_headers)
        baseline = _time.perf_counter() - t0
        if not base_body:
            continue
        any_body = True

        # --- time-based ---
        for payload in timing[:2]:
            if probed >= config.BLIND_SQLI_MAX_PROBES:
                return
            if _budget_exhausted():
                return
            probed += 1
            t0 = _time.perf_counter()
            body = _fetch_body(_append_param(base_url, pname, payload), custom_headers)
            dt = _time.perf_counter() - t0
            if body and dt >= max(delay * 0.9, baseline * min_ratio):
                result.add(Finding(
                    check="blind_sqli", name="Blind SQLi (time-based) suspected",
                    status="fail", severity=rule.get("severity", "high"),
                    detail=(f"Parameter '{pname}' took {dt:.2f}s to answer a benign "
                            f"sleep payload vs a {baseline:.2f}s baseline ({payload!r}). "
                            f"This pattern indicates a time-based injection surface (CWE-89)."),
                    source_id=rule.get("source_id", "WSTG-INPV-05-SQLI"),
                    cwe=rule.get("cwe", "CWE-89"), owasp=rule.get("owasp", "A03"),
                    remediation=rule.get("remediation", ""),
                    confidence="medium"))
                return
        if probed >= config.BLIND_SQLI_MAX_PROBES:
            return

        # --- boolean-based ---
        if probed + 2 > config.BLIND_SQLI_MAX_PROBES:
            return
        probed += 2
        b_true = _fetch_body(_append_param(base_url, pname, bool_true), custom_headers)
        b_false = _fetch_body(_append_param(base_url, pname, bool_false), custom_headers)
        if b_true and b_false and b_true != b_false:
            result.add(Finding(
                check="blind_sqli", name="Blind SQLi (boolean-based) suspected",
                status="fail", severity=rule.get("severity", "high"),
                detail=(f"Parameter '{pname}' returned different bodies for a true "
                        f"predicate ({bool_true!r}) vs a false predicate ({bool_false!r}). "
                        f"This pattern indicates the predicate reaches SQL (CWE-89)."),
                source_id=rule.get("source_id", "WSTG-INPV-05-SQLI"),
                cwe=rule.get("cwe", "CWE-89"), owasp=rule.get("owasp", "A03"),
                remediation=rule.get("remediation", ""),
                confidence="high"))
            return

    if any_body:
        result.add(Finding(
            check="blind_sqli", name="No blind SQLi behavior detected",
            status="pass", severity="info",
            detail="Time- and boolean-based probes showed no delayed or divergent "
                   "response on candidate parameters.",
            source_id=rule.get("source_id", "WSTG-INPV-05-SQLI"),
            cwe=rule.get("cwe", "CWE-89"), owasp=rule.get("owasp", "A03")))
    else:
        result.add(Finding(
            check="blind_sqli", name="Blind SQLi probe could not run", status="warn",
            severity="low", detail="Candidate parameters returned no bodies to compare.",
            source_id=rule.get("source_id", "WSTG-INPV-05-SQLI"),
            cwe=rule.get("cwe", "CWE-89"), owasp=rule.get("owasp", "A03")))


def check_path_traversal(result: ScanResult, base_url: str, params=None, custom_headers: dict = None, kb_rules=None):
    """KB-driven path traversal / LFI surface probe (CWE-22 / WSTG-INPV-07).

    Sends benign '../' traversal payloads (plain and encoded variants) to
    file-style parameters and looks for well-known file-content signatures.
    Read-only: it only reads whatever the parameter would serve anyway.
    """
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    trav_rules = [r for r in kb_rules if r.get("type") == "path_traversal"]
    if not trav_rules:
        return
    rule = trav_rules[0]
    candidates = list(params) if params else config.PATH_TRAVERSAL_PARAMS
    payloads = rule.get("payloads") or config.PATH_TRAVERSAL_PAYLOADS
    signatures = rule.get("signatures") or config.PATH_TRAVERSAL_SIGNATURES

    probed = 0
    any_body = False
    for pname in candidates[:3]:
        for payload in payloads:
            if probed >= config.PATH_TRAVERSAL_MAX_PROBES:
                break
            if _budget_exhausted():
                return
            probed += 1
            body = _fetch_body(_append_param_raw(base_url, pname, payload), custom_headers)
            if not body:
                continue
            any_body = True
            low = body.lower()
            for sig in signatures:
                if sig in low:
                    idx = low.find(sig)
                    snippet = body[max(0, idx - 30):idx + len(sig) + 30].strip()
                    result.add(Finding(
                        check="path_traversal", name="Path traversal / LFI surface confirmed",
                        status="fail", severity=rule.get("severity", "high"),
                        detail=(f"Parameter '{pname}' served file content matching "
                                f"'{sig}' for a traversal payload ({payload!r}). "
                                f"The parameter reaches the filesystem (CWE-22)."),
                        source_id=rule.get("source_id", "WSTG-INPV-07-PATHTRAV"),
                        cwe=rule.get("cwe", "CWE-22"), owasp=rule.get("owasp", "A03"),
                        remediation=rule.get("remediation", ""),
                        confidence="high"))
                    result.raw.setdefault("evidence", []).append(
                        {"check": "path_traversal", "parameter": pname, "signature": sig,
                         "payload": payload, "snippet": snippet})
                    return
        if probed >= config.PATH_TRAVERSAL_MAX_PROBES:
            break

    if any_body:
        result.add(Finding(
            check="path_traversal", name="No path traversal signatures served",
            status="pass", severity="info",
            detail="Traversal payloads on candidate parameters returned no known "
                   "file-content signatures.",
            source_id=rule.get("source_id", "WSTG-INPV-07-PATHTRAV"),
            cwe=rule.get("cwe", "CWE-22"), owasp=rule.get("owasp", "A03")))
    else:
        result.add(Finding(
            check="path_traversal", name="Path traversal probe could not run",
            status="warn", severity="low",
            detail="Candidate parameters returned no bodies to inspect.",
            source_id=rule.get("source_id", "WSTG-INPV-07-PATHTRAV"),
            cwe=rule.get("cwe", "CWE-22"), owasp=rule.get("owasp", "A03")))


def check_csrf_token(result: ScanResult, body: str, base_url: str, kb_rules=None):
    """KB-driven CSRF token check (CWE-352 / WSTG-SESS-05).

    Parses the fetched page for state-changing forms (POST/PUT/DELETE/PATCH)
    and flags any that carry no anti-CSRF token input. Read-only HTML parsing
    of the page the crawler already fetched.
    """
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    csrf_rules = [r for r in kb_rules if r.get("type") == "csrf_token"]
    if not csrf_rules:
        return
    rule = csrf_rules[0]
    if not body:
        result.add(Finding(
            check="csrf_token", name="CSRF token check could not run", status="warn",
            severity="low", detail="No page body to analyze for forms.",
            source_id=rule.get("source_id", "WSTG-SESS-05-CSRF"),
            cwe=rule.get("cwe", "CWE-352"), owasp=rule.get("owasp", "A01")))
        return

    token_patterns = rule.get("token_names") or config.CSRF_TOKEN_NAME_PATTERNS
    forms = re.findall(r"<form\b[^>]*>.*?</form>", body, re.I | re.S)
    if not forms:
        result.add(Finding(
            check="csrf_token", name="No forms to evaluate", status="pass",
            severity="info",
            detail="The page contains no HTML forms, so no CSRF token surface.",
            source_id=rule.get("source_id", "WSTG-SESS-05-CSRF"),
            cwe=rule.get("cwe", "CWE-352"), owasp=rule.get("owasp", "A01")))
        return

    risky = []
    for form in forms:
        method = re.search(r'method=["\']([a-z]+)["\']', form, re.I)
        verb = method.group(1).lower() if method else "get"
        if verb not in config.CSRF_METHODS:
            continue
        inputs = re.findall(r"<input[^>]*>", form, re.I)
        has_token = any(
            re.search(pat, inp, re.I) for inp in inputs for pat in token_patterns
        )
        if not has_token:
            action = re.search(r'action=["\']([^"\']*)', form, re.I)
            risky.append(action.group(1) if action else "(no action attribute)")

    if risky:
        result.add(Finding(
            check="csrf_token", name="State-changing form(s) without CSRF token",
            status="fail", severity=rule.get("severity", "high"),
            detail=("POST/PUT/DELETE form(s) carry no anti-CSRF token: " +
                    ", ".join(risky[:4]) + ". These can be replayed cross-site on a "
                    "victim's session (CWE-352)."),
            source_id=rule.get("source_id", "WSTG-SESS-05-CSRF"),
            cwe=rule.get("cwe", "CWE-352"), owasp=rule.get("owasp", "A01"),
            remediation=rule.get("remediation", ""),
            confidence="high"))
    else:
        result.add(Finding(
            check="csrf_token", name="State-changing forms carry CSRF tokens",
            status="pass", severity="info",
            detail="Every state-changing form on the page includes an anti-CSRF token.",
            source_id=rule.get("source_id", "WSTG-SESS-05-CSRF"),
            cwe=rule.get("cwe", "CWE-352"), owasp=rule.get("owasp", "A01")))


def check_rate_limiting(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """KB-driven rate-limit backoff test (CWE-307 / OWASP DoS Cheat Sheet).

    Sends a short, low-intensity burst of requests and checks whether the
    target pushes back (429 / 503 / Retry-After). Read-only and bounded.
    """
    import time as _time
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    rl_rules = [r for r in kb_rules if r.get("type") == "rate_limiting"]
    if not rl_rules:
        return
    rule = rl_rules[0]
    count = int(rule.get("probe_count") or config.RATE_LIMIT_PROBE_COUNT)
    sleep_s = float(rule.get("window_sleep") or config.RATE_LIMIT_WINDOW_SLEEP)
    if config.SCAN_BUDGET_SEC <= 15:
        count = min(count, 3)
        sleep_s = min(sleep_s, 0.05)

    limited = False
    codes = []
    rl_headers_seen = {}
    for _ in range(count):
        if _budget_exhausted():
            break
        try:
            resp = _get(base_url, 3 if config.SCAN_BUDGET_SEC <= 15 else 8, custom_headers=custom_headers)
            codes.append(resp.getcode())
            hdrs = resp.headers
        except urllib.error.HTTPError as e:
            codes.append(e.code)
            hdrs = e.headers
        except Exception:
            codes.append(0)
            hdrs = None
        if hdrs:
            for k, v in hdrs.items():
                kl = k.lower()
                if kl in config.DDOS_RATELIMIT_HEADERS or kl.startswith("ratelimit-"):
                    rl_headers_seen.setdefault(kl, v)
        if codes[-1] in (429, 503):
            limited = True
            break
        _time.sleep(sleep_s)

    if limited:
        result.add(Finding(
            check="rate_limiting", name="Rate limiting enforced",
            status="pass", severity="info",
            detail=(f"The target pushed back with HTTP {codes[-1]} after "
                    f"{len(codes)} rapid requests; rate limiting is active."),
            source_id=rule.get("source_id", "OWASP-RATELIMIT-DEEP"),
            cwe=rule.get("cwe", "CWE-307"), owasp=rule.get("owasp", "A07")))
    elif rl_headers_seen:
        result.add(Finding(
            check="rate_limiting", name="Rate limiting advertised via headers",
            status="pass", severity="info",
            detail=(f"No 429/503 backoff in {len(codes)} rapid requests, but the "
                    f"target advertises rate limiting via "
                    f"{', '.join(f'{k}: {v}' for k, v in sorted(rl_headers_seen.items()))}. "
                    f"Per OWASP, RateLimit-* headers are the observable signal that "
                    f"such protection is active."),
            source_id="OWASP-RATELIMIT-BRUTEFORCE",
            cwe=rule.get("cwe", "CWE-307"), owasp=rule.get("owasp", "A07")))
    else:
        result.add(Finding(
            check="rate_limiting", name="No rate-limit backoff observed",
            status="warn", severity=rule.get("severity", "medium"),
            detail=(f"{count} rapid requests all answered normally (codes "
                    f"{sorted(set(c for c in codes if c))}); no 429/503 backoff. "
                    f"Login/API endpoints may be open to brute force (CWE-307)."),
            source_id=rule.get("source_id", "OWASP-RATELIMIT-DEEP"),
            cwe=rule.get("cwe", "CWE-307"), owasp=rule.get("owasp", "A07"),
            remediation=rule.get("remediation", "")))


def check_stateful_api(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """Stateful API & Parameter Validation Auditor (CWE-285, CWE-639, CWE-200, OWASP API Top 10 BOLA/BHA).
    Audits session state transitions and parameter validation robustness:
    1. Unauthenticated / Stripped Session State test (Missing Auth Header / Cookie).
    2. Boundary / Type Malformation parameter audit (Non-numeric / Type Confusion handling).
    """
    parsed = urllib.parse.urlparse(base_url)
    
    # 1. Stateful Session Control Audit: if custom headers/cookies are provided, test stripped-auth request
    if custom_headers and any(k.lower() in ("authorization", "cookie") for k in custom_headers):
        try:
            # Send request WITHOUT auth headers to test server-side session enforcement
            req = urllib.request.Request(base_url, headers={
                "User-Agent": "Mozilla/5.0 websec-auditor/1.0",
                "Accept": "*/*"
            })
            try:
                t_o = 8
                remaining = _budget_remaining()
                if remaining is not None:
                    t_o = min(t_o, max(remaining, 1))
                resp = netsafe.open_verified_first(req, timeout=t_o)
                status_code = getattr(resp, "status", None) or getattr(resp, "code", 200)
            except urllib.error.HTTPError as e:
                status_code = e.code

            if status_code in (200, 204):
                result.add(Finding(
                    check="stateful_api", name="Stateful Access Control Audit: Endpoint Public Without Credentials",
                    status="warn", severity="medium",
                    detail=("Endpoint responded with HTTP 200 even when session cookies / "
                            "Authorization tokens were stripped. If this URL is SUPPOSED to "
                            "require authentication, access control is missing (CWE-285/BOLA). "
                            "If it is a public page, this is expected behavior - verify manually."),
                    source_id="OWASP-API-2023-BOLA", cwe="CWE-285", owasp="A01",
                    remediation="Enforce server-side session identity and authorization checks on every endpoint that must not be public.",
                    confidence="low"))
            else:
                result.add(Finding(
                    check="stateful_api", name="Stateful Access Control Audit: Session Authorization Enforced",
                    status="pass", severity="info",
                    detail=f"Stripping authorization headers correctly triggered HTTP {status_code} protection response.",
                    source_id="OWASP-API-2023-BOLA", cwe="CWE-285", owasp="A01"))
        except Exception:
            pass

    # 2. Parameter Boundary & Validation Auditor
    sep = "&" if "?" in base_url else "?"
    boundary_test_url = f"{base_url}{sep}id=99999999999999999999999999999999%27%22%3C%3E"
    try:
        try:
            resp = _get(boundary_test_url, timeout=8, custom_headers=custom_headers)
            body = resp.read(150000).decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            body = e.read(150000).decode("utf-8", "ignore")
        
        # Check for unhandled stack traces or 500 Internal Server Errors exposing framework internals
        if any(err in body.lower() for err in ("traceback (most recent call last):", "fatal error:", "uncaught exception", "nullpointerexception")):
            result.add(Finding(
                check="stateful_api", name="Parameter Validation Audit: Unhandled Stack Trace Exposure",
                status="fail", severity="medium",
                detail="Boundary parameter malformation triggered unhandled framework exception / stack trace in response.",
                source_id="CWE-200", cwe="CWE-200", owasp="A05",
                remediation="Implement global exception handling middleware to catch unhandled errors and return sanitized 400 Bad Request responses."))
    except Exception:
        pass


def check_network_stability(result: ScanResult, base_url: str, custom_headers: dict = None):
    """Network Stability & Infrastructure Responsiveness Audit (TTFB & Latency Metrics).
    Measures server responsiveness, HTTP protocol efficiency, and connection stability.
    """
    import time
    start_t = time.time()
    try:
        req = urllib.request.Request(base_url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) websec-auditor/1.0",
            "Accept": "*/*"
        })
        if custom_headers:
            req.headers.update(custom_headers)
        t_o = 10
        remaining = _budget_remaining()
        if remaining is not None:
            t_o = min(t_o, max(remaining, 1))
        resp = netsafe.open_verified_first(req, timeout=t_o)
        ttfb_ms = int((time.time() - start_t) * 1000)
        if ttfb_ms < 400:
            result.add(Finding(
                check="network_stability", name=f"Network Stability: Excellent ({ttfb_ms}ms TTFB)",
                status="pass", severity="info",
                detail=f"Server latency is excellent ({ttfb_ms}ms response time). Network infrastructure is highly responsive.",
                source_id="BOOK-ZALEWSKI-SILENCE", cwe="CWE-400", owasp="A05"))
        elif ttfb_ms < 1200:
            result.add(Finding(
                check="network_stability", name=f"Network Stability: Moderate Latency ({ttfb_ms}ms TTFB)",
                status="pass", severity="info",
                detail=f"Server latency is moderate ({ttfb_ms}ms response time). Network connection is stable.",
                source_id="BOOK-FORSHAW-NETPROTOCOLS", cwe="CWE-400", owasp="A05"))
        else:
            result.add(Finding(
                check="network_stability", name=f"Network Stability: High Latency / Slow Response ({ttfb_ms}ms TTFB)",
                status="warn", severity="low",
                detail=f"Server response latency is elevated ({ttfb_ms}ms TTFB). Network or server load may experience congestion under traffic.",
                source_id="BOOK-FORSHAW-NETPROTOCOLS", cwe="CWE-400", owasp="A05",
                remediation="Enable HTTP/2, use CDN edge caching (Cloudflare/CloudFront), and optimize web server socket pools."))
    except Exception as e:
        result.add(Finding(
            check="network_stability", name="Network Stability: Unstable / Request Timeout",
            status="warn", severity="medium",
            detail=f"Network probe timed out or experienced connection drops: {e}",
            source_id="ATTACK-T1498-DOS", cwe="CWE-400", owasp="A05",
            remediation="Inspect network routing, firewall rate limiting, and web server socket health."))


def check_graphql_surface(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """Probe for exposed GraphQL schema endpoints (OWASP API8:2023 / CWE-200)."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    endpoints = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql"]
    for path in endpoints:
        if _budget_exhausted():
            break
        try:
            resp = _get(origin + path, timeout=2, custom_headers=custom_headers)
            status = getattr(resp, "status", None) or getattr(resp, "code", 200)
            if status in (200, 400):
                body = resp.read(2000).decode("utf-8", "ignore").lower()
                if "graphql" in body or "query" in body or "syntax error" in body:
                    result.add(Finding(
                        check="graphql_surface", name=f"GraphQL Endpoint Exposed ({path})",
                        status="warn", severity="medium",
                        detail=f"GraphQL endpoint discovered at {origin}{path}. Verify schema introspection is disabled in production.",
                        source_id="OWASP-API-2023-GRAPHQL", cwe="CWE-200", owasp="A05",
                        remediation="Disable introspection queries in production and restrict GraphQL IDE interfaces to internal networks."))
                    return
        except Exception:
            pass


def check_security_txt(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """Check for RFC 9116 security.txt vulnerability disclosure policy."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in ("/.well-known/security.txt", "/security.txt"):
        if _budget_exhausted():
            break
        try:
            resp = _get(origin + path, timeout=2, custom_headers=custom_headers)
            status = getattr(resp, "status", None) or getattr(resp, "code", 200)
            if status == 200:
                body = resp.read(1000).decode("utf-8", "ignore")
                if "contact:" in body.lower() or "expires:" in body.lower():
                    result.add(Finding(
                        check="security_txt", name="Security.txt Policy Published (RFC 9116)",
                        status="pass", severity="info",
                        detail=f"Standard vulnerability disclosure policy published at {origin}{path}.",
                        source_id="RFC-9116-SECURITY-TXT", cwe="CWE-200", owasp="A05"))
                    return
        except Exception:
            pass


def check_crossdomain_policy(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """Probe for exposed overly permissive crossdomain.xml or clientaccesspolicy.xml (CWE-942)."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
        if _budget_exhausted():
            break
        try:
            resp = _get(origin + path, timeout=2, custom_headers=custom_headers)
            status = getattr(resp, "status", None) or getattr(resp, "code", 200)
            if status == 200:
                body = resp.read(1500).decode("utf-8", "ignore").lower()
                if "allow-access-from" in body and 'domain="*"' in body:
                    result.add(Finding(
                        check="crossdomain_policy", name=f"Overly Permissive Cross-Domain Policy ({path})",
                        status="fail", severity="high",
                        detail=f"Found wildcard domain allowance (<allow-access-from domain=\"*\" />) in {origin}{path}.",
                        source_id="CWE-942-CROSSDOMAIN", cwe="CWE-942", owasp="A01",
                        remediation="Remove wildcard cross-domain access; restrict access to explicit trusted origins only."))
                    return
        except Exception:
            pass


def check_client_side_js_dom(result: ScanResult, base_url: str, body: str, custom_headers: dict = None, kb_rules=None):
    """Analyze client-side HTML, SPA JavaScript bundles, DOM sinks, and secrets (WSTG-CLNT / CWE-79 / CWE-798)."""
    if not body:
        return
    
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Extract script contents from HTML
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", body, re.DOTALL | re.IGNORECASE)
    js_sources = [s for s in script_blocks if s.strip()]

    # If the scanned target is itself a JS file or no script tags exist, treat body as JS only if content-type/ext matches
    if not js_sources and (base_url.endswith(".js") or "javascript" in base_url):
        js_sources.append(body)

    # Also inspect internal relative scripts referenced on page (up to 3)
    src_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
    for src in src_matches[:3]:
        if src.startswith("http://") or src.startswith("https://"):
            if not src.startswith(origin):
                continue
            script_url = src
        else:
            script_url = urllib.parse.urljoin(base_url, src)
        try:
            req = urllib.request.Request(script_url, headers=custom_headers or {"User-Agent": config.DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                raw_js = resp.read().decode("utf-8", errors="ignore")
                if raw_js.strip():
                    js_sources.append(raw_js)
        except Exception:
            pass

    combined_js = "\n".join(js_sources)
    if not combined_js.strip():
        result.add(Finding(
            check="client_js_dom", name="Client-Side DOM & JS Execution: No Insecure Sinks",
            status="pass", severity="info",
            detail="No client-side script vulnerabilities or unescaped DOM execution sinks detected.",
            source_id="WSTG-CLNT-01", cwe="CWE-79", owasp="A03",
            remediation=""))
        return

    # 1. Check DOM XSS Sinks in executable JavaScript blocks
    dom_sinks = [
        (r"document\.write\s*\(", "document.write() DOM injection sink", "CWE-79", "A03", "medium"),
        (r"(\.innerHTML|\.outerHTML)\s*=", "innerHTML / outerHTML dynamic assignment without sanitization", "CWE-79", "A03", "medium"),
        (r"\beval\s*\(", "Dynamic eval() execution in client script", "CWE-94", "A03", "high"),
        (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML unescaped DOM insertion", "CWE-79", "A03", "medium"),
        (r"v-html\s*=", "Vue v-html unescaped raw HTML directive", "CWE-79", "A03", "medium"),
    ]
    found_sink = False
    for pattern, desc, cwe, owasp, sev in dom_sinks:
        if re.search(pattern, combined_js, re.IGNORECASE):
            result.add(Finding(
                check="client_js_dom", name=f"DOM Injection / Client Sink: {desc.split()[0]}",
                status="warn", severity=sev,
                detail=f"Discovered dangerous client-side DOM manipulation sink ({desc}) in executable client scripts.",
                source_id="WSTG-CLNT-01", cwe=cwe, owasp=owasp,
                remediation="Use textContent or safe DOM APIs; sanitize untrusted input with DOMPurify before insertion."))
            found_sink = True
            break

    # 2. Check postMessage listeners without origin checks (CWE-345)
    if "addeventlistener('message'" in combined_js.lower() or 'addeventlistener("message"' in combined_js.lower():
        if "event.origin" not in combined_js and "e.origin" not in combined_js:
            result.add(Finding(
                check="client_js_dom", name="Insecure postMessage Handler (Missing Origin Verification)",
                status="fail", severity="medium",
                detail="window.addEventListener('message', ...) is present without visible origin verification (e.origin check).",
                source_id="WSTG-CLNT-11", cwe="CWE-345", owasp="A01",
                remediation="Always verify event.origin against a trusted domain allowlist before processing message data."))
            found_sink = True

    # 3. Check for exposed secrets / API keys in frontend source
    secret_match = re.search(r"(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]", combined_js, re.IGNORECASE)
    if secret_match:
        result.add(Finding(
            check="client_js_dom", name="Client-Exposed API Key or Token",
            status="fail", severity="high",
            detail=f"Detected high-entropy API token or secret assignment in client-accessible source: {secret_match.group(0)[:40]}...",
            source_id="CWE-798-HARDCODED-CREDENTIALS", cwe="CWE-798", owasp="A07",
            remediation="Never embed server API secrets or private tokens in client-side HTML or JS bundles."))
        found_sink = True

    if not found_sink:
        result.add(Finding(
            check="client_js_dom", name="Client-Side DOM & JS Execution: No Insecure Sinks",
            status="pass", severity="info",
            detail="Audited client-side JavaScript bundles and script blocks; zero dangerous DOM sinks or unverified postMessage handlers detected.",
            source_id="WSTG-CLNT-01", cwe="CWE-79", owasp="A03",
            remediation=""))


def check_email_security_dmarc_spf(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """Audit email spoofing and domain reputation defenses: SPF (RFC 7208) and DMARC (RFC 7489)."""
    if _budget_exhausted():
        return
    parsed = urllib.parse.urlparse(base_url)
    hostname = parsed.hostname
    if not hostname or hostname in ("localhost", "127.0.0.1") or netsafe.is_private_ip(hostname):
        return

    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    # Query DoH for DMARC TXT record
    try:
        req = urllib.request.Request(
            f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT",
            headers={"Accept": "application/dns-json", "User-Agent": "websec-auditor"}
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            answers = data.get("Answer", [])
            txts = [a.get("data", "").strip('"') for a in answers if a.get("type") == 16]
            dmarc_record = next((t for t in txts if "v=dmarc1" in t.lower()), None)
            if not dmarc_record:
                result.add(Finding(
                    check="email_security", name="Missing DMARC Policy (Domain Spoofing Vulnerability)",
                    status="fail", severity="medium",
                    detail=f"No DMARC TXT record published at _dmarc.{domain}. The domain is vulnerable to email spoofing and brand phishing.",
                    source_id="RFC-7489-DMARC", cwe="CWE-358", owasp="A05",
                    remediation=f"Publish a DMARC TXT record at _dmarc.{domain} with 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}'."))
            elif "p=none" in dmarc_record.lower():
                result.add(Finding(
                    check="email_security", name="Weak DMARC Policy (p=none Monitoring Only)",
                    status="warn", severity="low",
                    detail=f"DMARC record at _dmarc.{domain} specifies 'p=none'. Spoofed emails will not be rejected or quarantined.",
                    source_id="RFC-7489-DMARC", cwe="CWE-358", owasp="A05",
                    remediation=f"Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' to enforce rejection of fraudulent emails."))
            else:
                result.add(Finding(
                    check="email_security", name="Strong DMARC Policy Enforced (RFC 7489)",
                    status="pass", severity="info",
                    detail=f"DMARC policy active at _dmarc.{domain}: {dmarc_record}",
                    source_id="RFC-7489-DMARC", cwe="CWE-358", owasp="A05"))
    except Exception:
        pass

    # Query DoH for SPF TXT record
    try:
        req = urllib.request.Request(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
            headers={"Accept": "application/dns-json", "User-Agent": "websec-auditor"}
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            answers = data.get("Answer", [])
            txts = [a.get("data", "").strip('"') for a in answers if a.get("type") == 16]
            spf_record = next((t for t in txts if "v=spf1" in t.lower()), None)
            if not spf_record:
                result.add(Finding(
                    check="email_security", name="Missing SPF Record (RFC 7208)",
                    status="warn", severity="medium",
                    detail=f"No SPF TXT record found for {domain}. Mail relays cannot verify authorized sender IPs.",
                    source_id="RFC-7208-SPF", cwe="CWE-358", owasp="A05",
                    remediation=f"Publish an SPF TXT record on {domain} specifying authorized mail servers (e.g. 'v=spf1 include:_spf.google.com ~all')."))
            elif "+all" in spf_record:
                result.add(Finding(
                    check="email_security", name="Overly Permissive SPF Record (+all)",
                    status="fail", severity="high",
                    detail=f"SPF record on {domain} contains '+all', explicitly authorizing any IP on the Internet to send mail on your behalf.",
                    source_id="RFC-7208-SPF", cwe="CWE-358", owasp="A05",
                    remediation="Change '+all' to '~all' (softfail) or '-all' (hardfail) in your SPF record."))
    except Exception:
        pass


def check_subdomain_exposure(result: ScanResult, base_url: str, custom_headers: dict = None, kb_rules=None):
    """Probe for exposed staging/dev environments and CNAME subdomain takeover signatures (CWE-358)."""
    if _budget_exhausted():
        return
    parsed = urllib.parse.urlparse(base_url)
    hostname = parsed.hostname
    if not hostname or hostname in ("localhost", "127.0.0.1") or netsafe.is_private_ip(hostname):
        return

    parts = hostname.split(".")
    if len(parts) < 2:
        return
    root_domain = ".".join(parts[-2:])

    for sub in ("dev", "staging", "test", "admin", "api"):
        sub_host = f"{sub}.{root_domain}"
        if sub_host == hostname:
            continue
        try:
            req = urllib.request.Request(
                f"https://cloudflare-dns.com/dns-query?name={sub_host}&type=A",
                headers={"Accept": "application/dns-json", "User-Agent": "websec-auditor"}
            )
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("Answer"):
                    result.add(Finding(
                        check="subdomain_exposure", name=f"Discovered Environment Subdomain: {sub_host}",
                        status="warn", severity="low",
                        detail=f"Active DNS resolution found for development/staging asset: {sub_host}. Verify IP allow-lists and access controls.",
                        source_id="CWE-358-SUBDOMAIN", cwe="CWE-358", owasp="A05",
                        remediation=f"Restrict access to {sub_host} behind a corporate VPN, Cloudflare Access, or IP allow-list."))
                    break
        except Exception:
            pass


def scan_one(result: ScanResult, url: str, timeout: int = 15, params=None, custom_headers: dict = None, kb_rules=None, allow_private: bool = False):
    """Run every per-page check against one URL. The caller owns the ScanResult.
    TLS is host-level and checked separately by scan(). Returns an info dict
    {ok, status, headers, body, params} for the caller (e.g. the crawler).
    allow_private=True (local CLI / bundled demo) widens the anti-SSRF guard
    to loopback/private targets for this scan's duration."""
    global _BUDGET_DEADLINE
    import time as _t
    owns = _BUDGET_DEADLINE is None
    if owns:
        _BUDGET_DEADLINE = _t.monotonic() + config.SCAN_BUDGET_SEC
    with netsafe.private_allowed(allow_private):
        try:
            return _scan_one_impl(result, url, timeout, params, custom_headers, kb_rules)
        finally:
            if owns:
                _BUDGET_DEADLINE = None


def _scan_one_impl(result: ScanResult, url: str, timeout: int = 15, params=None, custom_headers: dict = None, kb_rules=None):
    parsed = urllib.parse.urlparse(url)
    kb_rules = kb_rules if kb_rules is not None else load_kb_rules()
    if _budget_exhausted():
        return {"ok": False, "error": "scan budget exhausted", "budget": True}
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
    check_client_side_js_dom(result, url, body, custom_headers, kb_rules)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        f1 = executor.submit(check_sensitive_files, result, url, custom_headers, kb_rules)
        f2 = executor.submit(check_http_methods, result, url, custom_headers, kb_rules)
        f3 = executor.submit(check_open_redirect, result, url, params, custom_headers, kb_rules)
        f4 = executor.submit(check_stateful_api, result, url, custom_headers, kb_rules)
        f5 = executor.submit(check_network_stability, result, url, custom_headers)
        f6 = executor.submit(check_sqli, result, url, params, custom_headers, kb_rules)
        f7 = executor.submit(check_xss, result, url, params, custom_headers, kb_rules)
        f8 = executor.submit(check_ddos_mitigation, result, headers, kb_rules)
        f9 = executor.submit(check_blind_sqli, result, url, params, custom_headers, kb_rules)
        f10 = executor.submit(check_path_traversal, result, url, params, custom_headers, kb_rules)
        f11 = executor.submit(check_csrf_token, result, body, url, kb_rules)
        f12 = executor.submit(check_rate_limiting, result, url, custom_headers, kb_rules)
        f13 = executor.submit(check_graphql_surface, result, url, custom_headers, kb_rules)
        f14 = executor.submit(check_security_txt, result, url, custom_headers, kb_rules)
        f15 = executor.submit(check_crossdomain_policy, result, url, custom_headers, kb_rules)
        f16 = executor.submit(check_email_security_dmarc_spf, result, url, custom_headers, kb_rules)
        f17 = executor.submit(check_subdomain_exposure, result, url, custom_headers, kb_rules)
        concurrent.futures.wait([f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16, f17], timeout=4 if config.SCAN_BUDGET_SEC <= 15 else 6)
    return {
        "ok": True,
        "status": getattr(resp, "status", None) or getattr(resp, "code", 0),
        "headers": headers, "body": body, "params": params,
    }


def scan(target: str, custom_headers: dict = None, kb_rules=None) -> ScanResult:
    """Scan a target URL. Returns a ScanResult with grounded findings."""
    global _BUDGET_DEADLINE
    import time as _t
    owns = _BUDGET_DEADLINE is None
    if owns:
        _BUDGET_DEADLINE = _t.monotonic() + config.SCAN_BUDGET_SEC
    try:
        target = target.strip()
        if not target.startswith("http"):
            target = "https://" + target
        parsed = urllib.parse.urlparse(target)
        result = ScanResult(target=target, scheme=parsed.scheme)
        info = scan_one(result, target, custom_headers=custom_headers, kb_rules=kb_rules)
        if parsed.scheme == "https" and info.get("ok"):
            check_tls(result, parsed.hostname, 443)
        return result
    finally:
        if owns:
            _BUDGET_DEADLINE = None


if __name__ == "__main__":
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "https://self-signed.badssl.com"
    r = scan(tgt)
    print(json.dumps(r.to_dict(), indent=2, default=str))
