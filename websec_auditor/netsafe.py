"""Network-level safety guard for every outbound scanner request (anti-SSRF).

Grounding: OWASP SSRF Prevention Cheat Sheet (CWE-918) -- validate every
target server-side BEFORE the request, refuse private/reserved address
space, and RE-VALIDATE on every redirect hop (an open redirect on the
target must not turn the scanner into an internal-network proxy).

What is refused (unless the caller explicitly allowed private targets for
local use, e.g. the bundled demo server on 127.0.0.1):
  * non-http(s) schemes (file://, ftp://, data: ...)
  * URLs carrying credentials (user:pass@host)
  * loopback, private, link-local (incl. cloud metadata 169.254.169.254),
    CGNAT 100.64.0.0/10, reserved, multicast and unspecified addresses,
    resolved from the hostname's FULL A/AAAA record set (one bad record
    blocks the host)

NOTE (DNS rebinding): stdlib-only code cannot pin the resolved IP to the
actual socket connection, so a target whose DNS flips between a public and
a private address between validate() and connect() is not fully covered.
The validate-at-request-time check below is the standard baseline defense.
"""
from __future__ import annotations
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
import ssl
from contextlib import contextmanager

# Module-level switch widened by local entry points (CLI / local webui
# against the user's own machine). Default False: the deployed UI must
# never fetch private address space. private_allowed() only ever WIDENS
# within a scope so nested scan_one() calls inherit the outer permission.
ALLOW_PRIVATE = False

# Resolved-address cache: {hostname: (expiry_monotonic, [ips])} to avoid a
# DNS lookup per probe on the same host. Bounded; entries expire quickly.
_DNS_TTL = 60.0
_DNS_CACHE: dict = {}
_DNS_CACHE_MAX = 512

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class UnsafeTargetError(Exception):
    """Raised when a URL points at address space the scanner must not touch."""


def _blocked_reason(ip) -> str:
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private address space"
    if ip.is_link_local:
        return "link-local address (incl. cloud metadata services)"
    if ip in _CGNAT:
        return "carrier-grade NAT address space"
    if ip.is_reserved:
        return "reserved address space"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    return ""


def _resolve(host: str):
    import time
    now = time.monotonic()
    ent = _DNS_CACHE.get(host)
    if ent and ent[0] > now:
        return ent[1]
    try:
        infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
    except Exception as e:
        raise UnsafeTargetError(f"could not resolve host {host!r}: {e}") from e
    ips = []
    for info in infos:
        addr = info[4][0]
        try:
            ips.append(ipaddress.ip_address(addr.split("%")[0]))
        except ValueError:
            continue
    if not ips:
        raise UnsafeTargetError(f"host {host!r} resolved to no usable address")
    if len(_DNS_CACHE) < _DNS_CACHE_MAX:
        _DNS_CACHE[host] = (now + _DNS_TTL, ips)
    return ips


def validate_target(url: str, allow_private: bool = None) -> str:
    """Validate a URL and return it unchanged; raise UnsafeTargetError if it
    points at address space the scanner must not fetch."""
    if allow_private is None:
        allow_private = ALLOW_PRIVATE
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError(f"scheme {parsed.scheme!r} is not allowed (http/https only)")
    host = parsed.hostname
    if not host:
        raise UnsafeTargetError("URL has no hostname")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("URLs with embedded credentials are not allowed")
    # Literal IP or hostname: resolve and check EVERY address record.
    for ip in _resolve(host):
        reason = _blocked_reason(ip)
        if reason and not allow_private:
            raise UnsafeTargetError(
                f"target {host} resolves to {ip} ({reason}); refusing to fetch. "
                "Private/internal targets are only supported from the local CLI.")
    return url


@contextmanager
def private_allowed(flag: bool):
    """Widen the module permission for a local scan scope (never narrows an
    enclosing scope). Used by engine.scan / crawler.scan_site entry points."""
    global ALLOW_PRIVATE
    prev = ALLOW_PRIVATE
    ALLOW_PRIVATE = prev or bool(flag)
    try:
        yield
    finally:
        ALLOW_PRIVATE = prev


class GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates every redirect hop against the same SSRF rules. A
    redirect into blocked address space stops here (urlopen then raises the
    3xx HTTPError, which callers already handle)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = urllib.parse.urljoin(req.full_url, newurl)
        try:
            validate_target(newurl)
        except UnsafeTargetError:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener(context):
    handlers = [GuardedRedirectHandler()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def open_guarded(req: urllib.request.Request, timeout: int = 10, context=None):
    """Validate req.full_url, then fetch it with redirect revalidation.
    `context` is an ssl.SSLContext (callers choose verifying or relaxed)."""
    validate_target(req.full_url)
    return _opener(context).open(req, timeout=timeout)


def open_verified_first(req: urllib.request.Request, timeout: int = 10):
    """Fetch with certificate verification ON first (MITM-resistant); fall
    back to a relaxed context only when the failure is certificate
    verification (target genuinely has a broken/self-signed cert -- the TLS
    check reports that separately)."""
    try:
        return open_guarded(req, timeout=timeout, context=ssl.create_default_context())
    except urllib.error.URLError as e:
        if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
            # Deliberate: only after a real verification failure do we fall back
            # to a relaxed context so the scanner can still inspect (and report)
            # broken/self-signed TLS certs instead of failing the whole scan.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False  # codereview-ignore: disabled-ssl-verification
            ctx.verify_mode = ssl.CERT_NONE
            return open_guarded(req, timeout=timeout, context=ctx)
        raise
    except ssl.SSLCertVerificationError:
        # Deliberate: same intent as above -- inspect broken certs, report them
        # as a separate finding, never silently accept without reporting.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # codereview-ignore: disabled-ssl-verification
        ctx.verify_mode = ssl.CERT_NONE
        return open_guarded(req, timeout=timeout, context=ctx)
