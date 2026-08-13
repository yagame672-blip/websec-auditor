"""A local demo server for websec-auditor, used as a PROOF TARGET.

It runs in two modes controlled by websec_auditor/fixgen (data/demo_fixstate.json):
  * FLAWED   (default)  -> intentionally insecure (no headers, reflected XSS,
                           verbose SQL error, unhardened cookie, CSRF-less
                           login form, hidden admin area leaked by robots.txt)
  * HARDENED (after Fix) -> serves the security headers, HTML-escapes reflected
                           input, suppresses verbose errors, hardens the cookie,
                           adds a CSRF token to the login form, and locks down
                           /admin.

Multi-page structure (exercises the site-wide crawler):
  /            home: links to /about, /search, /login
  /about       static page
  /search      reflected q parameter (XSS + SQL error probes)
  /login       state-changing POST form (CSRF token absent when flawed)
  /admin       hidden area, linked ONLY from robots.txt
  /robots.txt  leaks /admin when flawed
  /sitemap.xml lists /about, /search, /login

NOT production code.
"""
from __future__ import annotations
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from websec_auditor import fixgen


def _hardened():
    return fixgen.demo_is_hardened()


_PAGE = ("<html><head><title>{t}</title></head><body>"
         "<h1>{t}</h1>{body}</body></html>")


def _home():
    return _PAGE.format(t="Demo site", body=(
        "<p>Welcome. Search, read about us, or sign in.</p>"
        "<ul><li><a href='/about'>About</a></li>"
        "<li><a href='/search'>Search</a></li>"
        "<li><a href='/login'>Login</a></li></ul>"))


def _about():
    return _PAGE.format(t="About", body="<p>This is the demo about page.</p>")


def _search(q, hardened):
    if not hardened and "'" in q:
        # FLAW: verbose SQL error leaked.
        return ("<html><body>You have an error in your SQL syntax near '"
                + html.escape(q) + "'</body></html>"), 500
    reflected = html.escape(q) if hardened else q
    body = (_PAGE.format(t="Search", body=(
            f"<p>You searched for: {reflected}</p>"
            "<form action='/search' method='get'><input name='q'>"
            "<button>Go</button></form>")))
    return body, 200


def _login(hardened):
    if hardened:
        token = "<input type='hidden' name='_token' value='7f3c9d2a'>"
    else:
        token = ""
    body = _PAGE.format(t="Login", body=(
            "<form action='/login' method='post'>" + token +
            "<input name='username' placeholder='username'>"
            "<input name='password' type='password' placeholder='password'>"
            "<button>Sign in</button></form>"))
    return body


class Handler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())
        if not _hardened():
            # FLAW: advertise the server software/version.
            self.send_header("Server", self.version_string())

    def _serve(self, body, hardened, status=200, extra_headers=None):
        self.send_response(status)
        if hardened:
            self.send_header("Strict-Transport-Security",
                             "max-age=63072000; includeSubDomains; preload")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; frame-ancestors 'none'; object-src 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy",
                             "camera=(), microphone=(), geolocation=()")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Set-Cookie",
                             "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax")
        else:
            # FLAW: unhardened session cookie on every page.
            self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        if hardened:
            self.send_header("Content-Type", "text/html; charset=utf-8")
        else:
            # FLAW: HTML served without a declared charset.
            self.send_header("Content-Type", "text/html")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        hardened = _hardened()
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]

        if path == "/search":
            body, status = _search(q, hardened)
            self._serve(body, hardened, status)
            return
        if path == "/login":
            self._serve(_login(hardened), hardened)
            return
        if path == "/about":
            self._serve(_about(), hardened)
            return
        if path == "/admin":
            if hardened:
                self._serve("<html><body><h1>403 Forbidden</h1></body></html>",
                            hardened, status=403)
            else:
                # FLAW: hidden admin area reachable, no authz check.
                self._serve(_PAGE.format(t="Admin", body=(
                    "<p>Admin panel. User list, config, backups.</p>")), hardened)
            return
        if path == "/robots.txt":
            if hardened:
                # FIX: no sensitive paths disallowed -> nothing to leak.
                body = "User-agent: *\nAllow: /\n"
            else:
                # FLAW: robots.txt leaks the hidden admin/backup areas.
                body = ("User-agent: *\n"
                        "Disallow: /admin\n"
                        "Disallow: /backup\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())
            return
        if path == "/sitemap.xml":
            if hardened:
                # FIX: no sitemap -> no URLs exposed via metafiles.
                self.send_error(404)
                return
            body = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                    "<url><loc>http://127.0.0.1:8099/about</loc></url>\n"
                    "<url><loc>http://127.0.0.1:8099/search</loc></url>\n"
                    "<url><loc>http://127.0.0.1:8099/login</loc></url>\n"
                    "</urlset>")
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())
            return

        self._serve(_home(), hardened)

    def do_POST(self):
        hardened = _hardened()
        if urlparse(self.path).path == "/login":
            self._serve(_login(hardened), hardened)
        else:
            self._serve("<html><body><h1>404</h1></body></html>", hardened, status=404)

    def log_message(self, *a):
        pass


def serve(host="127.0.0.1", port=8099):
    print(f"Starting demo server on http://{host}:{port} (Ctrl+C to stop)")
    HTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    serve()
