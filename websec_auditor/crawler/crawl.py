"""Site-wide crawler for websec-auditor (same-origin, bounded, read-only).

Book/standard grounding:
  - WSTG-INFO-03  Review Webserver Metafiles (robots.txt / sitemap.xml)
  - WSTG-INFO-06  Identify Application Entry Points (forms, params)
  - WSTG-INFO-07  Map Execution Paths (spider pages, test each path)
  - CWE-352       Cross-Site Request Forgery (state-changing form tokens)
  - Web Scraping with Python: link parsing, URL normalization, dedupe,
    polite bounded crawling.
  - Black Hat Python: request crafting / response parsing for authorized
    tooling.

Safety: only crawls same-origin URLs, read-only GETs, bounded by
max_pages/max_depth. Never submits forms, never sends payloads beyond the
engine's benign probes.
"""
from __future__ import annotations
import re
from collections import OrderedDict
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag

from websec_auditor import config
from websec_auditor.scanner import engine


class _LinkParser(HTMLParser):
    """Collects <a href>, <link href>, <iframe src> and <form> structures."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links = []
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ("a", "area") and d.get("href"):
            self.links.append(urljoin(self.base_url, d["href"]))
        elif tag == "link" and d.get("href"):
            self.links.append(urljoin(self.base_url, d["href"]))
        elif tag == "iframe" and d.get("src"):
            self.links.append(urljoin(self.base_url, d["src"]))
        elif tag == "form":
            action = d.get("action") or ""
            self._form = {
                "action": urljoin(self.base_url, action) if action else self.base_url,
                "method": (d.get("method") or "get").lower(),
                "fields": [],
            }
        elif tag == "input" and self._form is not None and d.get("name"):
            self._form["fields"].append(d["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _normalize(url: str):
    """Normalize a URL for dedupe: drop fragment, collapse empty paths."""
    url_no_frag, _ = urldefrag(url)
    parsed = urlparse(url_no_frag)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.path:
        parsed = parsed._replace(path="/")
    return parsed.geturl()


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port or (443 if pa.scheme == "https" else 80)) == \
           (pb.scheme, pb.hostname, pb.port or (443 if pb.scheme == "https" else 80))


def _is_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(config.CRAWL_SKIP_EXTS)


def _fetch(url: str, timeout: int = config.CRAWL_TIMEOUT, custom_headers: dict = None):
    """GET a URL; return dict {ok, status, body, final, headers}."""
    import urllib.request
    import urllib.error
    import ssl
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 websec-auditor/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if custom_headers:
            headers.update(custom_headers)
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(200000).decode("utf-8", "ignore")
        return {"ok": True, "status": getattr(resp, "status", 200),
                "body": body, "final": resp.geturl(), "headers": resp.headers}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(200000).decode("utf-8", "ignore")
        except Exception:
            pass
        return {"ok": False, "status": e.code, "body": body,
                "final": url, "headers": e.headers}
    except Exception as e:
        return {"ok": False, "status": 0, "body": "",
                "final": url, "error": str(e)}


def _discover_metafiles(seed: str, timeout: int, custom_headers: dict = None):
    """WSTG-INFO-03: fetch robots.txt + sitemap.xml, return discovered URLs."""
    base = f"{urlparse(seed).scheme}://{urlparse(seed).netloc}"
    found = []
    for path in ("/robots.txt", "/sitemap.xml"):
        info = _fetch(base + path, timeout, custom_headers=custom_headers)
        if not info["ok"] or info["status"] >= 400:
            continue
        body = info["body"]
        if path == "/robots.txt":
            for line in body.splitlines():
                m = re.match(r"\s*disallow\s*:\s*(\S+)", line, re.I)
                if m:
                    found.append(urljoin(base, m.group(1)))
        else:
            for m in re.finditer(r"<loc>\s*(.*?)\s*</loc>", body, re.I | re.S):
                found.append(m.group(1).strip())
    return [u for u in dict.fromkeys(found) if _normalize(u)]


def crawl(seed: str, max_pages=None, max_depth=None, timeout=None, custom_headers: dict = None):
    """BFS same-origin crawl of `seed`. Returns dict:
    {seed, pages: [ {url, depth, forms, params} ], links, metafiles}."""
    max_pages = max_pages or config.CRAWL_MAX_PAGES
    max_depth = max_depth if max_depth is not None else config.CRAWL_MAX_DEPTH
    timeout = timeout or config.CRAWL_TIMEOUT
    seed = seed.strip()
    if not seed.startswith("http"):
        seed = "https://" + seed
    seed_n = _normalize(seed) or seed
    visited = {}
    queue = [(seed_n, 0)]
    origin = urlparse(seed_n)
    order = []
    metafiles = []

    metafile_urls = _discover_metafiles(seed_n, timeout, custom_headers=custom_headers)
    for u in metafile_urls:
        if _same_origin(u, seed_n):
            metafiles.append(u)
            queue.append((u, 0))

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        key = _normalize(url)
        if key is None or key in visited:
            continue
        if not _same_origin(key, seed_n):
            continue
        if depth > max_depth:
            continue
        visited[key] = {"url": key, "depth": depth, "forms": [], "params": []}
        order.append(key)
        info = _fetch(key, timeout, custom_headers=custom_headers)
        if not info["ok"] or info["status"] >= 400:
            continue
        # WSTG-INFO-06: entry points = query params + forms on this page.
        visited[key]["params"] = list(parse_qs(urlparse(key).query).keys())
        parser = _LinkParser(key)
        try:
            parser.feed(info["body"])
        except Exception:
            pass
        visited[key]["forms"] = parser.forms
        for link in parser.links:
            n = _normalize(link)
            if (n and n not in visited and _same_origin(n, seed_n)
                    and not _is_asset(n) and depth + 1 <= max_depth):
                queue.append((n, depth + 1))

    return {
        "seed": seed_n,
        "pages": [visited[k] for k in order],
        "links": sorted({v["url"] for v in visited.values()}),
        "metafiles": metafiles,
    }


def _check_entry_points(result, pages, max_forms_shown=5):
    """WSTG-INFO-06: record discovered forms + params; CWE-352: flag
    state-changing forms that lack an anti-CSRF token."""
    from websec_auditor.scanner.engine import Finding
    all_params = set()
    for p in pages:
        all_params.update(p["params"])
    total_forms = sum(len(p["forms"]) for p in pages)
    if not total_forms and not all_params:
        return
    detail = f"Discovered {len(all_params)} query-string parameter name(s)."
    if total_forms:
        detail += f" Found {total_forms} form(s) across {len(pages)} page(s)."
    result.add(Finding(
        check="entry_points", name="Application entry points discovered",
        status="info", severity="info", detail=detail,
        source_id="WSTG-INFO-06-ENTRYPOINTS"))

    csrf_re = re.compile(config.CSRF_FIELD_RE, re.I)
    shown = 0
    for p in pages:
        for f in p["forms"]:
            has_token = any(csrf_re.search(field) for field in f["fields"])
            if f["method"] == "post" and not has_token:
                result.add(Finding(
                    check="csrf", name="State-changing form lacks CSRF token",
                    status="fail", severity=config.CSRF_RULE["severity"],
                    detail=(f"POST form at {f['action']} has no anti-CSRF token "
                            f"field (fields: {', '.join(f['fields']) or 'none'})."),
                    source_id=config.CSRF_RULE["source_id"],
                    cwe=config.CSRF_RULE["cwe"], owasp=config.CSRF_RULE["owasp"],
                    remediation=config.CSRF_RULE["remediation"]))
            elif f["method"] == "post" and has_token:
                result.add(Finding(
                    check="csrf", name="State-changing form has CSRF token",
                    status="pass", severity="info",
                    detail=f"POST form at {f['action']} includes an anti-CSRF token.",
                    source_id=config.CSRF_RULE["source_id"],
                    cwe=config.CSRF_RULE["cwe"], owasp=config.CSRF_RULE["owasp"]))
            if f["method"] == "post":
                shown += 1
                if shown >= max_forms_shown:
                    break
        if shown >= max_forms_shown:
            break


def _aggregate_findings(page_results):
    """Dedupe per-page findings by (check, name, status); annotate page counts."""
    merged = OrderedDict()
    for page_url, res in page_results:
        for f in res.findings:
            key = (f.check, f.name, f.status)
            if key in merged:
                merged[key]["pages"].append(page_url)
            else:
                merged[key] = {"finding": f, "pages": [page_url]}
    out = []
    for key, entry in merged.items():
        f = entry["finding"]
        pages = entry["pages"]
        if len(pages) > 1:
            sample = ", ".join(pages[:4])
            more = f" ... and {len(pages) - 4} more" if len(pages) > 4 else ""
            f.detail = f"{f.detail} | seen on {len(pages)} pages: {sample}{more}"
        out.append(f)
    return out


def scan_site(seed: str, max_pages=None, max_depth=None, timeout=None, custom_headers: dict = None):
    """Crawl `seed` and scan every discovered page. Returns an aggregated
    ScanResult (TLS checked once per host, per-page checks deduped)."""
    data = crawl(seed, max_pages, max_depth, timeout, custom_headers=custom_headers)
    result = engine.ScanResult(target=data["seed"], scheme=urlparse(data["seed"]).scheme)
    parsed = urlparse(data["seed"])
    if parsed.scheme == "https":
        engine.check_tls(result, parsed.hostname, 443)

    page_results = []
    for page in data["pages"]:
        url = page["url"]
        params = page["params"] or ["q"]
        sub = engine.ScanResult(target=url, scheme=urlparse(url).scheme)
        engine.scan_one(sub, url, timeout=timeout, params=params, custom_headers=custom_headers)
        page_results.append((url, sub))
        # keep a compact crawl record in raw for the report
        result.raw.setdefault("pages", [])
        result.raw["pages"].append({
            "url": url, "depth": page["depth"],
            "params": params, "forms": page["forms"],
        })

    result.raw["crawl"] = {
        "seed": data["seed"],
        "pages_scanned": len(data["pages"]),
        "urls_discovered": len(data["links"]),
        "metafiles": data["metafiles"],
    }

    # WSTG-INFO-03 metafile discovery finding
    from websec_auditor.scanner.engine import Finding
    if data["metafiles"]:
        result.add(Finding(
            check="metafiles", name="Webserver metafiles leak paths",
            status="warn", severity="low",
            detail=(f"robots.txt / sitemap.xml exposed {len(data['metafiles'])} "
                    f"URL(s): {', '.join(data['metafiles'][:5])}"),
            source_id="WSTG-INFO-03-METAFILES", cwe="CWE-200", owasp="A05"))
    else:
        result.add(Finding(
            check="metafiles", name="No leaking webserver metafiles",
            status="pass", severity="info",
            detail="No robots.txt/sitemap.xml paths were discovered.",
            source_id="WSTG-INFO-03-METAFILES", cwe="CWE-200", owasp="A05"))

    _check_entry_points(result, data["pages"])

    for f in _aggregate_findings(page_results):
        result.add(f)

    result.add(Finding(
        check="crawl_summary", name="Site crawl completed", status="info",
        severity="info",
        detail=(f"Scanned {len(data['pages'])} same-origin page(s) from "
                f"{data['seed']} (limit {max_pages or config.CRAWL_MAX_PAGES}, "
                f"depth {max_depth if max_depth is not None else config.CRAWL_MAX_DEPTH})."),
        source_id="WSTG-INFO-07-MAPPING"))
    return result
