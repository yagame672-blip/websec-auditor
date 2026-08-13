# websec-auditor

A **book-grounded** web security auditor. Detection rules are curated directly
from authoritative security literature (OWASP Top 10:2021, MITRE CWE, OWASP
ASVS, OWASP cheat sheets). The analyzer layer only *explains and cites*
findings using passages from that knowledge base — it never invents
vulnerabilities. Deterministic, read-only probes do the actual detection.

## Why this is different from "vibe-coded" scanners

Most AI security scanners let the LLM *guess* whether a site is vulnerable —
which hallucinates. Here:

- **Detection = real code.** HTTP probes check headers, TLS, cookie flags,
  input reflection, and SQL error signatures.
- **Rule catalog = grounded in books/standards.** Every check carries a
  `source_id` (CWE / OWASP entry) drawn from the knowledge base.
- **Explanation = quoted from the KB.** Each finding shows the exact
  standard/book passage behind it, with a citation link and a concrete fix.

## Knowledge sources (per project design)

- **A — Free, legal, authoritative docs:** OWASP Top 10:2021, MITRE CWE, ASVS,
  OWASP cheat sheets. Passages are our *own paraphrased* explanations of those
  public standards (facts + guidance), attributed with source name + URL. No
  copyrighted text is copied.
- **B — Curated reputable security books:** metadata + publisher + the
  publisher's own free/preview links (O'Reilly, Wiley, Manning, OWASP). We do
  NOT redistribute book bodies.
- **C — User-owned books (optional):** drop your own legally-owned PDFs into
  `data/user_books/` and run the PDF ingestor (offline/local only).

## Usage

```bash
# 1. Build the knowledge base (run once)
python websec_cli.py build-kb

# 2. Scan a single page you OWN / are authorized to test
python websec_cli.py scan https://your-site.example [--html]

# 3. Site-wide scan: crawl same-origin pages (robots.txt + sitemap.xml +
#    discovered links + forms) and scan each discovered page
python websec_cli.py scan https://your-site.example --crawl

# 4. Start the web UI (standard library only, no external deps)
python websec_cli.py webui --port 8000
#    open http://127.0.0.1:8000 in your browser (tick "site-wide crawl")

# 5. (Optional) Run the bundled flawed demo server as a proof target
python websec_cli.py demo
#    then paste http://127.0.0.1:8099 into the UI and click Scan
```

The site-wide crawl is grounded in the WSTG information-gathering chapters:
`WSTG-INFO-03` (review webserver metafiles), `WSTG-INFO-06` (identify entry
points), and `WSTG-INFO-07` (map execution paths), with crawling engineering
patterns from *Web Scraping with Python* and *Black Hat Python*. It is bounded
(`config.CRAWL_MAX_PAGES` / `CRAWL_MAX_DEPTH`), same-origin only, read-only,
and reports per-issue deduplicated findings ("seen on N pages").

### UI workflow (verified)

1. Paste a URL of a site you **own / are authorized to test** → click **Scan**.
2. The UI lists every finding with its **severity**, the **reason it was
   flagged** (book/standard citation: OWASP, MITRE CWE, ASVS), and a concrete
   **fix**.
3. **Fix Demo Site** button — hardens the bundled demo server and re-scans it
   so the flags turn green (proves the loop on a site we own). For your own
   sites, **Download Fix Bundle** generates ready-to-deploy nginx / Apache /
   Flask / Express config you apply on your server.
4. Scanning targets you do not own/authorize may violate computer-fraud law.

## How the "Fix" works (honest scope)

- **Bundled demo server** (a site we own): the Fix button directly writes a
  hardened config and re-scans — turning the flags green. This is the verifiable
  fix loop.
- **Your own server** (any external site): the tool cannot and must not edit a
  remote host. Instead it generates a deployment-ready remediation bundle
  (security headers + cookie flags + output-encoding guidance) you apply
  yourself. This respects authorization boundaries while still "fixing" the
  issues it found.

## Safety

This tool only runs **safe, read-only** probes. It never performs destructive,
DoS, or fuzzing payloads. Injection checks use a benign reflection marker and
error-signature detection only. Scan **only targets you own or are explicitly
authorized to test** — scanning others may violate computer-fraud law.

## Project layout

```
websec-auditor/
  websec_cli.py                  CLI entrypoint
  websec_auditor/
    config.py                    rule catalog (grounded in standards)
    knowledge/build_kb.py        builds sources A + B
    scanner/engine.py            deterministic probes (scan / scan_one)
    crawler/crawl.py             site-wide crawler (BFS + metafiles + forms)
    analyzer/analyze.py          joins findings -> KB passages (citations)
    report/render.py             text + HTML report
    demo/flawed_server.py        intentionally-broken server (proof target)
  data/                          generated knowledge base (kb_books.jsonl)
  reports/                       generated HTML reports
```

## Verified behavior

Tested against a deliberately-flawed local server: correctly flagged missing
HSTS/CSP/X-Content-Type-Options/X-Frame-Options/Referrer-Policy/
Permissions-Policy, missing Secure/HttpOnly/SameSite cookie flags, cacheable
session responses, reflected-input XSS surface (CWE-79), and SQL error
signature (CWE-89). Tested against a well-configured external site: correctly
passed header, TLS, and reflection checks, and reported only genuine issues
(CSP unsafe-inline, CORS wildcard, Server/X-Powered-By disclosure).

Site-wide crawl (`--crawl`) against the multi-page demo: discovered 6
same-origin pages including the hidden `/admin` area leaked only via
`robots.txt` (WSTG-INFO-03), found the reflected XSS + SQL error on `/search`
(WSTG-INFO-07), flagged the CSRF-less login form (CWE-352), and aggregated
repeated header/cookie findings as "seen on N pages". After the demo fix the
same scan drops to green (SECURE), proving the fix loop site-wide.
