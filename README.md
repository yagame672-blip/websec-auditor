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

# 6. KB-driven static code review of a source file or directory
python websec_cli.py codereview path/to/source [--html]
#    SQLi, XSS, SSRF, command/code injection, hardcoded credentials,
#    deserialization (pickle/yaml/unserialize), weak crypto, TLS disabled...

# 7. Dependency & advisory (CVE) scan of manifests / a directory
python websec_cli.py depscan path/to/requirements.txt [--html]
python websec_cli.py depscan path/to/repo
#    parses requirements.txt, Pipfile, pyproject.toml, setup.py, package.json,
#    package-lock.json, yarn.lock, composer.{json,lock}, Gemfile{.lock},
#    pom.xml, build.gradle, go.mod, go.sum against a LOCAL advisory seed
#    (Log4Shell, Spring4Shell, prototype-pollution chains, requests/urllib3...)

# 8. OWASP Top 10:2021 assessment (scorecard A01-A10 aggregated from findings)
python websec_cli.py owasp https://your-site.example [--crawl] [--html]

# 9. Generate security tests (Burp Intruder template, payloads, fuzzer, curl)
python websec_cli.py testgen https://your-site.example [--crawl] [--out reports/tests]
#    writes TEST_PLAN_*.md, burp_intruder_*.txt, websec_fuzzer_*.py,
#    tests_*.sh, payloads_<class>_*.txt

# 10. Machine-readable reports (scan / owasp / codereview / depscan)
python websec_cli.py scan https://your-site.example --json   # reports/report_<ts>.json
python websec_cli.py scan https://your-site.example --sarif  # SARIF 2.1.0 (code-scanning tools)
python websec_cli.py owasp https://your-site.example --sarif --html
```

The **code review**, **dependency scan**, **OWASP scorecard**, and **test
generation** commands are all driven by the same knowledge base
(`build-kb` compiles their rules from `knowledge/expansion.py` and
`config.py`): every finding carries a `source_id` (CWE/OWASP record), KB
citations, and a concrete remediation, and each OWASP category on the
scorecard lists the CWEs behind its status.

The site-wide crawl is grounded in the WSTG information-gathering chapters:
`WSTG-INFO-03` (review webserver metafiles), `WSTG-INFO-06` (identify entry
points), and `WSTG-INFO-07` (map execution paths), with crawling engineering
patterns from *Web Scraping with Python* and *Black Hat Python*. It is bounded
(`config.CRAWL_MAX_PAGES` / `CRAWL_MAX_DEPTH`), same-origin only, read-only,
and reports per-issue deduplicated findings ("seen on N pages").

### Report formats

- **Text** (default) and **HTML** (`--html`): human-readable, citations inline.
- **JSON** (`--json`): `{"tool", "target", "generated", "summary", "findings"}`.
- **SARIF 2.1.0** (`--sarif`): the standard feed for GitHub code scanning /
  VS Code; only fail/warn findings are emitted as results, with
  `security-severity` and CWE/OWASP properties per rule.

### Tests

Run the test suite (stdlib + pytest only) after building the KB:

```bash
python websec_cli.py build-kb
python -m pytest tests -q
```

CI (`.github/workflows/ci.yml`) runs byte-compilation plus the same suite on
Python 3.10/3.11/3.12.

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

### Live scan usage counter

The web UI shows a **Live Scan Usage** stat (number of scans run through the
site). It is a real counter, not a hardcoded number:

- **Deployed (Vercel):** the counter persists in **Neon Postgres** via the
  Neon HTTP SQL endpoint — no database driver, keeping the project
  standard-library-only. Set the **`DATABASE_URL`** environment variable in
  your Vercel project to your Neon pooled connection string; the table
  (`websec_usage`) is created automatically on first use.
- **Local runs:** without `DATABASE_URL`, the counter falls back to a JSON
  file at `data/usage.json` (gitignored).
- Best-effort: if storage is unreachable, the scan still completes and the UI
  keeps showing the last known count.
- CLI scans (`websec_cli.py scan ...`) do **not** increment the counter — it
  counts scans performed through the site only.

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

The scanner runs **read-only** probes only — it never submits forms, never
modifies data, and performs no DoS/fuzzing. But be precise about what it does
send, because several probes are *active* (they exercise the target):

- **Reflection markers** — a benign inert tag (`<websec_xss_probe_9f6b2>`) and
  a bare single quote sent to candidate parameters to detect unencoded
  reflection (XSS surface) and SQL error signatures.
- **Timing-based blind SQLi probes** — e.g. `' OR SLEEP(2)-- `,
  `WAITFOR DELAY '0:0:2'`, `pg_sleep(2)` (up to
  `config.BLIND_SQLI_MAX_PROBES` per parameter). Read-only, but they do occupy
  a DB connection for ~2 seconds on a vulnerable target.
- **Rate-limit backoff test** — a burst of up to
  `config.RATE_LIMIT_PROBE_COUNT` (5) rapid requests to see whether the target
  throttles. A handful of extra HTTP requests, not a flood.
- **Path-traversal payloads** — `../../../../../../etc/passwd`, `..%2f...`,
  Windows `..\..\win.ini` etc. sent to file/path parameters, checking only for
  *signatures* (`root:x:0:0`, `[extensions]`) in the response. The tool never
  writes or downloads files.
- **Anti-SSRF guard** — every outbound request (and every redirect hop) is
  validated against private/reserved address space before the fetch, so the
  scanner cannot be used to reach internal networks or cloud metadata
  (`169.254.169.254`). Local runs widen this only for the bundled
  127.0.0.1 demo; the deployed UI keeps it locked down.

Scan **only targets you own or are explicitly authorized to test** — scanning
others may violate computer-fraud law.

The generated security tests (`testgen`) are advisory artifacts, not exploits:
every payload is read-only (the same benign probes the engine uses), the raw
Burp template and fuzzer carry an authorization reminder, and the README of the
bundle says to run them only against targets you own or are authorized to test.
`codereview`/`depscan` run fully offline and never execute the code they scan.

## Project layout

```
websec-auditor/
  websec_cli.py                  CLI entrypoint
  api/index.py                   Vercel serverless entrypoint
  websec_auditor/
    config.py                    rule catalog (grounded in standards)
    codereview.py                KB-driven static code review (SQLi, XSS, SSRF...)
    dependscan.py                dependency & advisory (CVE) manifest scan
    testgen.py                   Burp Intruder / fuzzer / curl test generation
    owasptop10.py                OWASP Top 10:2021 scorecard aggregator + renderer
    netsafe.py                   anti-SSRF guard (validates target + redirect hops)
    selfharden.py                KB self-study: audit & harden this app's own config
    knowledge/build_kb.py        builds sources A + B
    scanner/engine.py            deterministic probes (scan / scan_one)
    crawler/crawl.py             site-wide crawler (BFS + metafiles + forms)
    analyzer/analyze.py          joins findings -> KB passages (citations)
    report/render.py             text + HTML + JSON + SARIF report renderers
    demo/flawed_server.py        intentionally-broken server (proof target)
  data/                          generated knowledge base (kb_books.jsonl)
  reports/                       generated HTML reports + testgen bundles (gitignored)
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

The new dev-stage commands are also verified end-to-end:

- **`codereview`** on a sample Python file flagged SQLi via string
  concatenation *and* f-string `execute()` (CWE-89/A03), `pickle.loads`
  (CWE-502/A08), `os.system` (CWE-78/A03), `urlopen(variable)` SSRF
  (CWE-918/A10), hardcoded credentials (CWE-798/A07), and MD5 credential
  hashing (CWE-327/A02) — each with a KB citation (MITRE CWE direct source +
  local book passages) and a remediation, plus a matching OWASP scorecard.
- **`depscan`** on a sample repo flagged `lodash 4.17.20` (CVE-2021-23337),
  `minimist 1.2.5` (CVE-2021-44906), `json5 2.2.0` (CVE-2022-46175),
  `requests 2.28.0` (CVE-2023-32681), `urllib3 1.26.4` (CVE-2023-45803),
  `pillow 10.0.0` (CVE-2023-4421) as exact matches, and `qs ^6.7.0`
  (CVE-2022-24999), `django >=3.2.5,<3.3` (CVE-2022-36359), `werkzeug ~=2.0.0`
  (CVE-2023-25577) as range "possibly affected" warnings — A06 FAIL on the
  scorecard. Manifest formats exercised: `requirements.txt`, `package.json`,
  and the JSON/XML/Gemfile/go formats parse through the same code path.
- **`owasp`** against the demo server produced an A01–A10 scorecard with
  FAIL/WARN/NA per category and the CWEs behind each, integrated into both the
  CLI text report and the HTML/UI report.
- **`testgen`** against the demo server wrote a test bundle (test plan, raw
  Burp Intruder request with positional markers, per-class payload wordlists,
  a stdlib-only fuzzer, and a curl script), and the web UI exposes all of it:
  paste code → **Run Code Review**, paste a manifest → **Scan Dependencies**,
  and **Download Security Tests** for the last scan. All probes stay read-only
  and the bundle warns to run only against owned/authorized targets.
