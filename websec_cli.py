#!/usr/bin/env python
"""websec-auditor CLI.

Usage:
  python websec_cli.py build-kb            # build the book/standard knowledge base
  python websec_cli.py scan URL [--html]   # scan a target you OWN/are authorized to test
  python websec_cli.py self-harden [--audit-only]  # audit & harden this app's own config
  python websec_cli.py demo                # start the flawed demo server (proof target)
  python websec_cli.py library             # show the local full-book library stats
  python websec_cli.py ingest-book [PATH]  # index a full local book (default: D:\\LocalLibrary)

  python websec_cli.py codereview PATH [--html]   # KB-driven static code review (SQLi, XSS, SSRF, insecure auth...)
  python websec_cli.py depscan PATH [--html]      # dependency & advisory (CVE) scan of manifests
  python websec_cli.py owasp URL [--crawl] [--html]  # OWASP Top 10:2021 assessment
  python websec_cli.py testgen URL [--crawl] [--out DIR]  # generate Burp/fuzz/curl security tests

  Report formats (scan / owasp / codereview / depscan):
    --html   write a self-contained HTML report
    --json   write machine-readable JSON (reports/report_<ts>.json)
    --sarif  write SARIF 2.1.0 for code-scanning tools (reports/report_<ts>.sarif)


Scanning targets you do not own/authorize may violate computer-fraud law.
This tool only runs safe, read-only probes.
"""
import argparse
import os
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from websec_auditor import config
from websec_auditor.scanner import engine
from websec_auditor.analyzer.analyze import analyze as run_analyze
from websec_auditor.report import render


def _report_formats(args):
    fmts = []
    if getattr(args, "html", False):
        fmts.append("html")
    if getattr(args, "json", False):
        fmts.append("json")
    if getattr(args, "sarif", False):
        fmts.append("sarif")
    return fmts


def _custom_headers(args):
    custom_headers = {}
    if getattr(args, "cookie", None):
        custom_headers["Cookie"] = args.cookie
    if getattr(args, "header", None):
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
    return custom_headers


def _write_report(enriched, target, fmt=None):
    """Write HTML / JSON / SARIF report(s) into reports/. `fmt` may be a string
    ("html", "json", "sarif") or an iterable of formats; defaults to html."""
    from datetime import datetime
    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if isinstance(fmt, str):
        formats = [fmt] if fmt != "all" else ["html", "json", "sarif"]
    else:
        formats = fmt or ["html"]
    out = None
    for f in formats:
        if f == "json":
            out = os.path.join("reports", f"report_{ts}.json")
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(render.render_json(enriched, target))
        elif f == "sarif":
            out = os.path.join("reports", f"report_{ts}.sarif")
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(render.render_sarif(enriched, target))
        else:
            out = os.path.join("reports", f"report_{ts}.html")
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(render.render_html(enriched, target))
        print(f"[websec-auditor] {f.upper()} report -> {out}")
    if "html" in formats:
        try:
            webbrowser.open(out)
        except Exception:
            pass


def _write_test_package(outdir, artifacts):
    from datetime import datetime
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    plan = os.path.join(outdir, f"TEST_PLAN_{ts}.md")
    burp = os.path.join(outdir, f"burp_intruder_{ts}.txt")
    fuzz = os.path.join(outdir, f"websec_fuzzer_{ts}.py")
    curl = os.path.join(outdir, f"tests_{ts}.sh")
    with open(plan, "w", encoding="utf-8") as f:
        f.write(artifacts["plan"])
    with open(burp, "w", encoding="utf-8") as f:
        f.write(artifacts["burp_request"])
    with open(fuzz, "w", encoding="utf-8") as f:
        f.write(artifacts["fuzz_py"])
    with open(curl, "w", encoding="utf-8") as f:
        f.write(artifacts["curl_sh"])
    files = [plan, burp, fuzz, curl]
    for cat in artifacts["payloads"]:
        p = os.path.join(outdir, f"payloads_{cat}_{ts}.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(artifacts["payloads"][cat]) + "\n")
        files.append(p)
    print(f"[websec-auditor] Test package for {artifacts['target']} "
          f"(classes: {', '.join(artifacts['categories']) or 'none'})")
    for p in files:
        print(f"  -> {os.path.abspath(p)}")
    print("  Run only against targets you own or are authorized to test.")


def main():
    from websec_auditor import netsafe
    with netsafe.private_allowed(True):
        _main()


def _main():
    ap = argparse.ArgumentParser(prog="websec-auditor")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("build-kb")
    pscan = sub.add_parser("scan")
    pscan.add_argument("url")
    pscan.add_argument("--html", action="store_true", help="write an HTML report")
    pscan.add_argument("--json", action="store_true", help="write a JSON report")
    pscan.add_argument("--sarif", action="store_true", help="write a SARIF 2.1.0 report")
    pscan.add_argument("--crawl", action="store_true",
                       help="site-wide scan: crawl same-origin pages and scan each")
    pscan.add_argument("--cookie", help="Custom session cookie string (e.g. 'session=12345')")
    pscan.add_argument("--header", action="append", help="Custom request header (e.g. 'Authorization: Bearer token')")
    sub.add_parser("webui").add_argument("--port", type=int, default=8000)
    psh = sub.add_parser("self-harden", help="KB self-study: audit & harden this app's own config")
    psh.add_argument("--audit-only", action="store_true",
                     help="only audit the app's own posture; do not write changes")
    sub.add_parser("library", help="list locally-indexed full books (D:\\LocalLibrary)")
    ping = sub.add_parser("ingest-book", help="index a full locally-owned book (PDF/TXT/MD) or folder")
    ping.add_argument("path", nargs="?", default=None,
                      help="path to a book file or folder (default: D:\\LocalLibrary)")
    pcr = sub.add_parser("codereview", help="KB-driven static code review (SQLi, XSS, SSRF, insecure auth, ...)")
    pcr.add_argument("path", help="source file or directory to review")
    pcr.add_argument("--html", action="store_true", help="write an HTML report")
    pcr.add_argument("--json", action="store_true", help="write a JSON report")
    pcr.add_argument("--sarif", action="store_true", help="write a SARIF 2.1.0 report")
    pds = sub.add_parser("depscan", help="dependency & advisory (CVE) scan of manifests")
    pds.add_argument("path", help="manifest file or project directory")
    pds.add_argument("--html", action="store_true", help="write an HTML report")
    pds.add_argument("--json", action="store_true", help="write a JSON report")
    pds.add_argument("--sarif", action="store_true", help="write a SARIF 2.1.0 report")
    pow = sub.add_parser("owasp", help="OWASP Top 10:2021 assessment of a target")
    pow.add_argument("url")
    pow.add_argument("--crawl", action="store_true", help="crawl same-origin pages and scan each")
    pow.add_argument("--html", action="store_true", help="write an HTML report")
    pow.add_argument("--json", action="store_true", help="write a JSON report")
    pow.add_argument("--sarif", action="store_true", help="write a SARIF 2.1.0 report")
    pow.add_argument("--cookie", help="Custom session cookie string (e.g. 'session=12345')")
    pow.add_argument("--header", action="append", help="Custom request header (e.g. 'Authorization: Bearer token')")
    ptg = sub.add_parser("testgen", help="generate security tests (Burp Intruder, payloads, fuzzer, curl)")
    ptg.add_argument("url")
    ptg.add_argument("--crawl", action="store_true", help="crawl to discover entry points first")
    ptg.add_argument("--out", default="reports/tests", help="output directory (default: reports/tests)")
    ptg.add_argument("--cookie", help="Custom session cookie string (e.g. 'session=12345')")
    ptg.add_argument("--header", action="append", help="Custom request header (e.g. 'Authorization: Bearer token')")
    sub.add_parser("demo")
    args = ap.parse_args()

    if args.cmd == "build-kb":
        from websec_auditor.knowledge import build_kb
        build_kb.write_kb()
        return

    if args.cmd == "webui":
        import threading
        from websec_auditor import webui
        from websec_auditor.demo import flawed_server
        threading.Thread(target=flawed_server.serve, daemon=True).start()
        webui.serve(args.port)
        return

    if args.cmd == "demo":
        from websec_auditor.demo import flawed_server
        flawed_server.serve()
        return

    if args.cmd == "library":
        from websec_auditor.knowledge import build_kb
        stats = build_kb.library_stats()
        print(f"[websec-auditor] Local Full-Book Library ({config.LOCAL_BOOKS_DIR})")
        print(f"  books:    {stats['books']}")
        print(f"  passages: {stats['passages']}")
        print("  (local-only: never deployed, never redistributed)")
        return

    if args.cmd == "ingest-book":
        from websec_auditor.knowledge import build_kb
        path = args.path or config.LOCAL_BOOKS_DIR
        os.makedirs(config.LOCAL_BOOKS_DIR, exist_ok=True)
        res = build_kb.ingest_book_file(path)
        print(f"[websec-auditor] Ingested: {res.get('title', path)}")
        print(f"  passages: {res['passages']}  chars: {res['chars']}")
        stats = build_kb.library_stats()
        print(f"  library now: {stats['books']} books, {stats['passages']} passages")
        print("  The app now quotes these full books on local scans.")
        return

    if args.cmd == "self-harden":
        from websec_auditor import selfharden
        before = selfharden.audit_state()
        print(f"[websec-auditor] KB Self-Study audit: {len(before)} findings\n")
        for f in before:
            sev = f.get("status", "info")
            mark = {"fail": "FAIL", "warn": "WARN", "pass": "PASS"}.get(sev, sev.upper())
            print(f"  [{mark}] {f.get('name', '')}")
            print(f"        {f.get('detail', '')}")
            cit = f.get("citation") or {}
            if cit.get("passage"):
                print(f"        Source: {cit.get('title', '')} - \"{cit.get('passage', '')}\"")
            print()
        if args.audit_only:
            print("[websec-auditor] audit-only mode; nothing written.")
            return
        print("[websec-auditor] applying KB-grounded hardening...")
        summary = selfharden.apply_hardening()
        for k in ("added", "fixed", "removed"):
            for item in summary.get(k, []):
                print(f"  + {item}")
        if summary.get("readonly"):
            print("  (read-only filesystem: changes could not be persisted)")
        print("\n[websec-auditor] re-auditing after hardening...")
        after = selfharden.verify_state()
        fails = [f for f in after if f.get("status") in ("fail", "warn")]
        print(f"  remaining fail/warn findings: {len(fails)}")
        for f in fails:
            print(f"  [{f.get('status', 'warn').upper()}] {f.get('name', '')}")
        return

    if args.cmd == "scan":
        custom_headers = {}
        if args.cookie:
            custom_headers["Cookie"] = args.cookie
        if args.header:
            for h in args.header:
                if ":" in h:
                    k, v = h.split(":", 1)
                    custom_headers[k.strip()] = v.strip()

        if args.crawl:
            print(f"[websec-auditor] site-wide scan of {args.url} (owned/authorized target only)")
            from websec_auditor.crawler import scan_site
            res = scan_site(args.url, custom_headers=custom_headers)
        else:
            print(f"[websec-auditor] scanning {args.url} (owned/authorized target only)")
            res = engine.scan(args.url, custom_headers=custom_headers)
        enriched = run_analyze(res)
        text = render.render_text(enriched, args.url)
        print(text)
        if args.html or args.json or args.sarif:
            _write_report(enriched, args.url, _report_formats(args))
        return

    if args.cmd == "codereview":
        from websec_auditor import codereview
        print(f"[websec-auditor] KB-driven static code review of {args.path}")
        findings = codereview.review_path(args.path)
        res = engine.ScanResult(target=f"code review: {args.path}")
        for f in findings:
            res.add(f)
        enriched = run_analyze(res)
        print(render.render_text(enriched, f"CODE REVIEW: {args.path}"))
        if not findings:
            print("[websec-auditor] No code-review patterns matched.")
        if args.html or args.json or args.sarif:
            _write_report(enriched, f"code review: {args.path}", _report_formats(args))
        return

    if args.cmd == "depscan":
        from websec_auditor import dependscan
        print(f"[websec-auditor] dependency & advisory scan of {args.path}")
        findings = dependscan.scan_path(args.path)
        res = engine.ScanResult(target=f"dependency scan: {args.path}")
        for f in findings:
            res.add(f)
        enriched = run_analyze(res)
        print(render.render_text(enriched, f"DEPENDENCY SCAN: {args.path}"))
        if not findings:
            print("[websec-auditor] No known-vulnerable dependencies matched the local advisory seed.")
        if args.html or args.json or args.sarif:
            _write_report(enriched, f"dependency scan: {args.path}", _report_formats(args))
        return

    if args.cmd == "owasp":
        custom_headers = _custom_headers(args)
        if args.crawl:
            print(f"[websec-auditor] OWASP assessment (site-wide) of {args.url} (owned/authorized target only)")
            from websec_auditor.crawler import scan_site
            res = scan_site(args.url, custom_headers=custom_headers)
        else:
            print(f"[websec-auditor] OWASP assessment of {args.url} (owned/authorized target only)")
            res = engine.scan(args.url, custom_headers=custom_headers)
        enriched = run_analyze(res)
        print(render.render_text(enriched, args.url))
        if args.html or args.json or args.sarif:
            _write_report(enriched, args.url, _report_formats(args))
        return

    if args.cmd == "testgen":
        custom_headers = _custom_headers(args)
        if args.crawl:
            print(f"[websec-auditor] scanning {args.url} to collect entry points (owned/authorized target only)")
            from websec_auditor.crawler import scan_site
            res = scan_site(args.url, custom_headers=custom_headers)
        else:
            res = engine.scan(args.url, custom_headers=custom_headers)
        enriched = run_analyze(res)
        from websec_auditor import testgen
        artifacts = testgen.generate(args.url, findings=res, enriched=enriched)
        _write_test_package(args.out, artifacts)
        return

    ap.print_help()


if __name__ == "__main__":
    main()
