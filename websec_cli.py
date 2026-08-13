#!/usr/bin/env python
"""websec-auditor CLI.

Usage:
  python websec_cli.py build-kb            # build the book/standard knowledge base
  python websec_cli.py scan URL [--html]   # scan a target you OWN/are authorized to test
  python websec_cli.py demo                # start the flawed demo server (proof target)

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


def main():
    ap = argparse.ArgumentParser(prog="websec-auditor")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("build-kb")
    pscan = sub.add_parser("scan")
    pscan.add_argument("url")
    pscan.add_argument("--html", action="store_true", help="write an HTML report")
    pscan.add_argument("--crawl", action="store_true",
                       help="site-wide scan: crawl same-origin pages and scan each")
    pscan.add_argument("--cookie", help="Custom session cookie string (e.g. 'session=12345')")
    pscan.add_argument("--header", action="append", help="Custom request header (e.g. 'Authorization: Bearer token')")
    sub.add_parser("webui").add_argument("--port", type=int, default=8000)
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
        if args.html:
            from datetime import datetime
            os.makedirs("reports", exist_ok=True)
            out = os.path.join("reports", f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            with open(out, "w", encoding="utf-8") as f:
                f.write(render.render_html(enriched, args.url))
            print(f"\n[websec-auditor] HTML report -> {out}")
            try:
                webbrowser.open(out)
            except Exception:
                pass
        return

    ap.print_help()


if __name__ == "__main__":
    main()
