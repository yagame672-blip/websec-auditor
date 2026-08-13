"""Site-wide crawling for websec-auditor (same-origin, bounded, read-only)."""
from websec_auditor.crawler.crawl import crawl, scan_site

__all__ = ["crawl", "scan_site"]
