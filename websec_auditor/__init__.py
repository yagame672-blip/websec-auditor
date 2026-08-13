"""websec-auditor: a book-grounded web security auditor.

Detection rules are curated directly from authoritative security literature
(OWASP Top 10:2021, MITRE CWE, OWASP ASVS). The analyzer layer only *explains
and cites* findings using passages from that knowledge base -- it never invents
vulnerabilities. Deterministic probes do the actual detection.
"""
__version__ = "0.1.0"
