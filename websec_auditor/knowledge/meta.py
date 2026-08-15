"""CWE metadata taxonomy for websec-auditor.

Maps every CWE identifier used by the KB/scanner to richer structured metadata:
human tags (used by multi-axis matching), MITRE ATT&CK technique(s), CAPEC attack
patterns, CIA impact, a severity baseline, and the default authority confidence.
Centralizing this lets the analyzer match on more axes than source_id/CWE and
lets reports display context (tags / ATT&CK / CAPEC / impact) without storing
the table in every record.
"""
from __future__ import annotations

CWE_META = {
    "CWE-16": {"tags": ["misconfiguration", "headers", "hardening"],
               "att_ck": [], "capec": ["CAPEC-2"],
               "impact": ["Confidentiality", "Integrity"], "severity": "low"},
    "CWE-20": {"tags": ["input-validation", "injection"],
               "att_ck": [], "capec": ["CAPEC-10"],
               "impact": ["Integrity", "Availability"], "severity": "medium"},
    "CWE-22": {"tags": ["path-traversal", "file", "input-validation", "lfi"],
               "att_ck": ["T1006"], "capec": ["CAPEC-126"],
               "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-78": {"tags": ["command-injection", "rce", "input-validation"],
               "att_ck": ["T1059"], "capec": ["CAPEC-88"],
               "impact": ["Confidentiality", "Integrity", "Availability"], "severity": "high"},
    "CWE-79": {"tags": ["xss", "injection", "client-side"],
               "att_ck": ["T1059.007"], "capec": ["CAPEC-63"],
               "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-89": {"tags": ["sql-injection", "injection", "database"],
               "att_ck": ["T1190"], "capec": ["CAPEC-66"],
               "impact": ["Confidentiality", "Integrity", "Availability"], "severity": "high"},
    "CWE-94": {"tags": ["code-injection", "rce"],
               "att_ck": ["T1059"], "capec": ["CAPEC-242"],
               "impact": ["Confidentiality", "Integrity", "Availability"], "severity": "high"},
    "CWE-116": {"tags": ["encoding", "output-encoding", "input-validation"],
                "att_ck": [], "capec": ["CAPEC-267"],
                "impact": ["Integrity"], "severity": "medium"},
    "CWE-200": {"tags": ["information-disclosure", "fingerprinting", "banner"],
                "att_ck": ["T1592"], "capec": ["CAPEC-118"],
                "impact": ["Confidentiality"], "severity": "low"},
    "CWE-250": {"tags": ["privilege", "least-privilege", "process"],
                "att_ck": [], "capec": ["CAPEC-162"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-285": {"tags": ["access-control", "authorization", "broken-access-control"],
                "att_ck": [], "capec": ["CAPEC-112"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-287": {"tags": ["authentication", "credentials", "broken-authentication"],
                "att_ck": ["T1078"], "capec": ["CAPEC-49"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-295": {"tags": ["tls", "certificate", "trust"],
                "att_ck": ["T1557"], "capec": ["CAPEC-94"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-307": {"tags": ["brute-force", "rate-limiting", "authentication"],
                "att_ck": ["T1110"], "capec": ["CAPEC-49"],
                "impact": ["Confidentiality"], "severity": "medium"},
    "CWE-312": {"tags": ["mobile", "data-at-rest", "privacy"],
                "att_ck": ["T1552"], "capec": [],
                "impact": ["Confidentiality"], "severity": "high"},
    "CWE-319": {"tags": ["transport", "tls", "crypto"],
                "att_ck": ["T1040"], "capec": ["CAPEC-117"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-326": {"tags": ["crypto", "weak-algorithms"],
                "att_ck": [], "capec": ["CAPEC-20"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-327": {"tags": ["crypto", "broken-algorithm"],
                "att_ck": [], "capec": ["CAPEC-20"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-352": {"tags": ["csrf", "session", "state-changing"],
                "att_ck": [], "capec": ["CAPEC-62"],
                "impact": ["Integrity", "Availability"], "severity": "medium"},
    "CWE-384": {"tags": ["session-fixation", "session"],
                "att_ck": [], "capec": ["CAPEC-61"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-400": {"tags": ["dos", "resource-exhaustion", "availability"],
                "att_ck": ["T1498"], "capec": ["CAPEC-125"],
                "impact": ["Availability"], "severity": "medium"},
    "CWE-434": {"tags": ["file-upload", "malware", "rce"],
                "att_ck": ["T1505.003"], "capec": ["CAPEC-650"],
                "impact": ["Confidentiality", "Integrity", "Availability"], "severity": "high"},
    "CWE-436": {"tags": ["mime", "content-type", "misconfiguration"],
                "att_ck": [], "capec": [],
                "impact": ["Integrity"], "severity": "medium"},
    "CWE-444": {"tags": ["smuggling", "protocol", "http"],
                "att_ck": ["T1190"], "capec": ["CAPEC-33"],
                "impact": ["Integrity", "Confidentiality"], "severity": "high"},
    "CWE-502": {"tags": ["deserialization", "rce", "input-validation"],
                "att_ck": ["T1203"], "capec": ["CAPEC-586"],
                "impact": ["Confidentiality", "Integrity", "Availability"], "severity": "high"},
    "CWE-521": {"tags": ["passwords", "authentication", "policy"],
                "att_ck": ["T1110"], "capec": ["CAPEC-600"],
                "impact": ["Confidentiality"], "severity": "medium"},
    "CWE-524": {"tags": ["cache", "session", "privacy"],
                "att_ck": [], "capec": [],
                "impact": ["Confidentiality"], "severity": "medium"},
    "CWE-548": {"tags": ["directory-listing", "information-disclosure"],
                "att_ck": ["T1083"], "capec": ["CAPEC-127"],
                "impact": ["Confidentiality"], "severity": "medium"},
    "CWE-601": {"tags": ["redirect", "open-redirect", "phishing"],
                "att_ck": ["T1566.002"], "capec": ["CAPEC-38"],
                "impact": ["Integrity"], "severity": "medium"},
    "CWE-614": {"tags": ["cookies", "session", "transport"],
                "att_ck": ["T1539"], "capec": [],
                "impact": ["Confidentiality"], "severity": "high"},
    "CWE-639": {"tags": ["idor", "access-control", "authorization"],
                "att_ck": ["T1590"], "capec": ["CAPEC-87"],
                "impact": ["Confidentiality"], "severity": "high"},
    "CWE-693": {"tags": ["isolation", "headers", "hardening"],
                "att_ck": [], "capec": [],
                "impact": ["Confidentiality", "Integrity"], "severity": "low"},
    "CWE-749": {"tags": ["http-methods", "verb-tampering"],
                "att_ck": ["T1599"], "capec": ["CAPEC-272"],
                "impact": ["Confidentiality", "Integrity"], "severity": "medium"},
    "CWE-778": {"tags": ["logging", "timeouts", "resource"],
                "att_ck": [], "capec": [],
                "impact": ["Availability"], "severity": "medium"},
    "CWE-798": {"tags": ["credentials", "secrets", "hardcoded"],
                "att_ck": ["T1078.001"], "capec": ["CAPEC-191"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-918": {"tags": ["ssrf", "server-side", "input-validation"],
                "att_ck": ["T1190"], "capec": ["CAPEC-664"],
                "impact": ["Confidentiality", "Integrity"], "severity": "high"},
    "CWE-942": {"tags": ["cors", "cross-domain"],
                "att_ck": [], "capec": ["CAPEC-21"],
                "impact": ["Confidentiality"], "severity": "medium"},
    "CWE-1004": {"tags": ["cookies", "xss", "session"],
                 "att_ck": ["T1539"], "capec": [],
                 "impact": ["Confidentiality"], "severity": "high"},
    "CWE-1021": {"tags": ["clickjacking", "ui-redress"],
                 "att_ck": ["T1204.001"], "capec": ["CAPEC-103"],
                 "impact": ["Integrity"], "severity": "medium"},
    "CWE-1104": {"tags": ["supply-chain", "sbom", "dependencies"],
                 "att_ck": ["T1195"], "capec": ["CAPEC-437"],
                 "impact": ["Confidentiality", "Integrity", "Availability"], "severity": "medium"},
    "CWE-1275": {"tags": ["csrf", "cookies", "session"],
                 "att_ck": [], "capec": ["CAPEC-62"],
                 "impact": ["Integrity"], "severity": "medium"},
}

# Confidence by source type: how authoritative the passage is for its CWE.
SOURCE_CONFIDENCE = {"A": "high", "B": "medium", "C": "high"}


def enrich_meta(rec: dict) -> dict:
    """Fill tags/att_ck/capec/impact/severity/confidence onto a record when they
    are missing, derived from its CWE (and source type). Mutates and returns rec."""
    cwe = rec.get("cwe") or ""
    meta = CWE_META.get(cwe)
    if meta:
        for key, val in meta.items():
            rec.setdefault(key, list(val) if isinstance(val, (list, tuple)) else val)
    if "confidence" not in rec:
        rec["confidence"] = SOURCE_CONFIDENCE.get(rec.get("source_type", "A"), "medium")
    return rec


def tags_for_cwe(cwe: str):
    """Tags for a CWE (used to match findings without a source_id to passages)."""
    meta = CWE_META.get(cwe or "")
    return list(meta["tags"]) if meta else []
