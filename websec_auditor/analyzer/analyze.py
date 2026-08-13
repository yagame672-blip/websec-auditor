"""Analyzer: link raw scanner findings to book/standard passages and produce a
cited, human-readable report. The LLM/explanation layer here is RULE-GROUNDED:
it joins findings to the knowledge base by source_id/CWE and quotes the
passage -- it does not invent vulnerabilities.
"""
from __future__ import annotations
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from websec_auditor import config


def load_kb():
    kb = []
    if not os.path.exists(config.KB_FILE):
        return kb
    with open(config.KB_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                kb.append(json.loads(line))
    return kb


def lookup(kb, source_id=None, cwe=None):
    hits = []
    for rec in kb:
        if source_id and rec.get("id") == source_id:
            hits.append(rec)
        elif cwe and rec.get("cwe") == cwe and rec.get("source_type") == "A":
            hits.append(rec)
    return hits


def analyze(scan_result, kb=None):
    kb = kb if kb is not None else load_kb()
    enriched = []
    for f in scan_result.findings:
        entry = {
            "finding": f.to_dict() if hasattr(f, "to_dict") else f,
            "citations": [],
        }
        # primary: by source_id
        hits = lookup(kb, source_id=f.source_id) if hasattr(f, "source_id") else []
        # fallback: by CWE
        if not hits and hasattr(f, "cwe"):
            hits = lookup(kb, cwe=f.cwe)
            entry["citations"].append({
                "title": h.get("title", ""),
                "authority": h.get("authority") or h.get("publisher", ""),
                "url": h.get("url", ""),
                "passage": h.get("passage", ""),
                "cwe": h.get("cwe", ""),
                "owasp": h.get("owasp", ""),
            })
        enriched.append(entry)
    return enriched


def summarize(enriched):
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for e in enriched:
        sev = e["finding"].get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


if __name__ == "__main__":
    import sys
    from websec_auditor.scanner import engine
    tgt = sys.argv[1] if len(sys.argv) > 1 else "https://self-signed.badssl.com"
    r = engine.scan(tgt)
    en = analyze(r)
    print(json.dumps({"summary": summarize(en), "findings": en}, indent=2, default=str))
