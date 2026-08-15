"""Analyzer: link raw scanner findings to book/standard passages and produce a
cited, human-readable report. The LLM/explanation layer here is RULE-GROUNDED:
it joins findings to the knowledge base by MULTI-AXIS SCORED matching
(source_id > CWE > OWASP > tags) and quotes the passage -- it does not invent
vulnerabilities. Synonym groups expand keyword overlap for the local library.
"""
from __future__ import annotations
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from websec_auditor import config
from websec_auditor.knowledge.meta import tags_for_cwe


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


def load_local_kb():
    """Load the local-only full-book library (D:\\LocalLibrary). Never deployed."""
    local = []
    if os.path.exists(config.LOCAL_KB_FILE):
        with open(config.LOCAL_KB_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    local.append(json.loads(line))
    return local


def _fattr(f, name, default=""):
    """Read an attribute from a Finding object OR a plain dict."""
    if isinstance(f, dict):
        return f.get(name, default)
    return getattr(f, name, default)


def _split_words(text):
    return set(re.findall(r"[a-z0-9]{4,}", (text or "").lower()))


def _mentioned_groups(text):
    """Synonym groups whose phrase appears in the text (substring, ci)."""
    low = " " + (text or "").lower() + " "
    out = set()
    for grp in config.SYNONYM_GROUPS:
        for phrase in grp:
            if phrase in low:
                out.add(grp)
                break
    return out


MATCH_LABELS = {
    "id": "Direct source",
    "cwe": "CWE match",
    "owasp": "OWASP category match",
    "tags": "Related topic",
    "keywords": "Keyword overlap",
    "synonym": "Synonym match",
}


def _cite_dict(rec, axes):
    return {
        "title": rec.get("title", ""),
        "authority": rec.get("authority") or rec.get("publisher", ""),
        "url": rec.get("url", ""),
        "passage": rec.get("passage", ""),
        "cwe": rec.get("cwe", ""),
        "owasp": rec.get("owasp", ""),
        "tags": rec.get("tags", []),
        "att_ck": rec.get("att_ck", []),
        "capec": rec.get("capec", []),
        "impact": rec.get("impact", []),
        "confidence": rec.get("confidence", ""),
        "match": [MATCH_LABELS.get(a, a) for a in axes],
    }


def lookup(kb, source_id=None, cwe=None, owasp=None, tags=None):
    """Multi-axis scored lookup over the compiled KB.

    Axes (high -> low): exact source_id (10), CWE (5), OWASP category (3),
    tags (2). CWE/OWASP/tag axes only apply to source_type A (standards) to
    avoid book-catalog noise; a CWE match alone still qualifies (score >= 3).
    Returns [(score, axes, rec), ...] sorted desc.
    """
    if source_id:
        for rec in kb:
            if rec.get("id") == source_id:
                return [(10, ["id"], rec)]
    scored = []
    for rec in kb:
        if rec.get("source_type") != "A":
            continue
        score, axes = 0, []
        if cwe and rec.get("cwe") == cwe:
            score += 5
            axes.append("cwe")
        if owasp and rec.get("owasp") == owasp:
            score += 3
            axes.append("owasp")
        if tags:
            rtags = {t.lower() for t in rec.get("tags") or []}
            if tags & rtags:
                score += 2
                axes.append("tags")
        if score >= 3:
            scored.append((score, axes, rec))
    scored.sort(key=lambda x: -x[0])
    return scored


def _build_local_index(local):
    """Precompute per-record word sets + synonym groups ONCE so per-finding
    scoring is cheap (regex/substring work is done a single time)."""
    index = []
    for rec in local:
        passage = rec.get("passage", "")
        index.append({
            "rec": rec,
            "words": _split_words(passage),
            "groups": _mentioned_groups(passage),
            "tags": {t.lower() for t in rec.get("tags") or []},
            "cwe": rec.get("cwe", ""),
            "owasp": rec.get("owasp", ""),
        })
    return index


def _local_citations(local_index, finding):
    """Pick the 1-2 most relevant local-book passages for a finding, ranked by
    CWE match, OWASP, tags, keyword overlap, then synonym-group overlap.
    `local_index` is the precomputed output of _build_local_index()."""
    if not local_index:
        return []
    cwe = _fattr(finding, "cwe", "")
    owasp = _fattr(finding, "owasp", "")
    text = (_fattr(finding, "name", "") + " " + _fattr(finding, "detail", "")).lower()
    keywords = _split_words(text)
    tags = {t.lower() for t in tags_for_cwe(cwe)}
    groups = _mentioned_groups(text)

    scored = []
    for ent in local_index:
        rec = ent["rec"]
        score, axes = 0, []
        if cwe and ent["cwe"] == cwe:
            score += 5
            axes.append("cwe")
        if owasp and ent["owasp"] == owasp:
            score += 3
            axes.append("owasp")
        inter = tags & ent["tags"]
        if inter:
            score += 2
            axes.append("tags")
        n = len(keywords & ent["words"])
        if n:
            score += min(n, 4)
            axes.append("keywords")
        shared = groups & ent["groups"]
        if shared:
            score += min(2 * len(shared), 4)
            axes.append("synonym")
        if score >= 3:
            scored.append((score, axes, rec))
    scored.sort(key=lambda x: -x[0])
    return [_cite_dict(rec, axes) for _, axes, rec in scored[:2]]


def analyze(scan_result, kb=None, local_kb=None):
    kb = kb if kb is not None else load_kb()
    local_kb = local_kb if local_kb is not None else load_local_kb()
    local_index = _build_local_index(local_kb)
    enriched = []
    for f in scan_result.findings:
        entry = {
            "finding": f.to_dict() if hasattr(f, "to_dict") else f,
            "citations": [],
        }
        source_id = _fattr(f, "source_id", "")
        cwe = _fattr(f, "cwe", "")
        owasp = _fattr(f, "owasp", "")
        tags = {t.lower() for t in tags_for_cwe(cwe)}
        # primary: multi-axis scored match
        for score, axes, rec in lookup(kb, source_id=source_id, cwe=cwe,
                                       owasp=owasp, tags=tags):
            entry["citations"].append(_cite_dict(rec, axes))
        # local full-book passages (your own copies, local-only)
        for c in _local_citations(local_index, f):
            entry["citations"].append(c)
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
