"""KB-compliance guard: every Finding in the codebase must cite a real KB
record id and must not assert a severity higher than its KB source allows.
This keeps the auditor grounded in the compiled Knowledge Base (books and
standards) instead of ad-hoc claims."""
import ast
import glob
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KB_PATH = os.path.join(ROOT, "data", "kb_books.jsonl")
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _load_kb():
    kb = {}
    with open(KB_PATH, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            kb[rec["id"]] = rec
    return kb


def _findings():
    for fpath in glob.glob(os.path.join(ROOT, "websec_auditor", "**", "*.py"), recursive=True):
        with open(fpath, encoding="utf-8") as fh:
            try:
                tree = ast.parse(fh.read())
            except SyntaxError:
                continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "Finding"):
                continue
            kw = {}
            for k in node.keywords:
                kw[k.arg] = k.value.value if isinstance(k.value, ast.Constant) else None
            if kw.get("source_id") is None:
                continue
            yield fpath, node.lineno, kw


def test_every_finding_cites_a_real_kb_record():
    kb = _load_kb()
    bad = []
    for fpath, lineno, kw in _findings():
        if kw["source_id"] not in kb:
            bad.append((os.path.relpath(fpath, ROOT), lineno, kw["source_id"]))
    assert bad == [], f"Finding source_ids not in KB: {bad}"


def test_finding_severity_never_exceeds_its_kb_source():
    kb = _load_kb()
    bad = []
    for fpath, lineno, kw in _findings():
        sev = kw.get("severity")
        if sev is None or sev not in SEV_RANK:
            continue
        rec = kb.get(kw["source_id"]) or {}
        known = [s for s in [rec.get("severity")]
                 + [ru.get("severity") for ru in (rec.get("scan_rules") or [])]
                 if s in SEV_RANK]
        if not known:
            continue  # KB record does not rate the severity; nothing to exceed
        if SEV_RANK[sev] > max(SEV_RANK[s] for s in known):
            bad.append((os.path.relpath(fpath, ROOT), lineno, kw["source_id"], sev, known))
    assert bad == [], f"Findings asserting severity above KB source: {bad}"


def test_error_page_leak_is_grounded_in_cwe_209():
    # WSTG-ERRH + CWE-209: the 4xx/5xx body inspection must cite the KB record
    # that covers unhandled exception traces and debug banners.
    from websec_auditor.scanner.engine import ScanResult, check_error_body_leak

    res = ScanResult(target="https://example.test")
    check_error_body_leak(res, 500, "Traceback (most recent call last):")
    leaks = [f for f in res.findings if f.check == "error_leak"]
    assert leaks and leaks[0].source_id == "CWE-209-ERROR-LEAK"
    assert leaks[0].severity == "medium"
