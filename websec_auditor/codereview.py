"""KB-driven static code review (OWASP Code Review Guide / SAST).

The primary rule set is loaded from the compiled Knowledge Base (scan_rules of
type "code_review"), so every finding is grounded in a book/standard passage;
if the KB has not been built yet a config fallback set is used. Review works on
a source tree (path) or on pasted source text (web UI / snippets).

SAFETY: static, read-only pattern matching. It flags *potential* weaknesses
(SAST-style) that must be triaged; no code is executed and nothing is sent
over the network.
"""
from __future__ import annotations
import os
import re

from websec_auditor import config
from websec_auditor.scanner.engine import Finding
from websec_auditor.scanner.engine import load_kb_rules


def load_rules():
    """Return code-review rules from the KB; fall back to config if KB is empty."""
    kb_rules = [r for r in load_kb_rules() if r.get("type") == "code_review"]
    if kb_rules:
        return kb_rules
    return [dict(r) for r in config.CODE_REVIEW_FALLBACK_RULES]


def _lang_for(path):
    return config.LANG_BY_EXT.get(os.path.splitext(path)[1].lower(), "generic")


def _rule_applies(rule, path, lang):
    langs = rule.get("languages")
    if not langs:
        return True
    return lang in langs or "generic" in langs


def _match_snippet(lines, line_no, context=config.CODE_REVIEW_CONTEXT_LINES):
    """Return a small code snippet (with line numbers) around a match."""
    start = max(0, line_no - 1 - context)
    end = min(len(lines), line_no + context)
    out = []
    for i in range(start, end):
        out.append(f"  {i + 1}: {lines[i].rstrip()}")
    return "\n".join(out)


def review_text(text, filename="<paste>", rules=None):
    """Static-review a block of pasted source text. Returns a list of Finding."""
    rules = rules if rules is not None else load_rules()
    lang = _lang_for(filename or "<paste>")
    lines = (text or "").splitlines()
    findings = []
    for rule in rules:
        if not _rule_applies(rule, filename or "", lang):
            continue
        try:
            pattern = re.compile(rule["pattern"], re.IGNORECASE)
        except re.error:
            continue
        for i, line in enumerate(lines):
            m = pattern.search(line)
            if m:
                findings.append(_build_finding(rule, filename, lang, i + 1, line, lines))
    return _dedupe(findings)


def review_path(path, rules=None):
    """Recursively static-review a file or directory. Returns a list of Finding."""
    rules = rules if rules is not None else load_rules()
    findings = []
    files = _iter_source_files(path)
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, UnicodeError):
            continue
        findings.extend(review_text(text, fpath, rules))
    return _dedupe(findings)


def review(path_or_text, filename="<paste>", rules=None):
    """Entry point: if `path_or_text` looks like an existing filesystem path it
    reviews the tree; otherwise it treats the value as pasted source text."""
    if os.path.exists(path_or_text):
        return review_path(path_or_text, rules), "path"
    return review_text(path_or_text, filename, rules), "text"


def _iter_source_files(path):
    if os.path.isfile(path):
        if _is_source_file(path):
            yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in config.CODE_REVIEW_SKIP_DIRS]
        for name in files:
            fpath = os.path.join(root, name)
            if _is_source_file(fpath):
                yield fpath
    return


def _is_source_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext not in config.LANG_BY_EXT:
        return False
    try:
        return os.path.getsize(path) <= config.CODE_REVIEW_MAX_FILE_BYTES
    except OSError:
        return False


def _build_finding(rule, fpath, lang, line_no, line, lines):
    detail = (
        f"{fpath}:{line_no} [{lang}] -- {rule.get('description', rule['name'])}\n"
        + _match_snippet(lines, line_no)
    )
    return Finding(
        check="code-review",
        name=rule.get("name", "code-review-finding"),
        status="fail",
        severity=rule.get("severity", "medium"),
        detail=detail,
        source_id=rule.get("source_id", "OWASP-CODE-REVIEW-GUIDE"),
        cwe=rule.get("cwe", ""),
        owasp=rule.get("owasp", ""),
        remediation=rule.get("remediation", ""),
        confidence=rule.get("confidence", "low"),
    )


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.check, f.name, f.detail.splitlines()[0] if f.detail else f.name)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
