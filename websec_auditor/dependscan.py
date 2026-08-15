"""Dependency & advisory scanner (OWASP A06 Vulnerable and Outdated Components,
OWASP SCVS / Supply-chain).

Parses common dependency manifests (requirements.txt, package.json, package-lock,
yarn.lock, composer.*, Gemfile*.lock, pom.xml, build.gradle, go.mod/go.sum,
Pipfile, pyproject.toml, setup.py) and checks each resolved version against a
LOCAL advisory seed in config.CVE_ADVISORIES. Fully offline and read-only.

Honest limits: the seed is small and curated. It is a smoke-test for known
high-profile CVEs (Log4Shell, Spring4Shell, prototype-pollution chains), not a
replacement for OSV/NVD/GHSA. Range-only declarations produce a "possibly
affected" finding; lockfile versions produce exact matches.
"""
from __future__ import annotations
import json
import os
import re

from websec_auditor import config
from websec_auditor.scanner.engine import Finding


# ---------------------------------------------------------------------------
# Version comparison (small, semver-ish; good enough for the advisory seed)
# ---------------------------------------------------------------------------

def _ver_tuple(v):
    parts = re.split(r"[.+\-]", str(v).strip())
    out = []
    for p in parts:
        if p.isdigit():
            out.append((1, int(p)))   # numeric component ranks above prerelease
        elif p.lower() in ("rc", "b", "beta", "a", "alpha", "pre", "dev", "snapshot"):
            out.append((0, p.lower()))
        else:
            out.append((0, p.lower()))
    return tuple(out)


def _lt(a, b):
    return _ver_tuple(a) < _ver_tuple(b)


def _range_floor(spec):
    """Best-effort lowest version a range spec can resolve to (or exact for
    pins). Returns (floor, pinned) where pinned is True only for exact specs."""
    spec = (spec or "").strip()
    if not spec or spec == "*":
        return None, False
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    floors = []
    exact = None
    for p in parts:
        m = re.fullmatch(r"(==|=)?\s*([A-Za-z0-9][A-Za-z0-9.\-+]*)", p)
        if p.startswith("==") or p.startswith("="):
            exact = p.split("==")[-1] if "==" in p else p.split("=")[-1]
        elif p.startswith(">="):
            floors.append(p[2:].strip())
        elif p.startswith(">"):
            floors.append(p[1:].strip())
        elif p.startswith("^"):
            floors.append(p[1:].strip())
        elif p.startswith("~="):
            floors.append(p[2:].strip())
        elif p.startswith("~"):
            floors.append(p[1:].strip())
        elif m:  # bare version like "2.0.1" -> treat as a pin
            exact = m.group(2)
    if exact:
        return exact, True
    if not floors:
        return None, False
    floor = floors[0]
    for other in floors[1:]:
        if _lt(other, floor):
            floor = other
    return floor, False


# ---------------------------------------------------------------------------
# Manifest parsers (each returns [{"file", "pkg", "spec", "version"}])
# ---------------------------------------------------------------------------

def _norm_pkg(name, ecosystem):
    name = (name or "").strip().strip("\"'")
    if ecosystem == "python":
        return name.replace("_", "-").lower()
    return name


def _add(deps, fname, ecosystem, pkg, spec, version=""):
    pkg = _norm_pkg(pkg, ecosystem)
    if not pkg:
        return
    deps.append({"file": fname, "ecosystem": ecosystem, "pkg": pkg,
                 "spec": spec, "version": (version or "").strip()})


REQ_SPEC_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(==|===|>=|<=|~=|!=|>|<|=)?\s*([^\s;]+)?")
PIP_ENTRY_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=\s*[\"']([^\"']*)[\"']")
PYPROJ_STR_RE = re.compile(r"[\"']([A-Za-z0-9_.\-\[\]]+)\s*(==|===|>=|<=|~=|!=|>|<|=)?\s*([^\"'\s,]+)?[\"']")
GEM_RE = re.compile(r"\b(?:gem|add_dependency)\s+[\"']([^\"']+)[\"']\s*(?:,\s*[\"']([^\"']+)[\"'])?")
GRADLE_RE = re.compile(r"(compile|implementation|api|runtimeOnly|testImplementation)\s+[\"']([^\"']+)[\"']")
GOMOD_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-/]+)\s+(v\d+(?:\.\d+){1,}[A-Za-z0-9.\-+]*)\s*$")
GOSUM_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-/]+)\s+(v\d+(?:\.\d+){1,}[A-Za-z0-9.\-+]*)\s+")

PARSER_ORDER = {}


def parse_text(text, filename="requirements.txt"):
    """Parse dependency declarations out of pasted manifest text."""
    fname = filename or "requirements.txt"
    ecosystem = config.MANIFEST_FILENAMES.get(os.path.basename(fname), "python")
    deps = []
    base = os.path.basename(fname).lower()

    if base == "requirements.txt":
        for line in text.splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith(("-", "[", ".", "#", "git", "svn", "hg")):
                continue
            m = REQ_SPEC_RE.match(line)
            if m:
                spec = (m.group(2) or "") + (m.group(3) or "")
                ver = m.group(3) or "" if m.group(2) in ("==", "===") else ""
                _add(deps, fname, "python", m.group(1), spec, ver)

    elif base == "pipfile":
        section = ""
        for line in text.splitlines():
            if re.match(r"^\s*\[", line):
                section = line.strip()
            elif section in ("[packages]", "[dev-packages]"):
                m = PIP_ENTRY_RE.match(line)
                if m:
                    spec = m.group(2) or ""
                    ver = spec.lstrip("=~^>< ") if spec and spec != "*" else ""
                    _add(deps, fname, "python", m.group(1), spec, ver)

    elif base in ("pyproject.toml", "setup.py"):
        for line in text.splitlines():
            for m in PYPROJ_STR_RE.finditer(line):
                name = m.group(1).strip("[]")
                op = m.group(2) or ""
                ver = m.group(3) or ""
                _add(deps, fname, "python", name, op + ver, ver)

    elif base in ("package.json", "composer.json"):
        try:
            data = json.loads(text)
            sections = []
            if base == "package.json":
                sections = [data.get("dependencies") or {},
                            data.get("devDependencies") or {}]
            else:
                sections = [data.get("require") or {},
                            data.get("require-dev") or {}]
            eco = "npm" if base == "package.json" else "composer"
            for section in sections:
                for name, spec in section.items():
                    _add(deps, fname, eco, name, spec, "")
        except json.JSONDecodeError:
            pass

    elif base == "package-lock.json":
        try:
            data = json.loads(text)
            pkgs = data.get("dependencies") or {}
            for name, info in pkgs.items():
                _add(deps, fname, "npm", name, "==" + str(info.get("version", "")),
                     info.get("version", ""))
            for name, info in (data.get("packages") or {}).items():
                if name and info.get("version") and "node_modules" not in name:
                    _add(deps, fname, "npm", name.split("/")[-1],
                         "==" + str(info["version"]), info["version"])
        except json.JSONDecodeError:
            pass

    elif base == "yarn.lock":
        cur_name, cur_version = None, None
        for line in text.splitlines():
            block = re.match(r'^\s*"?([^"\s]+)@[^"\s:]+":\s*$', line)
            ver_line = re.match(r'^\s+version\s+"?([^"\s]+)"?\s*$', line)
            if block:
                if cur_name and cur_version:
                    _add(deps, fname, "npm", cur_name, "==" + cur_version, cur_version)
                cur_name = cur_version = None
                name_part = block.group(1).strip("\"'")
                if name_part.startswith("@"):  # scoped
                    pass
                else:
                    cur_name = name_part.split("@")[0]
            elif ver_line:
                cur_version = ver_line.group(1)
        if cur_name and cur_version:
            _add(deps, fname, "npm", cur_name, "==" + cur_version, cur_version)

    elif base == "composer.lock":
        try:
            data = json.loads(text)
            for p in data.get("packages") or []:
                _add(deps, fname, "composer", p.get("name", ""),
                     "==" + str(p.get("version", "")), p.get("version", ""))
        except json.JSONDecodeError:
            pass

    elif base == "gemfile":
        for line in text.splitlines():
            m = GEM_RE.search(line)
            if m:
                _add(deps, fname, "rubygems", m.group(1), m.group(2) or "", "")

    elif base == "gemfile.lock":
        for line in text.splitlines():
            m = re.match(r"^\s{4}([^\s(]+)\s*\(([^()]+)\)", line)
            if m:
                _add(deps, fname, "rubygems", m.group(1), "==" + m.group(2), m.group(2))

    elif base == "pom.xml":
        for dep in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
            gid = re.search(r"<groupId>([^<]+)</groupId>", dep)
            aid = re.search(r"<artifactId>([^<]+)</artifactId>", dep)
            ver = re.search(r"<version>([^<]+)</version>", dep)
            if aid and ver and not (ver.group(1) or "").startswith("$"):
                name = f"{gid.group(1)}:{aid.group(1)}" if gid else aid.group(1)
                _add(deps, fname, "maven", name, "==" + ver.group(1), ver.group(1))

    elif base == "build.gradle":
        for line in text.splitlines():
            m = GRADLE_RE.search(line)
            if not m:
                continue
            parts = m.group(2).split(":")
            if len(parts) >= 3:
                _add(deps, fname, "maven", parts[1], "==" + parts[2], parts[2])
            elif len(parts) == 2:
                _add(deps, fname, "maven", parts[0], "==" + parts[1], parts[1])

    elif base == "go.mod":
        in_block = False
        for line in text.splitlines():
            s = line.strip()
            if s == "require (":
                in_block = True
                continue
            if s == ")":
                in_block = False
                continue
            if in_block:
                m = GOMOD_LINE_RE.match(line)
                if m:
                    _add(deps, fname, "go", m.group(1), "==" + m.group(2), m.group(2))
            elif s.startswith("require ") and not s.startswith("require ("):
                rest = s[len("require "):].strip()
                m = re.match(r"([^\s]+)\s+(v[\d.]+[^\s]*)", rest)
                if m:
                    _add(deps, fname, "go", m.group(1), "==" + m.group(2), m.group(2))

    elif base == "go.sum":
        for line in text.splitlines():
            m = GOSUM_LINE_RE.match(line)
            if m:
                _add(deps, fname, "go", m.group(1), "==" + m.group(2), m.group(2))

    return deps


def parse_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return parse_text(fh.read(), os.path.basename(path))
    except (OSError, UnicodeError):
        return []


def scan_path(path):
    """Scan a single manifest file or a directory tree. Returns a list of Finding."""
    if os.path.isfile(path):
        return _check(parse_file(path))
    deps = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in config.CODE_REVIEW_SKIP_DIRS]
        for name in files:
            if name in config.MANIFEST_FILENAMES:
                deps.extend(parse_file(os.path.join(root, name)))
    return _check(deps)


def scan_text(text, filename="requirements.txt"):
    return _check(parse_text(text, filename))


def _check(deps):
    """Match parsed dependencies against the advisory seed. Returns Findings."""
    findings = []
    for dep in deps:
        for adv in config.CVE_ADVISORIES:
            if adv.get("ecosystem") != dep["ecosystem"]:
                continue
            if not any(n.lower() in dep["pkg"].lower() for n in adv.get("names", [])):
                continue
            floor, pinned = _range_floor(dep["spec"])
            if floor is None:
                floor, pinned = (dep["version"] or None), bool(dep["version"])
            if not floor:
                continue
            if _lt(floor, adv["fixed"]):
                findings.append(_build_finding(dep, adv, pinned))
    return _dedupe(findings)


def _build_finding(dep, adv, pinned):
    if pinned:
        severity = adv.get("severity", "high")
        status, match = "fail", "exact match"
    else:
        severity = "medium"
        status, match = "warn", "range may include vulnerable version"
    detail = (
        f"{dep['file']}: {dep['pkg']} declared as '{dep['spec'] or dep['version'] or '?'}' "
        f"({dep['ecosystem']}) - {match} for {adv['cve']} "
        f"(fixed in {adv['fixed']}). {adv.get('note', '')}"
    )
    return Finding(
        check="dep-scan",
        name=f"{dep['pkg']} / {adv['cve']}",
        status=status,
        severity=severity,
        detail=detail,
        source_id=config.DEPENDENCY_RULE["source_id"],
        cwe=adv.get("cwe", config.DEPENDENCY_RULE["cwe"]),
        owasp=config.DEPENDENCY_RULE["owasp"],
        remediation=config.DEPENDENCY_RULE["remediation"],
        confidence="high" if pinned else "low",
    )


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.name, f.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
