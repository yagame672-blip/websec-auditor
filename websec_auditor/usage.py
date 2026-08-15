"""Persistent scan-usage counter.

Counts how many scans have been run through the web UI so the site can show a
real, non-hardcoded number of scans performed. Storage is durable across
serverless cold starts by persisting to Neon Postgres over the HTTP SQL
endpoint (the same transport the official @neondatabase/serverless driver
uses) - standard library only, no third-party driver.

When DATABASE_URL is not configured (local runs) a JSON file in data/ is used
instead. Every public function is best-effort: a storage failure never blocks
or breaks a scan, it only returns the last known value.
"""
from __future__ import annotations
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from websec_auditor import config

# Metric key that uniquely identifies the scan counter in the table.
METRIC = "scans"
# Hard ceiling on how long one Neon HTTP query may take.
USAGE_TIMEOUT = 6
# How long get_count() trusts its last value before re-reading storage.
CACHE_TTL = 10.0

_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS websec_usage ("
    " metric text PRIMARY KEY,"
    " count bigint NOT NULL DEFAULT 0,"
    " updated_at timestamptz NOT NULL DEFAULT now())"
)
_INC_SQL = (
    "INSERT INTO websec_usage (metric, count) VALUES ($1, 1) "
    "ON CONFLICT (metric) DO UPDATE SET count = websec_usage.count + 1, "
    "updated_at = now() RETURNING count"
)
_GET_SQL = "SELECT count FROM websec_usage WHERE metric = $1"
_RESET_SQL = (
    "UPDATE websec_usage SET count = 0, updated_at = now() "
    "WHERE metric = $1 RETURNING count"
)

_FILE = os.path.join(config.DATA_DIR, "usage.json")

_lock = threading.Lock()
_cache = {"count": 0, "ts": 0.0}
_table_ok = False


def _database_url():
    return os.environ.get("DATABASE_URL", "").strip()


def backend() -> str:
    """Which storage backend is active: 'neon' or 'file'."""
    return "neon" if _database_url() else "file"


def _neon_endpoint(url: str) -> str:
    """Build the Neon HTTP SQL endpoint from a pooled/direct connection URL.

    Mirrors the official driver: the first host label is dropped and replaced
    with 'api.', keeping the region suffix, e.g.
      ep-xyz-123456.us-east-1.aws.neon.tech
        -> https://api.us-east-1.aws.neon.tech/sql
    Routing to the right project happens via the Neon-Connection-String header.
    """
    host = urllib.parse.urlsplit(url).hostname or ""
    idx = host.find(".")
    if idx == -1:
        return "https://api." + host + "/sql"
    return "https://api." + host[idx + 1:] + "/sql"


def _neon_query(sql: str, params=None) -> dict:
    """Run one SQL statement over the Neon HTTP endpoint (raw text + array mode).

    Raises on transport/HTTP errors; callers are expected to swallow them.
    """
    url = _database_url()
    body = json.dumps({"query": sql, "params": params or []}).encode("utf-8")
    req = urllib.request.Request(
        _neon_endpoint(url),
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Neon-Connection-String": url,
            "Neon-Raw-Text-Output": "true",
            "Neon-Array-Mode": "true",
        },
    )
    # Trusted server-config endpoint only: the Neon HTTP SQL URL is derived
    # from DATABASE_URL (deploy-time env), never from user input -- not SSRF.
    with urllib.request.urlopen(req, timeout=USAGE_TIMEOUT) as resp:  # codereview-ignore: urlopen-user-input
        return json.loads(resp.read().decode("utf-8", "ignore"))


def _ensure_table():
    global _table_ok
    if _table_ok:
        return
    _neon_query(_TABLE_SQL)
    _table_ok = True


def _extract_count(payload) -> int | None:
    """Pull the 'count' value out of a Neon {fields, rows} response."""
    try:
        rows = payload.get("rows") or []
        if not rows:
            return None
        cell = rows[0]
        if isinstance(cell, (list, tuple)):
            cell = cell[0] if cell else None
        elif isinstance(cell, dict):
            cell = next(iter(cell.values()), None)
        if cell is None:
            return None
        return int(cell)
    except (TypeError, ValueError, AttributeError):
        return None


def _file_read() -> dict:
    try:
        with open(_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _file_count() -> int:
    n = _file_read().get("scans")
    return n if isinstance(n, int) else 0


def _file_write(count: int):
    try:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = _FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(
                {"scans": count,
                 "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                fh,
            )
        os.replace(tmp, _FILE)
    except Exception:
        pass


def _load_from_storage() -> int | None:
    """Read the persisted count, preferring Neon when configured."""
    if backend() == "neon":
        try:
            _ensure_table()
            n = _extract_count(_neon_query(_GET_SQL, [METRIC]))
            if n is not None:
                return n
        except Exception:
            pass
    n = _file_count()
    return n if n else None


def _cache_store(count: int):
    _cache["count"] = count
    _cache["ts"] = time.time()


def get_count() -> int:
    """Total number of scans run through the site (never raises)."""
    with _lock:
        if time.time() - _cache["ts"] < CACHE_TTL:
            return _cache["count"]
        n = _load_from_storage()
        if n is not None:
            _cache_store(n)
            return n
        return _cache["count"]


def increment() -> int:
    """Count one more scan. Returns the new total (never raises)."""
    with _lock:
        n = None
        if backend() == "neon":
            try:
                _ensure_table()
                n = _extract_count(_neon_query(_INC_SQL, [METRIC]))
            except Exception:
                n = None
        if n is None:
            n = _file_count() + 1
            _file_write(n)
        _cache_store(n)
        return n


def reset() -> int:
    """Zero the scan counter (admin/CLI use). Returns the new total."""
    with _lock:
        n = 0
        if backend() == "neon":
            try:
                _ensure_table()
                got = _extract_count(_neon_query(_RESET_SQL, [METRIC]))
                if got is not None:
                    n = got
            except Exception:
                pass
        _file_write(n)
        _cache_store(n)
        return n
