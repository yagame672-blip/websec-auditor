"""Usage counter tests (file backend; Neon is covered manually against DATABASE_URL)."""
import json
import os

import pytest

from websec_auditor import usage


@pytest.fixture(autouse=True)
def no_neon(monkeypatch, tmp_path):
    """Force the file backend and point the usage file at a temp path."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(usage, "_FILE", str(tmp_path / "usage.json"))
    monkeypatch.setattr(usage, "_cache", {"count": 0, "ts": 0.0})
    monkeypatch.setattr(usage, "_table_ok", False)
    yield


def test_backend_is_file_when_no_database_url():
    assert usage.backend() == "file"


def test_missing_file_reports_zero(no_neon):
    assert usage.get_count() == 0


def test_increment_returns_growing_count(no_neon):
    assert usage.increment() == 1
    assert usage.increment() == 2
    assert usage.get_count() == 2


def test_increment_persists_to_file(no_neon):
    usage.increment()
    usage.increment()
    with open(usage._FILE, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["scans"] == 2


def test_reset_zeroes_counter(no_neon):
    usage.increment()
    usage.increment()
    assert usage.reset() == 0
    assert usage.get_count() == 0
