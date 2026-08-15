"""Tests for the anti-SSRF network guard (netsafe)."""
import ssl
import urllib.error
import urllib.request

import pytest

from websec_auditor import netsafe


def test_scheme_blocked():
    with pytest.raises(netsafe.UnsafeTargetError):
        netsafe.validate_target("file:///etc/passwd")
    with pytest.raises(netsafe.UnsafeTargetError):
        netsafe.validate_target("ftp://example.com/")


def test_embedded_credentials_blocked():
    with pytest.raises(netsafe.UnsafeTargetError):
        netsafe.validate_target("https://user:pass@example.com/")


def test_loopback_blocked_by_default():
    with pytest.raises(netsafe.UnsafeTargetError):
        netsafe.validate_target("http://127.0.0.1/")
    with pytest.raises(netsafe.UnsafeTargetError):
        netsafe.validate_target("http://localhost/")


def test_cloud_metadata_blocked():
    # 169.254.169.254 is link-local; must never be reachable from the UI.
    with pytest.raises(netsafe.UnsafeTargetError):
        netsafe.validate_target("http://169.254.169.254/latest/meta-data/")


def test_cgnat_blocked():
    with pytest.raises(netsafe.UnsafeTargetError):
        netsafe.validate_target("http://100.64.0.1/")


def test_private_allowed_widens_scope():
    saved = netsafe.ALLOW_PRIVATE
    try:
        with netsafe.private_allowed(True):
            assert netsafe.validate_target("http://127.0.0.1/") == "http://127.0.0.1/"
        # scope must be restored
        with pytest.raises(netsafe.UnsafeTargetError):
            netsafe.validate_target("http://127.0.0.1/")
    finally:
        netsafe.ALLOW_PRIVATE = saved


def test_public_target_passes():
    netsafe.validate_target("https://example.com/")
