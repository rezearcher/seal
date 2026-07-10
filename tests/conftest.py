"""Pytest fixtures for e2e VPE middleware tests (P6.2)."""

import os
import sys
import tempfile

import pytest

_SEAL_ROOT = os.path.expanduser("~/projects/seal")
if _SEAL_ROOT not in sys.path:
    sys.path.insert(0, _SEAL_ROOT)

# Canonical middleware lives in the importable package (seal.integration).
from seal.integration.hermes_vpe_middleware import VPEMiddleware  # noqa: E402


@pytest.fixture
def key_dir():
    with tempfile.TemporaryDirectory(prefix="vpe-e2e-") as tmp:
        yield tmp


@pytest.fixture
def middleware(key_dir):
    mw = VPEMiddleware(
        config={
            "vpe_enabled": True,
            "vpe_mode": "enforce",
            "vpe_key_dir": key_dir,
            "vpe_skip_tools": ["todo", "memory", "clarify", "session_search"],
            "vpe_epd_enabled": False,
        }
    )
    mw.ensure_keys()
    return mw
