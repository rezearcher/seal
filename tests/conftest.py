"""Pytest fixtures for e2e VPE middleware tests (P6.2)."""
import os
import sys
import tempfile
import pytest

_SEAL_ROOT = os.path.expanduser("~/projects/seal")
if _SEAL_ROOT not in sys.path:
    sys.path.insert(0, _SEAL_ROOT)

import importlib.util
_MW_PATH = os.path.join(_SEAL_ROOT, "integration", "hermes_vpe_middleware.py")
_mw_spec = importlib.util.spec_from_file_location("hermes_vpe_middleware", _MW_PATH)
_mw_mod = importlib.util.module_from_spec(_mw_spec)
_mw_spec.loader.exec_module(_mw_mod)
VPEMiddleware = _mw_mod.VPEMiddleware


@pytest.fixture
def key_dir():
    with tempfile.TemporaryDirectory(prefix="vpe-e2e-") as tmp:
        yield tmp


@pytest.fixture
def middleware(key_dir):
    mw = VPEMiddleware(config={
        "vpe_enabled": True,
        "vpe_mode": "enforce",
        "vpe_key_dir": key_dir,
        "vpe_skip_tools": ["todo", "memory", "clarify", "session_search"],
        "vpe_epd_enabled": False,
    })
    mw.ensure_keys()
    return mw
