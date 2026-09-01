"""Guard against re-duplication of the shared ``_ensure_seal_dir`` helper.

B-001: the mkdir + best-effort chmod 0o700 + warn-on-failure logic used to
live as near-identical copies in ``seal.key_manager``, ``seal.cli`` and
``seal.credential_store``.  It now lives once in ``seal._fsutil``; these tests
pin that the legacy modules import and use the single shared function, so a
future re-copy is caught by the suite.
"""

import seal._fsutil as fsutil
import seal.cli
import seal.credential_store
import seal.key_manager


def test_shared_ensure_seal_dir_used_by_all_legacy_modules():
    """All three legacy modules must resolve to the single shared helper."""
    for mod in (seal.key_manager, seal.cli, seal.credential_store):
        assert mod._ensure_seal_dir is fsutil._ensure_seal_dir


def test_ensure_seal_dir_creates_0700_dir(tmp_path):
    """The shared helper creates parents and hardens the target to 0700."""
    target = tmp_path / "nested" / ".seal"
    fsutil._ensure_seal_dir(target)
    assert target.is_dir()
    assert target.stat().st_mode & 0o777 == 0o700


def test_ensure_seal_dir_accepts_arbitrary_directory(tmp_path):
    """The helper is not hardcoded to ~/.seal — callers pass the directory."""
    target = tmp_path / "elsewhere"
    fsutil._ensure_seal_dir(target)
    assert target.is_dir()
    assert target.stat().st_mode & 0o777 == 0o700
