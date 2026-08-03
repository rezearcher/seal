"""Tests for seal.rollback — VPE disable/rollback/status procedures.

All tests are hermetic: SEAL_HOME and HERMES_HOME env vars point at
temporary directories (rollback.py resolves paths at call time), so no
real ~/.seal or ~/.hermes state is touched.
"""

from __future__ import annotations

import re

import pytest
import yaml

from seal import rollback


@pytest.fixture
def homes(tmp_path, monkeypatch):
    """Point SEAL_HOME/HERMES_HOME at temp dirs; return (seal_home, hermes_home)."""
    seal_home = tmp_path / "seal"
    hermes_home = tmp_path / "hermes"
    seal_home.mkdir()
    hermes_home.mkdir()
    monkeypatch.setenv("SEAL_HOME", str(seal_home))
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    return seal_home, hermes_home


def _write_config(hermes_home, data: dict) -> None:
    path = hermes_home / "config.yaml"
    path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=False))


def _read_config(hermes_home) -> dict:
    return yaml.safe_load((hermes_home / "config.yaml").read_text()) or {}


def _vpe_config(enabled: bool = True) -> dict:
    return {
        "security": {
            "vpe": {
                "vpe_enabled": enabled,
                "vpe_mode": "enforce",
            }
        },
        "hooks": {
            "pre_tool_call": [
                {"command": "hermes vpe-middleware check"},
                {"command": "echo keep-me"},
            ]
        },
    }


# ---------------------------------------------------------------------------
# RollbackReport
# ---------------------------------------------------------------------------


class TestRollbackReport:
    def test_ok_empty(self):
        r = rollback.RollbackReport()
        assert r.ok() is True
        assert r.operations == []
        assert r.preserved == []
        assert r.warnings == []
        assert r.errors == []

    def test_ok_false_when_errors(self):
        r = rollback.RollbackReport()
        r.err("boom")
        assert r.ok() is False
        r.op("did something")
        r.keep("kept something")
        r.warn("careful")
        assert r.operations == ["did something"]
        assert r.preserved == ["kept something"]
        assert r.warnings == ["careful"]

    def test_print_report_empty(self, capsys):
        r = rollback.RollbackReport()
        r.print_report("Test Title")
        out = capsys.readouterr().out
        assert "Test Title" in out
        assert "Operations" not in out
        assert "Preserved" not in out

    def test_print_report_populated(self, capsys):
        r = rollback.RollbackReport()
        r.op("removed section")
        r.keep("audit preserved")
        r.warn("no keys found")
        r.err("config backup failed")
        r.print_report("Rollback")
        out = capsys.readouterr().out
        assert "✓ removed section" in out
        assert "• audit preserved" in out
        assert "⚠ no keys found" in out
        assert "✗ config backup failed" in out

    def test_report_to_dict(self):
        r = rollback.RollbackReport()
        r.op("a")
        r.warn("w")
        r.err("e")
        d = rollback._report_to_dict(r)
        assert d["operations"] == ["a"]
        assert d["warnings"] == ["w"]
        assert d["errors"] == ["e"]
        assert d["ok"] is False


# ---------------------------------------------------------------------------
# YAML helpers
# ---------------------------------------------------------------------------


class TestYamlHelpers:
    def test_load_yaml_missing(self, tmp_path):
        assert rollback._load_yaml(tmp_path / "nope.yaml") == {}

    def test_load_yaml_empty(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("")
        assert rollback._load_yaml(p) == {}

    def test_load_yaml_whitespace_only(self, tmp_path):
        p = tmp_path / "ws.yaml"
        p.write_text("   \n\n")
        assert rollback._load_yaml(p) == {}

    def test_load_yaml_valid(self, tmp_path):
        p = tmp_path / "c.yaml"
        p.write_text("security:\n  vpe:\n    vpe_enabled: true\n")
        data = rollback._load_yaml(p)
        assert data["security"]["vpe"]["vpe_enabled"] is True

    def test_load_yaml_invalid_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("security: [unclosed\n")
        with pytest.raises(yaml.YAMLError):
            rollback._load_yaml(p)

    def test_dump_yaml_round_trip(self, tmp_path):
        p = tmp_path / "sub" / "c.yaml"
        rollback._dump_yaml(p, {"a": {"b": [1, 2]}, "c": "x"})
        assert p.exists()
        assert rollback._load_yaml(p) == {"a": {"b": [1, 2]}, "c": "x"}


# ---------------------------------------------------------------------------
# cmd_disable
# ---------------------------------------------------------------------------


class TestCmdDisable:
    def test_missing_config(self, homes):
        seal_home, hermes_home = homes
        report = rollback.cmd_disable()
        assert report.ok() is False
        assert any("config not found" in e for e in report.errors)

    def test_invalid_yaml(self, homes):
        seal_home, hermes_home = homes
        (hermes_home / "config.yaml").write_text("security: [bad\n")
        report = rollback.cmd_disable()
        assert report.ok() is False
        assert any("Failed to load" in e for e in report.errors)

    def test_toggle_enabled_to_disabled(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config(enabled=True))
        report = rollback.cmd_disable()
        assert report.ok() is True
        cfg = _read_config(hermes_home)
        assert cfg["security"]["vpe"]["vpe_enabled"] is False
        # Backup file was created next to config
        backups = list(hermes_home.glob("config.yaml.vpe-*"))
        assert len(backups) == 1
        assert any("Toggled VPE" in op for op in report.operations)

    def test_already_disabled(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config(enabled=False))
        report = rollback.cmd_disable()
        assert report.ok() is True
        assert any("already disabled" in op for op in report.operations)

    def test_creates_section_when_absent(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"other": "value"})
        report = rollback.cmd_disable()
        assert report.ok() is True
        cfg = _read_config(hermes_home)
        assert cfg["security"]["vpe"]["vpe_enabled"] is False
        assert cfg["security"]["vpe"]["vpe_mode"] == "audit"
        assert any("Created security.vpe" in op for op in report.operations)

    def test_preserves_vpe_mode(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config(enabled=True))
        report = rollback.cmd_disable()
        cfg = _read_config(hermes_home)
        assert cfg["security"]["vpe"]["vpe_mode"] == "enforce"

    def test_keeps_recorded(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config())
        report = rollback.cmd_disable()
        assert len(report.preserved) >= 3
        assert any("Audit log untouched" in k for k in report.preserved)
        assert any("VPE keys untouched" in k for k in report.preserved)
        assert any("Credential store untouched" in k for k in report.preserved)


# ---------------------------------------------------------------------------
# cmd_rollback
# ---------------------------------------------------------------------------


class TestCmdRollback:
    def test_full_rollback_preserve_keys(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config(enabled=True))
        # Audit log with entries
        (seal_home / "audit.jsonl").write_text('{"a": 1}\n{"b": 2}\n')
        # VPE keys in hermes + seal key files
        vpe_keys = hermes_home / "vpe-keys"
        vpe_keys.mkdir()
        (vpe_keys / "default.key").write_bytes(b"k" * 32)
        (seal_home / "seal_private.key").write_bytes(b"p" * 32)

        report = rollback.cmd_rollback(clean_keys=False)
        assert report.ok() is True

        # Backup exists
        assert list(hermes_home.glob("config.yaml.vpe-*"))
        # Audit archived, original preserved
        archives = list((seal_home / "archive").glob("audit-*.jsonl"))
        assert len(archives) == 1
        assert (seal_home / "audit.jsonl").exists()
        # vpe section removed
        cfg = _read_config(hermes_home)
        assert "vpe" not in cfg.get("security", {})
        # Hooks cleaned: vpe hook gone, non-vpe hook kept
        pre = cfg.get("hooks", {}).get("pre_tool_call", [])
        assert len(pre) == 1
        assert pre[0]["command"] == "echo keep-me"
        # Keys preserved
        assert vpe_keys.exists()
        assert (seal_home / "seal_private.key").exists()
        assert any("left in place" in k for k in report.preserved)

    def test_full_rollback_clean_keys(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config())
        vpe_keys = hermes_home / "vpe-keys"
        vpe_keys.mkdir()
        (vpe_keys / "a.key").write_bytes(b"a" * 32)
        (seal_home / "seal_private.key").write_bytes(b"p" * 32)
        (seal_home / "seal_public.key").write_bytes(b"q" * 32)
        # non-key file must be left alone
        (seal_home / "credentials.yaml.enc").write_text("enc")

        report = rollback.cmd_rollback(clean_keys=True)
        assert report.ok() is True

        # hermes keys archived + removed
        assert not vpe_keys.exists()
        assert list(hermes_home.glob("vpe-keys-archive-*"))
        # seal keys moved into keys-archive-*
        key_archives = list(seal_home.glob("keys-archive-*"))
        assert len(key_archives) == 1
        archived = [p.name for p in key_archives[0].iterdir()]
        assert "seal_private.key" in archived
        assert "seal_public.key" in archived
        assert not list(seal_home.glob("seal_*.key"))
        # unrelated file untouched
        assert (seal_home / "credentials.yaml.enc").exists()
        assert any("archived to" in op for op in report.operations)

    def test_rollback_no_vpe_keys(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config())
        report = rollback.cmd_rollback(clean_keys=True)
        assert any("No VPE key directories found" in op for op in report.operations)

    def test_rollback_missing_config(self, homes):
        seal_home, hermes_home = homes
        report = rollback.cmd_rollback()
        assert report.ok() is False
        assert any("Config backup failed" in e for e in report.errors)
        assert any("config not found" in e for e in report.errors)

    def test_rollback_no_vpe_section(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {"name": "x"}})
        report = rollback.cmd_rollback()
        assert report.ok() is True
        assert any("No security section" in op for op in report.operations)

    def test_rollback_final_preservation_summary(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config())
        report = rollback.cmd_rollback()
        texts = " ".join(report.preserved)
        assert "Audit log — archived" in texts
        assert "Credential store — untouched" in texts
        assert "Division memory episodes" in texts

    def test_rollback_empty_audit(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config())
        (seal_home / "audit.jsonl").write_text("\n\n")
        report = rollback.cmd_rollback()
        assert report.ok() is True
        assert any("exists but is empty" in k for k in report.preserved)

    def test_rollback_no_audit(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config())
        report = rollback.cmd_rollback()
        assert any("No audit log found" in k for k in report.preserved)

    def test_rollback_removes_empty_security_section(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"security": {"vpe": {"vpe_enabled": True}}, "other": 1})
        report = rollback.cmd_rollback()
        cfg = _read_config(hermes_home)
        assert "security" not in cfg
        assert cfg["other"] == 1

    def test_rollback_non_dict_security(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"security": "scalar"})
        report = rollback.cmd_rollback()
        assert any("No security section" in op for op in report.operations)


# ---------------------------------------------------------------------------
# _remove_vpe_hooks
# ---------------------------------------------------------------------------


class TestRemoveVpeHooks:
    def _report_and_config(self, homes, hooks_value):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"hooks": {"pre_tool_call": hooks_value}})
        return rollback.RollbackReport(), hermes_home

    def test_removes_dict_vpe_hooks(self, homes):
        seal_home, hermes_home = homes
        _write_config(
            hermes_home,
            {
                "hooks": {
                    "pre_tool_call": [
                        {"command": "python -m seal.integration.hermes_vpe_middleware"},
                        {"command": "echo keep-me"},
                    ]
                }
            },
        )
        report = rollback.RollbackReport()
        rollback._remove_vpe_hooks(report)
        cfg = _read_config(hermes_home)
        pre = cfg["hooks"]["pre_tool_call"]
        assert len(pre) == 1
        assert pre[0]["command"] == "echo keep-me"
        assert any("Removed 1 VPE-related hook" in op for op in report.operations)

    def test_removes_str_vpe_hooks(self, homes):
        seal_home, hermes_home = homes
        _write_config(
            hermes_home,
            {
                "hooks": {
                    "pre_tool_call": [
                        "hermes_vpe_middleware check",
                        "echo keep",
                    ]
                }
            },
        )
        report = rollback.RollbackReport()
        rollback._remove_vpe_hooks(report)
        cfg = _read_config(hermes_home)
        assert cfg["hooks"]["pre_tool_call"] == ["echo keep"]

    def test_no_vpe_hooks_no_rewrite(self, homes):
        seal_home, hermes_home = homes
        _write_config(
            hermes_home,
            {"hooks": {"pre_tool_call": [{"command": "echo hi"}, {"command": "echo bye"}]}},
        )
        before = (hermes_home / "config.yaml").read_text()
        report = rollback.RollbackReport()
        rollback._remove_vpe_hooks(report)
        assert (hermes_home / "config.yaml").read_text() == before
        assert report.operations == []

    def test_pre_tool_call_not_a_list(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"hooks": {"pre_tool_call": "not-a-list"}})
        before = (hermes_home / "config.yaml").read_text()
        report = rollback.RollbackReport()
        rollback._remove_vpe_hooks(report)
        assert (hermes_home / "config.yaml").read_text() == before

    def test_no_hooks_section(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {}})
        before = (hermes_home / "config.yaml").read_text()
        report = rollback.RollbackReport()
        rollback._remove_vpe_hooks(report)
        assert (hermes_home / "config.yaml").read_text() == before


# ---------------------------------------------------------------------------
# cmd_status
# ---------------------------------------------------------------------------


class _StubKeyManager:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    def get_active_key(self):
        if self._error:
            raise self._error
        return self._result


@pytest.fixture
def stub_keymanager(monkeypatch):
    """Replace seal.key_manager.KeyManager (imported lazily inside cmd_status)."""

    def _apply(result=None, error=None):
        monkeypatch.setattr(
            "seal.key_manager.KeyManager",
            lambda: _StubKeyManager(result=result, error=error),
        )

    return _apply


class TestCmdStatus:
    def test_missing_config(self, homes):
        seal_home, hermes_home = homes
        report = rollback.cmd_status()
        assert report.ok() is False
        assert any("config not found" in e for e in report.errors)

    def test_invalid_config(self, homes):
        seal_home, hermes_home = homes
        (hermes_home / "config.yaml").write_text("security: [bad\n")
        report = rollback.cmd_status()
        assert report.ok() is False
        assert any("Failed to load config" in e for e in report.errors)

    def test_vpe_enabled(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config(enabled=True))
        report = rollback.cmd_status()
        ops = " ".join(report.operations)
        assert "present — ENABLED" in ops
        assert "mode: enforce" in ops

    def test_vpe_disabled_toggle(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config(enabled=False))
        report = rollback.cmd_status()
        assert any("DISABLED (toggle present)" in op for op in report.operations)

    def test_no_vpe_section(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {}})
        report = rollback.cmd_status()
        ops = " ".join(report.operations)
        assert "not present in Hermes config" in ops
        assert "will not be loaded" in ops

    def test_hooks_reported(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, _vpe_config())
        report = rollback.cmd_status()
        assert any("1 present" in op for op in report.operations if "hooks" in op)

    def test_no_hooks(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"security": {"vpe": {"vpe_enabled": False}}})
        report = rollback.cmd_status()
        assert any("hooks in pre_tool_call: none" in op for op in report.operations)

    def test_keys_reported(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {}})
        (hermes_home / "vpe-keys").mkdir()
        (hermes_home / "vpe-keys" / "k.key").write_bytes(b"k")
        (seal_home / "seal_private.key").write_bytes(b"p")
        report = rollback.cmd_status()
        ops = " ".join(report.operations)
        assert "1 file(s) at" in ops
        assert "seal_*.key" in ops or "Seal keys: 1" in ops

    def test_active_key_reported(self, homes, stub_keymanager):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {}})
        stub_keymanager(
            result={
                "kid": "k1",
                "fingerprint": "abc123",
                "not_after": 1_700_000_000 + 31_536_000,
            }
        )
        report = rollback.cmd_status()
        ops = " ".join(report.operations)
        assert "Active signing key: k1" in ops
        assert "abc123" in ops

    def test_no_active_key(self, homes, stub_keymanager):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {}})
        stub_keymanager(result=None)
        report = rollback.cmd_status()
        assert any("Active signing key: none" in op for op in report.operations)

    def test_keymanager_error(self, homes, stub_keymanager):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {}})
        stub_keymanager(error=RuntimeError("no db"))
        report = rollback.cmd_status()
        assert any("Active signing key: error" in op for op in report.operations)

    def test_audit_and_archive_reported(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {}})
        (seal_home / "audit.jsonl").write_text('{"x": 1}\n{"y": 2}\n')
        archive = seal_home / "archive"
        archive.mkdir()
        (archive / "audit-20200101T000000Z.jsonl").write_text("{}")
        report = rollback.cmd_status()
        ops = " ".join(report.operations)
        assert "Audit log: 2 entries" in ops
        assert "Archived audit logs: 1 file(s)" in ops

    def test_no_audit(self, homes):
        seal_home, hermes_home = homes
        _write_config(hermes_home, {"agent": {}})
        report = rollback.cmd_status()
        assert any("Audit log: not present" in op for op in report.operations)


# ---------------------------------------------------------------------------
# Path resolvers
# ---------------------------------------------------------------------------


class TestPathResolvers:
    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("SEAL_HOME", "/tmp/x-seal")
        monkeypatch.setenv("HERMES_HOME", "/tmp/x-hermes")
        assert rollback._resolve_seal_home() == __import__("pathlib").Path("/tmp/x-seal")
        assert rollback._resolve_hermes_home() == __import__("pathlib").Path("/tmp/x-hermes")

    def test_defaults_without_env(self, monkeypatch):
        monkeypatch.delenv("SEAL_HOME", raising=False)
        monkeypatch.delenv("HERMES_HOME", raising=False)
        import pathlib

        assert rollback._resolve_seal_home() == pathlib.Path.home() / ".seal"
        assert rollback._resolve_hermes_home() == pathlib.Path.home() / ".hermes"

    def test_derived_paths(self, homes):
        seal_home, hermes_home = homes
        assert rollback._hermes_config() == hermes_home / "config.yaml"
        assert rollback._seal_audit() == seal_home / "audit.jsonl"
        assert rollback._seal_archive() == seal_home / "archive"
        assert rollback._vpe_keys_hermes() == hermes_home / "vpe-keys"
        assert rollback._seal_backup_config() == hermes_home / "config.yaml.vpe-backup"

    def test_utcnow_format(self):
        ts = rollback._utcnow()
        assert re.match(r"^\d{8}T\d{6}Z$", ts)
