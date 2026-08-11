"""Unit tests for seal.rotator — the key rotation daemon CLI entry point."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

import seal.rotator as rotator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(argv: list[str], monkeypatch, mock_daemon) -> int:
    """Run main() with the given argv and a mocked rotation daemon."""
    monkeypatch.setattr(sys, "argv", ["seal-rotator", *argv])
    return rotator.main()


# ---------------------------------------------------------------------------
# Argument parsing and daemon invocation
# ---------------------------------------------------------------------------


class TestInvocation:
    def test_defaults_passed_to_daemon(self, monkeypatch):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(sys, "argv", ["seal-rotator"])
            with pytest.MonkeyPatch.context() as inner:
                inner.setattr(
                    "seal.rotator.KeyManager.run_rotation_daemon",
                    (mock := __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()),
                )
                code = rotator.main()
        assert code == 0
        mock.assert_called_once_with(
            db_path=None,
            days_before=30,
            interval_seconds=3600,
            once=False,
        )

    def test_once_flag(self, monkeypatch):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(sys, "argv", ["seal-rotator", "--once"])
            with pytest.MonkeyPatch.context() as inner:
                inner.setattr(
                    "seal.rotator.KeyManager.run_rotation_daemon",
                    (mock := __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()),
                )
                code = rotator.main()
        assert code == 0
        mock.assert_called_once_with(
            db_path=None,
            days_before=30,
            interval_seconds=3600,
            once=True,
        )

    def test_custom_flags_passed_through(self, monkeypatch):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                sys,
                "argv",
                ["seal-rotator", "--days-before", "14", "--interval", "120", "--db", "/tmp/x.db", "--once"],
            )
            with pytest.MonkeyPatch.context() as inner:
                inner.setattr(
                    "seal.rotator.KeyManager.run_rotation_daemon",
                    (mock := __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()),
                )
                code = rotator.main()
        assert code == 0
        mock.assert_called_once_with(
            db_path="/tmp/x.db",
            days_before=14,
            interval_seconds=120,
            once=True,
        )

    def test_invalid_int_argument_exits_2(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["seal-rotator", "--days-before", "soon"])
        with pytest.raises(SystemExit) as excinfo:
            rotator.main()
        assert excinfo.value.code == 2  # argparse usage error
        assert "invalid int value" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# KeyboardInterrupt handling
# ---------------------------------------------------------------------------


class TestKeyboardInterrupt:
    def test_returns_1_and_prints_stderr(self, monkeypatch, capsys):
        from unittest.mock import MagicMock

        daemon = MagicMock(side_effect=KeyboardInterrupt)
        monkeypatch.setattr("seal.rotator.KeyManager.run_rotation_daemon", daemon)
        monkeypatch.setattr(sys, "argv", ["seal-rotator", "--once"])
        code = rotator.main()
        assert code == 1
        captured = capsys.readouterr()
        assert "[seal-rotator] stopped by signal" in captured.err


# ---------------------------------------------------------------------------
# __main__ guard
# ---------------------------------------------------------------------------


class TestMainGuard:
    def test_raises_systemexit_with_main_return(self, monkeypatch):
        from unittest.mock import MagicMock

        monkeypatch.setattr("seal.rotator.KeyManager.run_rotation_daemon", MagicMock())
        monkeypatch.setattr(sys, "argv", ["seal-rotator", "--once"])
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_path(str(Path(rotator.__file__)), run_name="__main__")
        assert excinfo.value.code == 0

    def test_raises_systemexit_with_interrupt_code(self, monkeypatch):
        from unittest.mock import MagicMock

        daemon = MagicMock(side_effect=KeyboardInterrupt)
        monkeypatch.setattr("seal.rotator.KeyManager.run_rotation_daemon", daemon)
        monkeypatch.setattr(sys, "argv", ["seal-rotator", "--once"])
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_path(str(Path(rotator.__file__)), run_name="__main__")
        assert excinfo.value.code == 1
