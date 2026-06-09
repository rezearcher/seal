"""Tests for seal.secrets_broker — CredentialStore with corruption handling."""
from __future__ import annotations

import json
import logging

import pytest

from seal.secrets_broker import (
    CredentialStore,
    CredentialStoreCorruptedError,
)


def test_corrupted_file_raises_on_get(tmp_path):
    """Write a truncated JSON file, call get(), verify
    CredentialStoreCorruptedError is raised."""
    store_path = tmp_path / "corrupt.json"
    # Write truncated JSON (missing closing brace)
    store_path.write_text('{"key": "value"', encoding="utf-8")

    store = CredentialStore(str(store_path))
    # __init__ found the file exists, so _ensure_store() skipped creation.
    # Corruption is detected lazily on the first read operation.
    with pytest.raises(CredentialStoreCorruptedError) as excinfo:
        store.get("key")
    assert "corrupted" in str(excinfo.value).lower()
    assert str(store_path) in str(excinfo.value)


def test_corrupted_file_detected_on_list_labels(tmp_path):
    """list_labels() also raises CredentialStoreCorruptedError on corrupt file."""
    store_path = tmp_path / "garbage.json"
    store_path.write_text("{not json at all", encoding="utf-8")

    store = CredentialStore(str(store_path))
    with pytest.raises(CredentialStoreCorruptedError):
        store.list_labels()


def test_corrupted_file_detected_on_set(tmp_path):
    """set() also raises CredentialStoreCorruptedError on corrupt file."""
    store_path = tmp_path / "garbage2.json"
    store_path.write_text("{invalid", encoding="utf-8")

    store = CredentialStore(str(store_path))
    with pytest.raises(CredentialStoreCorruptedError):
        store.set("a", "b")


def test_corrupted_file_logs_warning(tmp_path, caplog):
    """Confirm that _read_store() logs a warning before raising."""
    store_path = tmp_path / "garbage3.json"
    store_path.write_text("{{{", encoding="utf-8")

    caplog.set_level(logging.WARNING)

    store = CredentialStore(str(store_path))
    with pytest.raises(CredentialStoreCorruptedError):
        store.get("anything")

    # Verify a warning was logged about corruption
    assert any(
        "corrupted" in record.getMessage().lower()
        and str(store_path) in record.getMessage()
        for record in caplog.records
    ), f"No corruption warning found in log records: {[r.getMessage() for r in caplog.records]}"


def test_missing_file_returns_empty_dict(tmp_path):
    """A non-existent file should not raise — missing is expected on first use."""
    store_path = tmp_path / "never_created.json"
    store = CredentialStore(str(store_path))
    # __init__ calls _ensure_store() which creates the file with {}.
    # A fresh store should be empty.
    assert store.list_labels() == []
    assert store.get("anything") is None


def test_integrity_check_clean_write(tmp_path):
    """A clean write should not raise integrity errors."""
    store_path = tmp_path / "clean.json"
    store = CredentialStore(str(store_path))
    store.set("hello", "world")
    assert store.get("hello") == "world"


def test_integrity_check_passes_after_write(tmp_path):
    """Writing valid data should pass _verify_store_integrity()."""
    store_path = tmp_path / "valid.json"
    store = CredentialStore(str(store_path))
    # set() calls _write_store() which calls _verify_store_integrity()
    store.set("a", "1")
    store.set("b", "2")
    # If _verify_store_integrity() failed, it would have raised by now
    assert store.list_labels() == ["a", "b"]


def test_delete_works_after_fix(tmp_path):
    """Normal operations after store is clean should work."""
    store_path = tmp_path / "ops.json"
    store = CredentialStore(str(store_path))
    store.set("temp", "val")
    assert store.delete("temp") is True
    assert store.delete("temp") is False
    assert store.list_labels() == []
