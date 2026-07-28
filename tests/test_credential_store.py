"""Tests for seal.credential_store — CredentialStore with corruption handling.

Migrated from the legacy ``seal.secrets_broker.CredentialStore`` (plaintext
JSON) to the Fernet-encrypted ``seal.credential_store.CredentialStore``.

Key behavioural difference: the encrypted store detects corruption eagerly at
construction time (``Fernet.decrypt``), not lazily on the first read operation.
"""

from __future__ import annotations

import logging

import pytest

from seal.credential_store import CredentialStore, CredentialStoreCorruptedError


def test_corrupted_file_raises_at_init(tmp_path):
    """Write a garbage file, expect CredentialStoreCorruptedError at init.

    The encrypted store detects corruption eagerly via ``Fernet.decrypt()``
    which raises ``InvalidToken`` on any non-ciphertext data, wrapped as
    ``CredentialStoreCorruptedError``.
    """
    store_path = tmp_path / "corrupt.bin"
    store_path.write_bytes(b"this is not valid fernet ciphertext")

    with pytest.raises(CredentialStoreCorruptedError) as excinfo:
        CredentialStore(str(store_path))
    assert "corrupt" in str(excinfo.value).lower() or "key" in str(excinfo.value).lower()
    assert str(store_path) in str(excinfo.value)


def test_corrupted_file_logs_warning(tmp_path, caplog):
    """Confirm that _load() logs a warning before raising on corruption."""
    store_path = tmp_path / "garbage.bin"
    store_path.write_bytes(b"garbage_data_that_is_not_valid_ciphertext")

    caplog.set_level(logging.WARNING)

    with pytest.raises(CredentialStoreCorruptedError):
        CredentialStore(str(store_path))

    # Verify a warning was logged about corruption
    assert any(
        "corrupt" in record.getMessage().lower() and str(store_path) in record.getMessage() for record in caplog.records
    ), f"No corruption warning found in log records: {[r.getMessage() for r in caplog.records]}"


def test_missing_file_returns_empty(tmp_path):
    """A non-existent file should not raise — missing is expected on first use."""
    store_path = tmp_path / "never_created.bin"
    store = CredentialStore(str(store_path))
    assert store.list_labels() == []
    assert store.get("anything") is None


def test_clean_write_and_read(tmp_path):
    """A clean write+read cycle should work perfectly."""
    store_path = tmp_path / "clean.bin"
    store = CredentialStore(str(store_path))
    store.set("hello", "world")
    assert store.get("hello") == "world"


def test_multiple_keys_round_trip(tmp_path):
    """Multiple keys should persist correctly."""
    store_path = tmp_path / "multi.bin"
    store = CredentialStore(str(store_path))
    store.set("alpha", "1")
    store.set("beta", "2")
    assert store.list_labels() == ["alpha", "beta"]
    assert store.get("alpha") == "1"
    assert store.get("beta") == "2"


def test_delete(tmp_path):
    """Delete operations should work correctly."""
    store_path = tmp_path / "ops.bin"
    store = CredentialStore(str(store_path))
    store.set("temp", "val")
    assert store.delete("temp") is True
    assert store.delete("temp") is False
    assert store.list_labels() == []


def test_persistence_across_reload(tmp_path):
    """Data written to the store should survive a reload from the same file."""
    store_path = tmp_path / "persist.bin"
    store = CredentialStore(str(store_path))
    store.set("secret", "data")
    del store  # force close

    store2 = CredentialStore(str(store_path))
    assert store2.get("secret") == "data"
    assert store2.list_labels() == ["secret"]


def test_exists(tmp_path):
    """exists() reports presence correctly."""
    store_path = tmp_path / "exists.bin"
    store = CredentialStore(str(store_path))
    assert not store.exists("nope")
    store.set("yes", "here")
    assert store.exists("yes")
