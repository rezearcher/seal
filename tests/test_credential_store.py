"""Tests for seal.credential_store."""

from __future__ import annotations

import os
import stat
import threading

import pytest
from cryptography.fernet import Fernet

from seal.credential_store import CredentialStore, CredentialStoreError


@pytest.fixture
def key() -> bytes:
    return Fernet.generate_key()


@pytest.fixture
def store_path(tmp_path):
    return str(tmp_path / "creds.yaml.enc")


def test_set_and_get(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    store.set("api_key", "s3cret-value")
    assert store.get("api_key") == "s3cret-value"


def test_get_missing_returns_none(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    assert store.get("nope") is None


def test_persistence_reload(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    store.set("token", "abc123")
    store.set("other", "def456")

    reloaded = CredentialStore(store_path, encryption_key=key)
    assert reloaded.get("token") == "abc123"
    assert reloaded.get("other") == "def456"
    assert reloaded.list_labels() == ["other", "token"]


def test_encryption_at_rest(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    store.set("api_key", "PLAINTEXT_SECRET_MARKER")

    raw = open(store_path, "rb").read()
    assert b"PLAINTEXT_SECRET_MARKER" not in raw
    assert b"api_key" not in raw


def test_wrong_key_fails(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    store.set("a", "b")
    with pytest.raises(CredentialStoreError):
        CredentialStore(store_path, encryption_key=Fernet.generate_key())


def test_label_validation(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    for bad in ["has space", "bad/slash", "dollar$", "", "semi;colon"]:
        with pytest.raises(CredentialStoreError):
            store.set(bad, "x")
    for good in ["ok", "ok_one", "ok-two", "OK123"]:
        store.set(good, "x")
        assert store.exists(good)


def test_delete(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    store.set("temp", "v")
    assert store.delete("temp") is True
    assert store.get("temp") is None
    assert store.delete("temp") is False


def test_exists(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    assert store.exists("x") is False
    store.set("x", "y")
    assert store.exists("x") is True


def test_missing_file_returns_empty(tmp_path, key):
    path = str(tmp_path / "does_not_exist.enc")
    store = CredentialStore(path, encryption_key=key)
    assert store.list_labels() == []
    assert store.get("anything") is None


def test_file_permissions_0600(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    store.set("a", "b")
    mode = stat.S_IMODE(os.stat(store_path).st_mode)
    assert mode == 0o600


def test_thread_safety(store_path, key):
    store = CredentialStore(store_path, encryption_key=key)
    errors = []

    def worker(n: int) -> None:
        try:
            for i in range(50):
                label = f"k{n}_{i}"
                store.set(label, f"v{n}_{i}")
                assert store.get(label) == f"v{n}_{i}"
        except Exception as exc:  # pragma: no cover - surfaced via errors list
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(store.list_labels()) == 8 * 50

    reloaded = CredentialStore(store_path, encryption_key=key)
    assert len(reloaded.list_labels()) == 8 * 50
