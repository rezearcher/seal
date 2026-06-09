"""Unit tests for Persistent NonceStore and CounterStore."""

import time

import pytest

from seal import CounterStore, NonceStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def nonce_store(tmp_path):
    """Fresh NonceStore backed by a temp database."""
    db = tmp_path / "test_nonces.db"
    store = NonceStore(db_path=db, cleanup_ttl=3600)
    yield store
    store.close()


@pytest.fixture
def counter_store(tmp_path):
    """Fresh CounterStore backed by a temp database."""
    db = tmp_path / "test_counters.db"
    store = CounterStore(db_path=db)
    yield store
    store.close()


# ---------------------------------------------------------------------------
# NonceStore
# ---------------------------------------------------------------------------


class TestNonceStore:
    def test_add_new_nonce(self, nonce_store):
        assert nonce_store.add("abc123") is True

    def test_add_duplicate_nonce_rejected(self, nonce_store):
        nonce_store.add("abc123")
        assert nonce_store.add("abc123") is False  # replay detected

    def test_contains(self, nonce_store):
        nonce_store.add("nonce-001")
        assert nonce_store.contains("nonce-001") is True
        assert nonce_store.contains("nonce-999") is False

    def test_size(self, nonce_store):
        assert nonce_store.size == 0
        nonce_store.add("a")
        nonce_store.add("b")
        nonce_store.add("c")
        assert nonce_store.size == 3

    def test_remove_existing(self, nonce_store):
        nonce_store.add("to-remove")
        assert nonce_store.remove("to-remove") is True
        assert nonce_store.contains("to-remove") is False
        assert nonce_store.size == 0

    def test_remove_missing(self, nonce_store):
        assert nonce_store.remove("never-added") is False

    def test_empty_string_nonce(self, nonce_store):
        assert nonce_store.add("") is True
        assert nonce_store.add("") is False  # duplicate

    def test_long_nonce(self, nonce_store):
        long_nonce = "x" * 1000
        assert nonce_store.add(long_nonce) is True
        assert nonce_store.contains(long_nonce) is True

    def test_unicode_nonce(self, nonce_store):
        assert nonce_store.add("日本語-🚀-nonce") is True
        assert nonce_store.contains("日本語-🚀-nonce") is True

    def test_many_nonces(self, nonce_store):
        """Add 1000 unique nonces."""
        for i in range(1000):
            assert nonce_store.add(f"nonce-{i}") is True
        assert nonce_store.size == 1000
        # Verify all exist
        for i in range(1000):
            assert nonce_store.contains(f"nonce-{i}") is True

    def test_survives_restart(self, tmp_path):
        """NonceStore data persists across instances (SQLite durability)."""
        db = tmp_path / "persist.db"
        store1 = NonceStore(db_path=db)
        store1.add("persistent-nonce")
        store1.close()

        store2 = NonceStore(db_path=db)
        assert store2.contains("persistent-nonce") is True
        assert store2.size == 1
        store2.close()

    def test_add_after_restart_rejects_duplicate(self, tmp_path):
        db = tmp_path / "dup.db"
        store1 = NonceStore(db_path=db)
        store1.add("duplicate-check")
        store1.close()

        store2 = NonceStore(db_path=db)
        assert store2.add("duplicate-check") is False  # still recorded
        store2.close()

    def test_cleanup_removes_expired(self, tmp_path):
        """Force cleanup removes nonces older than the TTL."""
        db = tmp_path / "cleanup.db"
        # Use a short TTL (1 second)
        store = NonceStore(db_path=db, cleanup_ttl=1)
        store.add("will-expire")
        store.add("will-expire-too")

        # Wait for TTL + margin to ensure integer-second cutoff passes
        time.sleep(2.1)

        # Add a fresh nonce — this triggers auto-cleanup
        store.add("fresh")

        # Expired nonces should be gone
        assert store.contains("will-expire") is False
        assert store.contains("fresh") is True

    def test_force_cleanup_returns_count(self, nonce_store):
        nonce_store.add("a")
        nonce_store.add("b")
        # Since TTL is 3600 and we just added, force_cleanup should delete 0
        assert nonce_store.force_cleanup() == 0

    def test_force_cleanup_after_ttl(self, tmp_path):
        db = tmp_path / "cleanup2.db"
        store = NonceStore(db_path=db, cleanup_ttl=1)
        store.add("expired")
        time.sleep(2.1)
        count = store.force_cleanup()
        assert count == 1
        assert store.size == 0

    def test_close_reopenable(self, nonce_store):
        nonce_store.add("close-test")
        nonce_store.close()
        # After close, should get a new connection on next access
        assert nonce_store.contains("close-test") is True

    def test_auto_creates_directory(self, tmp_path):
        """Store should create the directory if it doesn't exist."""
        nested = tmp_path / "deep" / "nested" / "store.db"
        store = NonceStore(db_path=nested)
        store.add("dir-creation-test")
        assert store.contains("dir-creation-test") is True
        assert nested.exists()
        store.close()


# ---------------------------------------------------------------------------
# CounterStore
# ---------------------------------------------------------------------------


class TestCounterStore:
    def test_get_missing(self, counter_store):
        assert counter_store.get("issuer:alice", "agent:bob") is None

    def test_set_and_get(self, counter_store):
        counter_store.set("issuer:alice", "agent:bob", 42)
        assert counter_store.get("issuer:alice", "agent:bob") == 42

    def test_update_counter(self, counter_store):
        counter_store.set("issuer:alice", "agent:bob", 1)
        assert counter_store.get("issuer:alice", "agent:bob") == 1
        counter_store.set("issuer:alice", "agent:bob", 5)
        assert counter_store.get("issuer:alice", "agent:bob") == 5

    def test_independent_keys(self, counter_store):
        counter_store.set("issuer:alice", "agent:bob", 10)
        counter_store.set("issuer:carol", "agent:dave", 20)
        assert counter_store.get("issuer:alice", "agent:bob") == 10
        assert counter_store.get("issuer:carol", "agent:dave") == 20

    def test_delete_existing(self, counter_store):
        counter_store.set("issuer:alice", "agent:bob", 42)
        assert counter_store.delete("issuer:alice", "agent:bob") is True
        assert counter_store.get("issuer:alice", "agent:bob") is None

    def test_delete_missing(self, counter_store):
        assert counter_store.delete("ghost", "pair") is False

    def test_size(self, counter_store):
        assert counter_store.size == 0
        counter_store.set("a", "b", 1)
        counter_store.set("c", "d", 2)
        assert counter_store.size == 2

    def test_size_after_delete(self, counter_store):
        counter_store.set("a", "b", 1)
        counter_store.set("c", "d", 2)
        counter_store.delete("a", "b")
        assert counter_store.size == 1

    def test_large_counter_value(self, counter_store):
        large = 2**31 - 1  # max 32-bit signed int
        counter_store.set("issuer:sys", "agent:batch", large)
        assert counter_store.get("issuer:sys", "agent:batch") == large

    def test_survives_restart(self, tmp_path):
        db = tmp_path / "counter_persist.db"
        store1 = CounterStore(db_path=db)
        store1.set("issuer:persist", "agent:check", 99)
        store1.close()

        store2 = CounterStore(db_path=db)
        assert store2.get("issuer:persist", "agent:check") == 99
        store2.close()

    def test_monotonic_example(self, counter_store):
        """Demonstrate intended usage pattern: verify monotonicity."""
        issuer = "user:rez"
        audience = "agent:hermes-default"
        last = counter_store.get(issuer, audience)
        assert last is None  # first time

        # First prompt, counter=1
        assert 1 > (last or 0)
        counter_store.set(issuer, audience, 1)
        last = 1

        # Second prompt, counter=2
        assert 2 > last
        counter_store.set(issuer, audience, 2)
        last = 2

        # Replay / skip would be counter <= last
        assert not (2 > last)  # 2 is not > 2

    def test_close_reopenable(self, counter_store):
        counter_store.set("a", "b", 100)
        counter_store.close()
        assert counter_store.get("a", "b") == 100

    def test_auto_creates_directory(self, tmp_path):
        nested = tmp_path / "deep" / "nested" / "counters.db"
        store = CounterStore(db_path=nested)
        store.set("issuer:test", "agent:test", 1)
        assert store.get("issuer:test", "agent:test") == 1
        assert nested.exists()
        store.close()


# ---------------------------------------------------------------------------
# Shared DB — NonceStore and CounterStore coexisting
# ---------------------------------------------------------------------------


class TestSharedDB:
    def test_same_db_both_stores(self, tmp_path):
        """NonceStore and CounterStore can share the same SQLite database."""
        db = tmp_path / "shared.db"
        nstore = NonceStore(db_path=db)
        cstore = CounterStore(db_path=db)

        nstore.add("shared-nonce")
        cstore.set("issuer:shared", "agent:test", 7)

        assert nstore.contains("shared-nonce") is True
        assert cstore.get("issuer:shared", "agent:test") == 7

        nstore.close()
        cstore.close()

    def test_independent_tables(self, tmp_path):
        """Tables are independent — operations on one don't affect the other."""
        db = tmp_path / "independent.db"
        nstore = NonceStore(db_path=db)
        cstore = CounterStore(db_path=db)

        nstore.add("nonce-data")
        cstore.set("counter-issuer", "counter-audience", 42)

        assert nstore.size == 1
        assert cstore.size == 1

        nstore.close()
        cstore.close()
