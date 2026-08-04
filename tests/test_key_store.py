"""Unit tests for seal.key_store — SQLite-backed key lifecycle store.

KeyStore is synchronous (sqlite3 with thread-local connections); all
tests here are plain sync pytest functions using a tmp_path database.
"""

import threading
import time

import pytest

from seal.key_store import KeyInfo, KeyStore

NOW = 1_700_000_000
DAY = 86_400
YEAR = 365 * DAY


@pytest.fixture
def store(tmp_path):
    ks = KeyStore(tmp_path / "keys.db")
    yield ks
    ks.close()


def _gen(store, label="l", not_before=None, not_after=NOW + YEAR, **kw):
    """Create a key with deterministic time defaults."""
    return store.generate_key(
        label=label,
        not_before=not_before,
        not_after=not_after,
        **kw,
    )


# ---------------------------------------------------------------------------
# generate_key
# ---------------------------------------------------------------------------


def test_generate_key_returns_active_keyinfo(store):
    info = _gen(store, label="hermes-prod", now=NOW)
    assert isinstance(info, KeyInfo)
    assert info.label == "hermes-prod"
    assert info.status == "active"
    assert len(info.key_id) == 16
    assert all(c in "0123456789abcdef" for c in info.key_id)
    assert len(info.public_key) == 32
    assert info.private_key is not None
    assert len(info.private_key) == 32
    assert info.not_before == NOW
    assert info.not_after == NOW + YEAR
    assert info.rotation_days == 0
    assert info.created_at == NOW


def test_generate_key_unique_ids(store):
    a = _gen(store, now=NOW)
    b = _gen(store, now=NOW + 1)
    assert a.key_id != b.key_id


def test_generate_key_demotes_existing_active_to_expiring(store):
    first = _gen(store, now=NOW)
    second = _gen(store, now=NOW + 1)

    assert first.status == "active"
    demoted = store.get_key(first.key_id)
    assert demoted.status == "expiring"
    assert second.status == "active"
    assert store.get_active_key("l", now=NOW + 1).key_id == second.key_id


def test_generate_key_custom_time_and_rotation(store):
    info = _gen(store, now=NOW + 100, rotation_days=45, not_after=NOW + 100 + 45 * DAY)
    assert info.not_before == NOW + 100
    assert info.not_after == NOW + 100 + 45 * DAY
    assert info.rotation_days == 45
    assert info.created_at == NOW + 100


def test_generate_key_with_provided_private_key(store):
    priv = b"\x11" * 32
    info = store.generate_key(
        label="l",
        not_before=NOW,
        not_after=NOW + YEAR,
        now=NOW,
        private_key=priv,
    )
    assert info.private_key == priv
    assert len(info.public_key) == 32
    stored = store.get_key(info.key_id)
    assert stored.private_key == priv


# ---------------------------------------------------------------------------
# get_key / get_key_by_label
# ---------------------------------------------------------------------------


def test_get_key_roundtrip(store):
    info = _gen(store, now=NOW)
    got = store.get_key(info.key_id)
    assert got == info


def test_get_key_unknown_returns_none(store):
    assert store.get_key("deadbeefdeadbeef") is None


def test_get_key_by_label_most_recent(store):
    old = _gen(store, now=NOW)
    new = _gen(store, now=NOW + 10)
    assert store.get_key_by_label("l").key_id == new.key_id
    assert old.key_id != new.key_id


def test_get_key_by_label_unknown_returns_none(store):
    assert store.get_key_by_label("missing") is None


# ---------------------------------------------------------------------------
# get_active_key
# ---------------------------------------------------------------------------


def test_get_active_key_two_stage_fallback(store):
    first = _gen(store, now=NOW)
    second = _gen(store, now=NOW + 1)
    # Strict active stage: returns the newest active key
    assert store.get_active_key("l", now=NOW + 1).key_id == second.key_id
    # After revoking the active key, falls back to the expiring-but-valid one
    assert store.revoke_key(second.key_id)
    fallback = store.get_active_key("l", now=NOW + 1)
    assert fallback is not None
    assert fallback.key_id == first.key_id
    assert fallback.status == "expiring"


def test_get_active_key_expired_not_returned(store):
    _gen(store, not_before=NOW - 100, not_after=NOW - 1)
    assert store.get_active_key("l", now=NOW) is None


def test_get_active_key_premature_not_returned(store):
    _gen(store, not_before=NOW + 1000, not_after=NOW + 2000)
    assert store.get_active_key("l", now=NOW) is None


def test_get_active_key_no_keys_returns_none(store):
    assert store.get_active_key("l", now=NOW) is None


# ---------------------------------------------------------------------------
# list_keys
# ---------------------------------------------------------------------------


def test_list_keys_empty(store):
    assert store.list_keys() == []


def test_list_keys_orders_by_created_at_desc(store):
    a = _gen(store, now=NOW)
    b = _gen(store, now=NOW + 5)
    c = _gen(store, now=NOW + 10)
    ids = [k.key_id for k in store.list_keys()]
    assert ids == [c.key_id, b.key_id, a.key_id]


def test_list_keys_label_filter(store):
    _gen(store, label="alpha", now=NOW)
    _gen(store, label="beta", now=NOW)
    assert [k.label for k in store.list_keys(label="alpha")] == ["alpha"]


def test_list_keys_status_filter(store):
    # Distinct labels: same-label generation demotes the prior active key
    # to expiring, which would mask the status filter under test.
    a = _gen(store, label="alpha", now=NOW)
    b = _gen(store, label="beta", now=NOW + 1)
    store.revoke_key(b.key_id)
    assert [k.key_id for k in store.list_keys(status_filter="active")] == [a.key_id]
    assert [k.key_id for k in store.list_keys(status_filter="revoked")] == [b.key_id]


# ---------------------------------------------------------------------------
# revoke_key
# ---------------------------------------------------------------------------


def test_revoke_key_sets_status(store):
    info = _gen(store, now=NOW)
    assert store.revoke_key(info.key_id) is True
    revoked = store.get_key(info.key_id)
    assert revoked.status == "revoked"
    assert not revoked.is_valid_at(NOW)


def test_revoke_key_unknown_returns_false(store):
    assert store.revoke_key("nope") is False


def test_revoke_key_already_revoked_returns_false(store):
    info = _gen(store, now=NOW)
    assert store.revoke_key(info.key_id) is True
    assert store.revoke_key(info.key_id) is False


# ---------------------------------------------------------------------------
# rotate_key
# ---------------------------------------------------------------------------


def test_rotate_key_without_prior_key_returns_none(store):
    assert store.rotate_key("l", rotation_days=30, now=NOW) is None


def test_rotate_key_creates_new_active(store):
    old = _gen(store, now=NOW)
    new = store.rotate_key("l", rotation_days=30, now=NOW + 100)

    assert new is not None
    assert new.key_id != old.key_id
    assert new.status == "active"
    assert new.rotation_days == 30
    assert new.not_before == NOW + 100
    assert new.not_after == NOW + 100 + 30 * DAY

    demoted = store.get_key(old.key_id)
    assert demoted.status == "expiring"
    assert store.get_active_key("l", now=NOW + 100).key_id == new.key_id


def test_rotate_key_default_days(store):
    _gen(store, now=NOW)
    new = store.rotate_key("l", now=NOW + 100)
    assert new is not None
    assert new.rotation_days == 30
    assert new.not_after == NOW + 100 + 30 * DAY


# ---------------------------------------------------------------------------
# needs_rotation
# ---------------------------------------------------------------------------


def test_needs_rotation_empty(store):
    assert store.needs_rotation(now=NOW) == []


def test_needs_rotation_flags_upcoming_and_past(store):
    soon = _gen(store, label="soon", not_after=NOW + 10 * DAY, rotation_days=30, now=NOW)
    at_window = _gen(store, label="at", not_after=NOW + 30 * DAY, rotation_days=30, now=NOW)
    far = _gen(store, label="far", not_after=NOW + 60 * DAY, rotation_days=30, now=NOW)

    flagged = {k.label for k in store.needs_rotation(now=NOW)}
    assert flagged == {soon.label, at_window.label}
    assert far.label not in flagged


def test_needs_rotation_ignores_zero_rotation_days(store):
    _gen(store, not_after=NOW + DAY, rotation_days=0, now=NOW)
    assert store.needs_rotation(now=NOW) == []


def test_needs_rotation_excludes_non_active_statuses(store):
    info = _gen(store, not_after=NOW + DAY, rotation_days=30, now=NOW)
    store.revoke_key(info.key_id)
    assert store.needs_rotation(now=NOW) == []


def test_needs_rotation_orders_by_not_after(store):
    later = _gen(store, label="later", not_after=NOW + 20 * DAY, rotation_days=30, now=NOW)
    earlier = _gen(store, label="earlier", not_after=NOW + 5 * DAY, rotation_days=30, now=NOW)
    assert [k.label for k in store.needs_rotation(now=NOW)] == [earlier.label, later.label]


# ---------------------------------------------------------------------------
# delete_key
# ---------------------------------------------------------------------------


def test_delete_key_removes_record(store):
    info = _gen(store, now=NOW)
    assert store.delete_key(info.key_id) is True
    assert store.get_key(info.key_id) is None
    assert store.list_keys() == []


def test_delete_key_unknown_returns_false(store):
    assert store.delete_key("nope") is False


# ---------------------------------------------------------------------------
# KeyInfo helper methods
# ---------------------------------------------------------------------------


def _info(**overrides):
    fields = dict(
        key_id="k1",
        label="l",
        public_key=b"\x00" * 32,
        private_key=None,
        not_before=NOW,
        not_after=NOW + 1000,
        status="active",
        rotation_days=0,
        created_at=NOW,
    )
    fields.update(overrides)
    return KeyInfo(**fields)  # type: ignore[arg-type] - dynamic kwargs


def test_keyinfo_validity_window():
    info = _info()
    assert info.is_valid_at(NOW + 500)
    assert info.is_valid_at(NOW)  # not_before boundary is inclusive
    assert not info.is_valid_at(NOW - 1)  # premature
    assert not info.is_valid_at(NOW + 1001)  # expired


def test_keyinfo_expiry_relative_to_now():
    # is_expired is a @property whose optional `now` arg is consumed by the
    # descriptor, so exercise it against the real clock with safe margins.
    past = _info(not_after=int(time.time()) - 5)
    assert past.is_expired
    future = _info(not_after=int(time.time()) + 100_000)
    assert not future.is_expired
    no_expiry = _info(not_after=0)
    assert not no_expiry.is_expired


def test_keyinfo_premature_relative_to_now():
    future = _info(not_before=int(time.time()) + 100_000)
    assert future.is_premature
    past = _info(not_before=int(time.time()) - 5)
    assert not past.is_premature
    no_restriction = _info(not_before=0)
    assert not no_restriction.is_premature


def test_keyinfo_no_time_restrictions():
    info = _info(not_before=0, not_after=0)
    assert not info.is_expired
    assert not info.is_premature
    assert info.is_valid_at(NOW)


def test_keyinfo_revoked_never_valid():
    info = _info(status="revoked")
    assert not info.is_valid_at(NOW + 500)


def test_keyinfo_to_dict():
    info = _info(key_id="abc", public_key=b"\x00" * 32, private_key=b"\x01" * 32, rotation_days=30, not_after=0)
    d = info.to_dict()
    assert d == {
        "key_id": "abc",
        "label": "l",
        "public_key_hex": "00" * 32,
        "has_private_key": True,
        "not_before": NOW,
        "not_after": 0,
        "status": "active",
        "rotation_days": 30,
        "created_at": NOW,
    }


def test_keyinfo_to_dict_without_private_key():
    info = _info(private_key=None)
    assert info.to_dict()["has_private_key"] is False


# ---------------------------------------------------------------------------
# Persistence / lifecycle
# ---------------------------------------------------------------------------


def test_persistence_across_instances(tmp_path):
    db = tmp_path / "keys.db"
    ks1 = KeyStore(db)
    info = _gen(ks1, now=NOW)
    ks1.close()

    ks2 = KeyStore(db)
    try:
        assert ks2.get_key(info.key_id) is not None
        assert len(ks2.list_keys()) == 1
    finally:
        ks2.close()


def test_close_then_reuse_reopens_connection(store):
    store.close()
    info = _gen(store, now=NOW)
    assert store.get_key(info.key_id) is not None


def test_concurrent_generation_different_labels(store):
    errors = []

    def worker(label):
        try:
            for _ in range(5):
                _gen(store, label=label, now=NOW)
        except Exception as e:  # pragma: no cover - failure reporter
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(f"label-{i}",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    keys = store.list_keys()
    assert len(keys) == 10
    assert sum(1 for k in keys if k.status == "active") == 2
    for i in range(2):
        active = store.get_active_key(f"label-{i}", now=NOW)
        assert active is not None
        assert active.status == "active"
