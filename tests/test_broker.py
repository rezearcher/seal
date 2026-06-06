"""Tests for seal.broker."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from seal.broker import REDACTED, SecretsBroker, SecretsBrokerError
from seal.credential_store import CredentialStore


@pytest.fixture
def broker(tmp_path):
    store = CredentialStore(
        str(tmp_path / "creds.enc"), encryption_key=Fernet.generate_key()
    )
    store.set("api_key", "REAL_SECRET_123")
    store.set("token", "tok-abc")
    return SecretsBroker(store)


def test_resolve_simple(broker):
    assert broker.resolve("{SECRET:api_key}") == "REAL_SECRET_123"


def test_resolve_non_placeholder_passthrough(broker):
    assert broker.resolve("plain string") == "plain string"
    assert broker.resolve(42) == 42
    assert broker.resolve(None) is None


def test_resolve_nested_dicts_and_lists(broker):
    payload = {
        "headers": {"Authorization": "{SECRET:token}"},
        "items": ["{SECRET:api_key}", "literal", {"deep": "{SECRET:token}"}],
        "count": 3,
    }
    resolved = broker.resolve(payload)
    assert resolved["headers"]["Authorization"] == "tok-abc"
    assert resolved["items"][0] == "REAL_SECRET_123"
    assert resolved["items"][1] == "literal"
    assert resolved["items"][2]["deep"] == "tok-abc"
    assert resolved["count"] == 3


def test_resolve_raises_on_missing(broker):
    with pytest.raises(SecretsBrokerError):
        broker.resolve("{SECRET:nonexistent}")
    with pytest.raises(SecretsBrokerError):
        broker.resolve({"x": ["{SECRET:nonexistent}"]})


def test_redact_replaces(broker):
    payload = {"auth": "{SECRET:api_key}", "list": ["{SECRET:token}", "keep"]}
    redacted = broker.redact(payload)
    assert redacted["auth"] == REDACTED
    assert redacted["list"][0] == REDACTED
    assert redacted["list"][1] == "keep"


def test_redact_never_leaks_value(broker):
    redacted = broker.redact({"a": "{SECRET:api_key}", "b": "{SECRET:token}"})
    blob = repr(redacted)
    assert "REAL_SECRET_123" not in blob
    assert "tok-abc" not in blob


def test_redact_does_not_raise_on_missing(broker):
    # Redaction is for logging; an unknown label must still mask, not blow up.
    assert broker.redact("{SECRET:nonexistent}") == REDACTED


def test_wrap_tool_call(broker):
    args = {"url": "https://api.example.com", "key": "{SECRET:api_key}"}
    wrapped = broker.wrap_tool_call("http_get", args)
    assert wrapped["key"] == "REAL_SECRET_123"
    assert wrapped["url"] == "https://api.example.com"


def test_wrap_tool_call_rejects_non_dict(broker):
    with pytest.raises(SecretsBrokerError):
        broker.wrap_tool_call("t", ["not", "a", "dict"])


def test_resolve_returns_deep_copy(broker):
    original = {"key": "{SECRET:api_key}", "nested": {"k": "{SECRET:token}"}}
    resolved = broker.resolve(original)
    # Original is untouched — no secret leaks back into caller's structure.
    assert original["key"] == "{SECRET:api_key}"
    assert original["nested"]["k"] == "{SECRET:token}"
    # And it is a genuine copy, not the same object.
    assert resolved is not original
    assert resolved["nested"] is not original["nested"]


def test_partial_string_not_treated_as_secret(broker):
    # Only whole-string placeholders resolve; embedded ones pass through
    # verbatim (and thus never silently leak a secret into a larger literal).
    value = "Bearer {SECRET:api_key}"
    assert broker.resolve(value) == "Bearer {SECRET:api_key}"


def test_tuple_walk(broker):
    resolved = broker.resolve(("{SECRET:token}", "x"))
    assert resolved == ("tok-abc", "x")
