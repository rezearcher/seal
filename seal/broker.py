"""Secrets Broker — resolves ``{SECRET:label}`` placeholders in tool arguments.

The broker is the only component that ever touches plaintext credential values
outside the store. It MUST NOT log, print, or otherwise emit secret values. The
``resolve`` path returns a deep copy so the caller's original argument structure
(which may be retained in prompt/log history) is never mutated to contain a
secret.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from seal.credential_store import CredentialStore

# Matches a *whole-string* placeholder. Whole-string only is deliberate: a
# secret embedded in a larger string (e.g. "Bearer {SECRET:tok}") would leave
# the surrounding literal in context and risk partial leakage, so we treat the
# whole value as the credential reference.
SECRET_PATTERN = re.compile(r"^\{SECRET:([a-zA-Z0-9_-]+)\}$")

REDACTED = "***REDACTED***"


class SecretsBrokerError(Exception):
    """Raised when a referenced secret label cannot be resolved."""


class SecretsBroker:
    """Recursively substitutes secret placeholders in tool-call arguments."""

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _match_label(value: Any) -> str | None:
        """Return the label if ``value`` is a secret placeholder string."""
        if isinstance(value, str):
            m = SECRET_PATTERN.match(value)
            if m:
                return m.group(1)
        return None

    # --------------------------------------------------------------- public
    def resolve(self, value: Any) -> Any:
        """Deep-copy ``value`` and replace every secret placeholder.

        Raises :class:`SecretsBrokerError` if any referenced label is missing.
        """
        return self._walk(copy.deepcopy(value), resolve=True)

    def redact(self, value: Any) -> Any:
        """Deep-copy ``value`` and replace every secret placeholder with a mask.

        Never raises on a missing label and never emits the real value — safe
        for logging and audit trails.
        """
        return self._walk(copy.deepcopy(value), resolve=False)

    def wrap_tool_call(self, tool_name: str, arguments: dict) -> dict:
        """Return ``arguments`` with all secret placeholders resolved.

        ``tool_name`` is accepted for symmetry with a dispatch layer (and could
        feed an audit log); it does not affect resolution.
        """
        if not isinstance(arguments, dict):
            raise SecretsBrokerError("arguments must be a dict")
        return self.resolve(arguments)

    # -------------------------------------------------------------- internal
    def _walk(self, value: Any, *, resolve: bool) -> Any:
        """Recurse over dicts/lists/tuples, substituting placeholder strings."""
        label = self._match_label(value)
        if label is not None:
            if not resolve:
                return REDACTED
            secret = self._store.get(label)
            if secret is None:
                raise SecretsBrokerError(f"unknown secret label: {label!r}")
            return secret

        if isinstance(value, dict):
            return {k: self._walk(v, resolve=resolve) for k, v in value.items()}
        if isinstance(value, list):
            return [self._walk(v, resolve=resolve) for v in value]
        if isinstance(value, tuple):
            return tuple(self._walk(v, resolve=resolve) for v in value)
        return value
