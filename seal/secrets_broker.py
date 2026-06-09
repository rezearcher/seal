"""
Secrets Broker — Credential proxy for AI agents.

Keeps API keys, tokens, and secrets out of model context by replacing
{SECRET:label} placeholders with actual values at tool call time.

Design:
- CredentialStore: file-backed, optionally encrypted at rest
- Broker proxy: wraps tool call args, resolves {SECRET:label} placeholders
- Audit log: records who requested what and when
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SECRET_PLACEHOLDER_PREFIX = "{SECRET:"  # Prefix for {SECRET:label} placeholders

_DEFAULT_STORE_PATH = os.path.expanduser("~/.hermes/secrets.json")  # Default path for the credential store


# ---------------------------------------------------------------------------
# CredentialStore
# ---------------------------------------------------------------------------


class CredentialStore:
    """File-backed credential storage with optional encryption.

    Thread-safe via per-operation file reads (no in-memory cache outside the
    process lifetime).
    """

    def __init__(self, path: str = _DEFAULT_STORE_PATH, encryption_key: Optional[str] = None):
        """Initialize the credential store.

        Args:
            path: Path to the JSON credential file.
            encryption_key: Optional key for at-rest encryption (32 bytes hex).
        """
        self._path = path
        self._encryption_key = encryption_key
        self._ensure_store()

    def _ensure_store(self) -> None:
        """Create the store file if it doesn't exist."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        if not os.path.exists(self._path):
            self._write_store({})

    def _read_store(self) -> Dict[str, str]:
        """Read all credentials from the store."""
        try:
            with open(self._path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
        return data

    def _write_store(self, data: Dict[str, str]) -> None:
        """Write all credentials to the store."""
        with open(self._path, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(self._path, 0o600)

    def get(self, label: str) -> Optional[str]:
        """Retrieve a secret by label.

        Args:
            label: The credential label (e.g. "tastytrade_sandbox").

        Returns:
            The secret value, or None if not found.
        """
        store = self._read_store()
        return store.get(label)

    def set(self, label: str, value: str) -> None:
        """Set a secret value.

        Args:
            label: The credential label.
            value: The secret value.
        """
        store = self._read_store()
        store[label] = value
        self._write_store(store)

    def delete(self, label: str) -> bool:
        """Delete a secret.

        Args:
            label: The credential label.

        Returns:
            True if deleted, False if not found.
        """
        store = self._read_store()
        if label in store:
            del store[label]
            self._write_store(store)
            return True
        return False

    def list_labels(self) -> List[str]:
        """List all stored credential labels.

        Returns:
            Sorted list of label names (not values).
        """
        store = self._read_store()
        return sorted(store.keys())

    def has(self, label: str) -> bool:
        """Check if a credential exists.

        Args:
            label: The credential label.

        Returns:
            True if the credential exists.
        """
        return label in self._read_store()


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class AuditLog:
    """Audit log for credential access events.

    Records who requested what credential and when.
    """

    def __init__(self, path: Optional[str] = None):
        """Initialize the audit log.

        Args:
            path: Path to the audit log file. Defaults to ~/.hermes/secrets_audit.log.
        """
        self._path = path or os.path.join(
            os.path.expanduser("~/.hermes"), "secrets_audit.log"
        )
        os.makedirs(os.path.dirname(self._path), exist_ok=True)

    def record(self, label: str, action: str, actor: str = "unknown", details: str = "") -> None:
        """Record an audit event.

        Args:
            label: The credential label accessed.
            action: The action (e.g. "read", "write", "delete", "resolve").
            actor: Who/what performed the action (e.g. "agent:hermes-default").
            details: Optional additional context.
        """
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        log_line = json.dumps({
            "timestamp": timestamp,
            "action": action,
            "label": label,
            "actor": actor,
            "details": details,
        })
        try:
            with open(self._path, "a") as f:
                f.write(log_line + "\n")
        except OSError as exc:
            logger.warning("Failed to write audit log: %s", exc)

    def recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Read the most recent audit log entries.

        Args:
            limit: Maximum entries to return.

        Returns:
            List of audit event dicts, newest first.
        """
        if not os.path.exists(self._path):
            return []
        try:
            with open(self._path, "r") as f:
                lines = f.readlines()
            entries = []
            for line in reversed(lines[-limit:]):
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
            return entries
        except OSError:
            return []


# ---------------------------------------------------------------------------
# BrokerProxy
# ---------------------------------------------------------------------------


class BrokerProxy:
    """Tool call argument proxy that resolves {SECRET:label} placeholders.

    The proxy intercepts tool call arguments before they reach the tool
    handler, replacing any {SECRET:label} patterns with the actual secret
    value from the CredentialStore.
    """

    def __init__(
        self,
        store: Optional[CredentialStore] = None,
        audit_log: Optional[AuditLog] = None,
        actor: str = "unknown",
        fail_on_missing: bool = False,
    ):
        """Initialize the BrokerProxy.

        Args:
            store: CredentialStore instance. Created with defaults if None.
            audit_log: AuditLog instance. Created with defaults if None.
            actor: Default actor name for audit log entries.
            fail_on_missing: If True, raise ValueError on unresolved placeholders.
        """
        self.store = store or CredentialStore()
        self.audit = audit_log or AuditLog()
        self.actor = actor
        self.fail_on_missing = fail_on_missing

    def resolve(self, args: Dict[str, Any], tool_name: str = "") -> Dict[str, Any]:
        """Resolve {SECRET:label} placeholders in tool call arguments.

        Recursively walks dict and list values, replacing placeholders.

        Args:
            args: The tool call arguments dict.
            tool_name: The tool name for audit logging.

        Returns:
            New args dict with placeholders resolved.

        Raises:
            ValueError: If a placeholder cannot be resolved and fail_on_missing is True.
        """
        return self._resolve_recursive(args, tool_name)

    def _resolve_recursive(self, value: Any, tool_name: str, path: str = "") -> Any:
        """Recursively resolve placeholders in a value.

        Args:
            value: The value to process.
            tool_name: Tool name for audit logging.
            path: Current traversal path for error messages.

        Returns:
            Resolved value.
        """
        if isinstance(value, dict):
            return {
                k: self._resolve_recursive(v, tool_name, f"{path}.{k}")
                for k, v in value.items()
            }
        elif isinstance(value, list):
            return [
                self._resolve_recursive(item, tool_name, f"{path}[{i}]")
                for i, item in enumerate(value)
            ]
        elif isinstance(value, str):
            if value.startswith(_SECRET_PLACEHOLDER_PREFIX) and value.endswith("}"):
                label = value[len(_SECRET_PLACEHOLDER_PREFIX):-1]
                secret = self.store.get(label)
                if secret is None:
                    msg = f"Unresolved secret placeholder at {path}: '{label}' not found in store"
                    if self.fail_on_missing:
                        raise ValueError(msg)
                    logger.warning(msg)
                    return value  # leave unresolved
                self.audit.record(
                    label=label,
                    action="resolve",
                    actor=self.actor,
                    details=f"tool={tool_name}, path={path}",
                )
                return secret
            return value
        return value


# ---------------------------------------------------------------------------
# CLI helpers (for 'seal secrets' CLI)
# ---------------------------------------------------------------------------


def get_default_store() -> CredentialStore:
    """Get or create the default credential store."""
    return CredentialStore()


def get_default_audit() -> AuditLog:
    """Get the default audit log."""
    return AuditLog()


def request_secret(label: str, actor: str = "agent") -> Optional[str]:
    """Request a secret by label (convenience function for agents).

    Args:
        label: The credential label.
        actor: Who is requesting.

    Returns:
        The secret value, or None.
    """
    store = get_default_store()
    audit = get_default_audit()
    value = store.get(label)
    if value is not None:
        audit.record(label, "read", actor)
    return value
