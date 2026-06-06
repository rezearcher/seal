"""Seal — Verified Prompt Envelope Protocol & AI Agent Security.

Secrets Broker subsystem: keeps API keys/tokens out of model context.
"""

__version__ = "0.1.0"

from seal.audit import AuditLog
from seal.broker import SecretsBroker, SecretsBrokerError
from seal.credential_store import CredentialStore

__all__ = [
    "AuditLog",
    "CredentialStore",
    "SecretsBroker",
    "SecretsBrokerError",
]
