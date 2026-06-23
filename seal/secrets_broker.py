"""
Secrets Broker — Credential proxy for AI agents.

.. deprecated::
    This module's legacy ``CredentialStore`` (plaintext JSON) and ``AuditLog``
    classes have been **removed** as part of task ``t_84148f82``.  They were
    replaced by the Fernet-encrypted implementations.

    Use the current modules instead::

        from seal.credential_store import CredentialStore        # encrypted at rest
        from seal.broker import SecretsBroker                    # recommended broker
        from seal.audit import AuditLog                          # audit trail
"""

from __future__ import annotations

import logging

from seal.credential_store import CredentialStore, CredentialStoreCorruptedError

logger = logging.getLogger(__name__)

__all__ = [
    "CredentialStore",
    "CredentialStoreCorruptedError",
]
