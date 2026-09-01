"""Filesystem helpers shared across seal modules.

Centralises the ``mkdir + best-effort chmod 0o700 + warn-on-failure`` logic
that previously lived as near-identical copies in several modules
(``seal.key_manager``, ``seal.cli``, ``seal.credential_store``).  A single
implementation prevents drift in this security-relevant path — prior silent
chmod-swallow bugs (L-001 / L-004 / L-007) all stemmed from diverging copies.
"""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)


def _ensure_seal_dir(path: Path) -> None:
    """Create the directory *path* (creating parents as needed) with ``0700`` perms.

    Best-effort: if the ``chmod`` fails (non-POSIX or restricted filesystem),
    a warning is logged instead of the error being swallowed silently.
    """
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError as exc:  # pragma: no cover - non-POSIX or restricted FS
        log.warning("cannot set 0700 perms on seal dir %s: %s", path, exc)
