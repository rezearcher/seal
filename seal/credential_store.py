"""Credential store — file-backed, encrypted at rest with Fernet.

Credentials live as a flat ``label -> value`` map. The backing file is the
ciphertext produced by Fernet over a YAML (or JSON-fallback) serialization of
that map. The plaintext map is held only in process memory.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

from cryptography.fernet import Fernet, InvalidToken

try:  # PyYAML is a declared dependency; JSON is a graceful fallback.
    import yaml

    _HAVE_YAML = True
except ImportError:  # pragma: no cover - exercised only without PyYAML
    _HAVE_YAML = False

# Labels are also validated at the CLI layer; enforce here too so the store is
# safe to use as a library on its own.
LABEL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

DEFAULT_KEYFILE = Path.home() / ".seal" / "encryption.key"


class CredentialStoreError(Exception):
    """Raised for invalid labels or unreadable/corrupt stores."""


class CredentialStoreCorruptedError(CredentialStoreError):
    """Alias for :exc:`CredentialStoreError` raised on corrupt or unreadable stores.

    Retained for compatibility with code that was migrated from the legacy
    ``seal.secrets_broker.CredentialStoreCorruptedError``.
    """


def _ensure_seal_dir(path: Path) -> None:
    """Create the parent directory (and ~/.seal) with 0700 perms."""
    parent = path.expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
    try:
        parent.chmod(0o700)
    except OSError:  # pragma: no cover - non-POSIX or restricted FS
        pass


def _load_or_create_keyfile(keyfile: Path) -> bytes:
    """Return the Fernet key from ``keyfile``, generating one if absent."""
    keyfile = keyfile.expanduser()
    if keyfile.exists():
        return keyfile.read_bytes().strip()
    _ensure_seal_dir(keyfile)
    key = Fernet.generate_key()
    # Write with 0600 from the start: create exclusively, then chmod.
    fd = os.open(str(keyfile), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:
        keyfile.chmod(0o600)
    except OSError:  # pragma: no cover
        pass
    return key


def validate_label(label: str) -> str:
    """Validate a credential label, returning it unchanged if valid."""
    if not isinstance(label, str) or not LABEL_RE.match(label):
        raise CredentialStoreError(
            f"invalid label {label!r}: must match {LABEL_RE.pattern}"
        )
    return label


class CredentialStore:
    """Thread-safe, Fernet-encrypted key-value credential store."""

    def __init__(self, path: str, encryption_key: bytes | None = None) -> None:
        self.path = Path(path).expanduser()
        if encryption_key is None:
            encryption_key = _load_or_create_keyfile(DEFAULT_KEYFILE)
        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()
        self._fernet = Fernet(encryption_key)
        self._lock = threading.Lock()
        self._data: dict[str, str] = {}
        self._load()

    # ------------------------------------------------------------------ I/O
    def _serialize(self, data: dict[str, str]) -> bytes:
        if _HAVE_YAML:
            return yaml.safe_dump(data, default_flow_style=False).encode("utf-8")
        return json.dumps(data, indent=2).encode("utf-8")

    def _deserialize(self, raw: bytes) -> dict[str, str]:
        text = raw.decode("utf-8")
        if not text.strip():
            return {}
        if _HAVE_YAML:
            parsed = yaml.safe_load(text)
        else:
            parsed = json.loads(text)
        if parsed is None:
            return {}
        if not isinstance(parsed, dict):
            raise CredentialStoreError("credential file did not decode to a mapping")
        return {str(k): str(v) for k, v in parsed.items()}

    def _load(self) -> None:
        """Decrypt and parse the backing file into memory.

        A missing file yields an empty store rather than an error.
        """
        try:
            ciphertext = self.path.read_bytes()
        except FileNotFoundError:
            self._data = {}
            return
        except OSError as exc:
            logger.warning(
                "cannot read credential store %s: %s — initializing empty",
                self.path,
                exc,
            )
            self._data = {}
            return
        if not ciphertext.strip():
            self._data = {}
            return
        try:
            plaintext = self._fernet.decrypt(ciphertext)
        except InvalidToken as exc:
            logger.warning(
                "Credential store corrupt at %s: %s. Raising CredentialStoreCorruptedError.",
                self.path,
                exc,
            )
            raise CredentialStoreCorruptedError(
                f"cannot decrypt {self.path}: wrong key or corrupt file"
            ) from exc
        self._data = self._deserialize(plaintext)

    def _flush(self) -> None:
        """Encrypt the in-memory map and atomically write it with 0600 perms."""
        _ensure_seal_dir(self.path)
        ciphertext = self._fernet.encrypt(self._serialize(self._data))
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, ciphertext)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            tmp.chmod(0o600)
        except OSError:  # pragma: no cover
            pass
        os.replace(tmp, self.path)
        try:
            self.path.chmod(0o600)
        except OSError:  # pragma: no cover
            pass

    # --------------------------------------------------------------- public
    def set(self, label: str, value: str) -> None:
        """Store a credential and write through to disk."""
        validate_label(label)
        if not isinstance(value, str):
            raise CredentialStoreError("credential value must be a string")
        with self._lock:
            self._data[label] = value
            self._flush()

    def get(self, label: str) -> str | None:
        """Return the stored credential, or ``None`` if absent."""
        with self._lock:
            return self._data.get(label)

    def list_labels(self) -> list[str]:
        """Return all credential labels (sorted, values never exposed)."""
        with self._lock:
            return sorted(self._data.keys())

    def delete(self, label: str) -> bool:
        """Remove a credential. Returns ``True`` if it existed."""
        with self._lock:
            if label in self._data:
                del self._data[label]
                self._flush()
                return True
            return False

    def exists(self, label: str) -> bool:
        """Return whether a credential label is present."""
        with self._lock:
            return label in self._data
