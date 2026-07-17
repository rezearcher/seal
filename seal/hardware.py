"""Hardware Security Module (HSM) abstraction for VPE.

Supports three hardware backends and a software simulation for testing:

- YubiKey PIV mode  — ``ykman piv`` subprocess (Linux/macOS)
- TPM (Linux)       — ``tpm2-tools`` subprocess
- macOS Secure
  Enclave           — ``security`` CLI subprocess (macOS only)
- SoftwareSim       — Pure-Python simulation routed through the same
                      interface (for testing / demo without hardware)

Each provider implements ``generate()`` + ``sign()``.  The ``HsmManager``
discovers available providers at runtime and routes signing operations.

Algorithm mapping
-----------------
+--------------------+----------+-------------+
| Provider           | Key type | Sig algo    |
+--------------------+----------+-------------+
| YubiKey PIV        | ECC P-256 | ecdsa-p256 |
| TPM (tpm2-tools)   | ECC P-256 | ecdsa-p256 |
| Secure Enclave     | ECC P-256 | ecdsa-p256 |
| YubiKey OpenPGP    | Ed25519  | ed25519     |
| SoftwareSim        | Ed25519  | ed25519     |
+--------------------+----------+-------------+

When the hardware only supports ECC P-256, the canonical payload is
SHA-256-hashed first, then signed with ECDSA.  The envelope carries
``sig_algorithm`` so the verifier knows which path to take.
"""

from __future__ import annotations

import abc
import hashlib
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SIG_ALG_ED25519 = "ed25519"
SIG_ALG_ECDSA_P256 = "ecdsa-p256"

# YubiKey PIV slot used for signing (9d = PIV Authentication / signing)
_YUBIKEY_PIV_SLOT = "9d"


# ---------------------------------------------------------------------------


class HsmError(Exception):
    """Error from hardware security module operations."""


# ---------------------------------------------------------------------------
# Key info record
# ---------------------------------------------------------------------------


logger = logging.getLogger(__name__)


@dataclass
class HsmKey:
    """Record of a key stored in or managed by a hardware provider."""

    key_id: str
    label: str
    provider_name: str
    sig_algorithm: str  # ed25519 | ecdsa-p256
    public_key: bytes
    created_at: int

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "label": self.label,
            "provider": self.provider_name,
            "sig_algorithm": self.sig_algorithm,
            "public_key_hex": self.public_key.hex(),
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Abstract provider
# ---------------------------------------------------------------------------


class HsmProvider(abc.ABC):
    """Abstract base for hardware key providers."""

    name: ClassVar[str] = ""
    supported_platforms: ClassVar[list[str]] = []
    sig_algorithm: ClassVar[str] = ""

    @classmethod
    @abc.abstractmethod
    def detect(cls) -> bool:
        """Return True if this hardware is available on the current system."""
        ...

    @abc.abstractmethod
    def generate(self, label: str) -> HsmKey:
        """Generate a new key on the hardware.

        The private key stays on the device.  Returns an ``HsmKey``
        record with the public key and metadata.
        """
        ...

    @abc.abstractmethod
    def sign(self, canonical_payload: bytes, key_id: str) -> bytes:
        """Sign a canonical payload with the hardware key.

        Returns raw signature bytes (DER-encoded for ECDSA, fixed 64-byte
        for Ed25519).
        """
        ...

    @abc.abstractmethod
    def get_public_key(self, key_id: str) -> bytes | None:
        """Retrieve the public key for a key ID, or None if not found."""
        ...

    def list_keys(self) -> list[HsmKey]:
        """List keys managed by this provider."""
        return []

    def delete_key(self, key_id: str) -> bool:
        """Remove a key record.  Returns True if removed."""
        return False


# ---------------------------------------------------------------------------
# YubiKey PIV provider  (ykman piv subprocess)
# ---------------------------------------------------------------------------


class YubiKeyPIVProvider(HsmProvider):
    """YubiKey PIV mode — ECC P-256 keys on the PIV applet.

    Requires ``ykman`` CLI installed and a YubiKey with PIV enabled.
    Keys live in PIV slot 9d (PIV Authentication / general signing).
    """

    name = "yubikey"
    supported_platforms = ["linux", "darwin"]
    sig_algorithm = SIG_ALG_ECDSA_P256

    # In-memory registry of generated keys (we track them because the
    # PIV slot is fixed — we manage one active key per slot).
    _keys: dict[str, HsmKey] = {}

    @classmethod
    def detect(cls) -> bool:
        """Check if ykman is installed and a YubiKey is connected."""
        if not shutil.which("ykman"):
            return False
        try:
            result = subprocess.run(
                ["ykman", "piv", "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def generate(self, label: str) -> HsmKey:
        """Generate a new ECC P-256 key on the YubiKey in PIV slot 9d.

        The private key is generated *inside* the YubiKey and never
        exported.  The public key is exported and returned.
        """
        key_id = f"yk_piv_{label}_{int(time.time())}"

        # Generate key on the YubiKey
        with tempfile.TemporaryDirectory() as tmp:
            pubkey_pem = os.path.join(tmp, "pubkey.pem")

            try:
                subprocess.run(
                    [
                        "ykman",
                        "piv",
                        "keys",
                        "generate",
                        "--algorithm",
                        "ECCP256",
                        _YUBIKEY_PIV_SLOT,
                        pubkey_pem,
                    ],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error(
                    "YubiKey PIV key generation failed (exit=%d): %s",
                    exc.returncode,
                    exc.stderr.strip(),
                )
                raise HsmError(
                    f"YubiKey PIV key generation failed: {exc.stderr.strip()}"
                ) from exc
            except subprocess.TimeoutExpired:
                logger.error("YubiKey PIV key generation timed out after 30s")
                raise HsmError("YubiKey PIV key generation timed out after 30s")

            # Read the public key
            public_key = _load_ec_pubkey_from_pem(pubkey_pem)

        key = HsmKey(
            key_id=key_id,
            label=label,
            provider_name=self.name,
            sig_algorithm=self.sig_algorithm,
            public_key=public_key,
            created_at=int(time.time()),
        )
        self._keys[key_id] = key
        return key

    def sign(self, canonical_payload: bytes, key_id: str) -> bytes:
        """Sign the SHA-256 hash of canonical_payload using PIV slot.

        The YubiKey PIV applet signs a hash, not raw data.  We hash
        the canonical payload with SHA-256 first, then sign the hash.
        """
        payload_hash = hashlib.sha256(canonical_payload).digest()

        with tempfile.TemporaryDirectory() as tmp:
            hash_file = os.path.join(tmp, "payload.hash")
            sig_file = os.path.join(tmp, "payload.sig")

            Path(hash_file).write_bytes(payload_hash)

            try:
                subprocess.run(
                    [
                        "ykman",
                        "piv",
                        "sign",
                        "--algorithm",
                        "ECDSA",
                        _YUBIKEY_PIV_SLOT,
                        hash_file,
                        sig_file,
                    ],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error(
                    "YubiKey PIV signing failed (exit=%d): %s",
                    exc.returncode,
                    exc.stderr.strip(),
                )
                raise HsmError(
                    f"YubiKey PIV signing failed: {exc.stderr.strip()}"
                ) from exc
            except subprocess.TimeoutExpired:
                logger.error("YubiKey PIV signing timed out after 30s")
                raise HsmError("YubiKey PIV signing timed out after 30s")

            return Path(sig_file).read_bytes()

    def get_public_key(self, key_id: str) -> bytes | None:
        """Return public key bytes for a tracked key."""
        key = self._keys.get(key_id)
        return key.public_key if key else None

    def list_keys(self) -> list[HsmKey]:
        return list(self._keys.values())


# ---------------------------------------------------------------------------
# TPM provider  (tpm2-tools subprocess)
# ---------------------------------------------------------------------------


class TPMProvider(HsmProvider):
    """TPM (Linux) — ECC P-256 keys via tpm2-tools.

    Requires ``tpm2-tools`` package installed and a TPM device
    (``/dev/tpm0`` or ``/dev/tpmrm0``) available.
    """

    name = "tpm"
    supported_platforms = ["linux"]
    sig_algorithm = SIG_ALG_ECDSA_P256

    _keys: dict[str, HsmKey] = {}

    @classmethod
    def detect(cls) -> bool:
        """Check if tpm2-tools are installed and a TPM device exists."""
        if not shutil.which("tpm2_createprimary"):
            return False
        # Check for TPM device
        if not os.path.exists("/dev/tpm0") and not os.path.exists("/dev/tpmrm0"):
            return False
        # Quick liveness check
        try:
            result = subprocess.run(
                ["tpm2_getcap", "properties-fixed"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def generate(self, label: str) -> HsmKey:
        """Generate an ECC P-256 key inside the TPM.

        Primary key + child key created under the TPM's storage hierarchy.
        The private key object is saved and the public key is exported.
        """
        key_id = f"tpm_{label}_{int(time.time())}"

        with tempfile.TemporaryDirectory() as tmp:
            primary_ctx = os.path.join(tmp, "primary.ctx")
            key_pub = os.path.join(tmp, "key.pub")
            key_priv = os.path.join(tmp, "key.priv")
            key_ctx = os.path.join(tmp, "key.ctx")
            pubkey_pem = os.path.join(tmp, "pubkey.pem")

            # Create primary key in storage hierarchy
            try:
                subprocess.run(
                    ["tpm2_createprimary", "-c", primary_ctx, "-Q"],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error("TPM createprimary failed (exit=%d): %s", exc.returncode, exc.stderr.strip())
                raise HsmError(f"TPM createprimary failed: {exc.stderr.strip()}") from exc
            except subprocess.TimeoutExpired:
                logger.error("TPM createprimary timed out after 30s")
                raise HsmError("TPM createprimary timed out after 30s")

            # Create ECC P-256 key
            try:
                subprocess.run(
                    [
                        "tpm2_create",
                        "-C",
                        primary_ctx,
                        "-G",
                        "ecc256:ecdsa",
                        "-u",
                        key_pub,
                        "-r",
                        key_priv,
                        "-Q",
                    ],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error("TPM create key failed (exit=%d): %s", exc.returncode, exc.stderr.strip())
                raise HsmError(f"TPM create key failed: {exc.stderr.strip()}") from exc
            except subprocess.TimeoutExpired:
                logger.error("TPM create key timed out after 30s")
                raise HsmError("TPM create key timed out after 30s")

            # Load into context
            try:
                subprocess.run(
                    ["tpm2_load", "-C", primary_ctx, "-u", key_pub, "-r", key_priv, "-c", key_ctx, "-Q"],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error("TPM load key failed (exit=%d): %s", exc.returncode, exc.stderr.strip())
                raise HsmError(f"TPM load key failed: {exc.stderr.strip()}") from exc
            except subprocess.TimeoutExpired:
                logger.error("TPM load key timed out after 30s")
                raise HsmError("TPM load key timed out after 30s")

            # Read public key
            try:
                subprocess.run(
                    ["tpm2_readpublic", "-c", key_ctx, "-o", pubkey_pem, "-Q"],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error("TPM readpublic failed (exit=%d): %s", exc.returncode, exc.stderr.strip())
                raise HsmError(f"TPM readpublic failed: {exc.stderr.strip()}") from exc
            except subprocess.TimeoutExpired:
                logger.error("TPM readpublic timed out after 30s")
                raise HsmError("TPM readpublic timed out after 30s")
            public_key = _load_ec_pubkey_from_pem(pubkey_pem)

            # Persist the key context for later signing
            persist_dir = _tpm_persist_dir()
            persist_dir.mkdir(parents=True, exist_ok=True)
            persist_ctx = persist_dir / f"{key_id}.ctx"
            try:
                subprocess.run(
                    ["tpm2_evictcontrol", "-c", key_ctx, "-o", str(persist_ctx), "-Q"],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error("TPM evictcontrol failed (exit=%d): %s", exc.returncode, exc.stderr.strip())
                raise HsmError(f"TPM evictcontrol failed: {exc.stderr.strip()}") from exc
            except subprocess.TimeoutExpired:
                logger.error("TPM evictcontrol timed out after 30s")
                raise HsmError("TPM evictcontrol timed out after 30s")

        key = HsmKey(
            key_id=key_id,
            label=label,
            provider_name=self.name,
            sig_algorithm=self.sig_algorithm,
            public_key=public_key,
            created_at=int(time.time()),
        )
        self._keys[key_id] = key
        return key

    def sign(self, canonical_payload: bytes, key_id: str) -> bytes:
        """Sign canonical_payload using the TPM key.

        The TPM signs the raw data digest (tpm2_sign handles hashing
        internally when -g sha256 is given).
        """
        persist_dir = _tpm_persist_dir()
        key_ctx = persist_dir / f"{key_id}.ctx"
        if not key_ctx.exists():
            raise FileNotFoundError(f"TPM key context not found: {key_ctx}")

        with tempfile.TemporaryDirectory() as tmp:
            msg_file = os.path.join(tmp, "msg.bin")
            sig_file = os.path.join(tmp, "sig.bin")

            Path(msg_file).write_bytes(canonical_payload)

            try:
                subprocess.run(
                    [
                        "tpm2_sign",
                        "-c",
                        str(key_ctx),
                        "-g",
                        "sha256",
                        "-o",
                        sig_file,
                        "-f",
                        "plain",
                        msg_file,
                    ],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error("TPM sign failed (exit=%d): %s", exc.returncode, exc.stderr.strip())
                raise HsmError(f"TPM sign failed: {exc.stderr.strip()}") from exc
            except subprocess.TimeoutExpired:
                logger.error("TPM sign timed out after 30s")
                raise HsmError("TPM sign timed out after 30s")

            return Path(sig_file).read_bytes()

    def get_public_key(self, key_id: str) -> bytes | None:
        key = self._keys.get(key_id)
        return key.public_key if key else None

    def list_keys(self) -> list[HsmKey]:
        return list(self._keys.values())

    def delete_key(self, key_id: str) -> bool:
        if key_id in self._keys:
            del self._keys[key_id]
            # Remove persisted context
            ctx = _tpm_persist_dir() / f"{key_id}.ctx"
            if ctx.exists():
                ctx.unlink()
            return True
        return False


def _tpm_persist_dir() -> Path:
    return Path.home() / ".seal" / "tpm"


# ---------------------------------------------------------------------------
# Secure Enclave provider  (macOS security CLI)
# ---------------------------------------------------------------------------


class SecureEnclaveProvider(HsmProvider):
    """macOS Secure Enclave — ECC P-256 via Security.framework CLI.

    Requires macOS with a Secure Enclave (T1/T2 chip or Apple Silicon).
    Uses ``security`` CLI to create and manage keys.
    """

    name = "enclave"
    supported_platforms = ["darwin"]
    sig_algorithm = SIG_ALG_ECDSA_P256

    # Stable directory for persisting Secure Enclave key references
    _keys_dir = os.path.expanduser("~/.seal/enclave-keys")
    _keys: dict[str, HsmKey] = {}

    @classmethod
    def _ensure_keys_dir(cls) -> str:
        os.makedirs(cls._keys_dir, exist_ok=True)
        return cls._keys_dir

    @classmethod
    def detect(cls) -> bool:
        """Check if we're on macOS with ``security`` CLI available."""
        if platform.system() != "Darwin":
            return False
        # Verify security CLI exists (it's built-in on macOS)
        security_path = shutil.which("security")
        if not security_path:
            return False
        # Quick check for Secure Enclave support
        try:
            result = subprocess.run(
                [security_path, "list-keychains"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def generate(self, label: str) -> HsmKey:
        """Generate an ECC P-256 key in the Secure Enclave.

        Uses ``security create-keypair`` with Secure Enclave flag.
        The private key never leaves the Enclave.

        Key reference PEMs are persisted to ``~/.seal/enclave-keys/``
        so the provider can find them for signing later.
        """
        key_id = f"enclave_{label}_{int(time.time())}"

        keys_dir = self._ensure_keys_dir()
        priv_pem = os.path.join(keys_dir, f"{key_id}.pem")
        pub_pem = os.path.join(keys_dir, f"{key_id}.pub.pem")

        try:
            subprocess.run(
                [
                    "security",
                    "create-keypair",
                    "-k",
                    priv_pem,
                    "-p",
                    pub_pem,
                    "-s",  # Secure Enclave
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            logger.error(
                "Secure Enclave key generation failed (exit=%d): %s",
                exc.returncode,
                exc.stderr.strip(),
            )
            raise HsmError(
                f"Secure Enclave key generation failed: {exc.stderr.strip()}"
            ) from exc
        except subprocess.TimeoutExpired:
            logger.error("Secure Enclave key generation timed out after 30s")
            raise HsmError("Secure Enclave key generation timed out after 30s")

        public_key = _load_ec_pubkey_from_pem(pub_pem)

        key = HsmKey(
            key_id=key_id,
            label=label,
            provider_name=self.name,
            sig_algorithm=self.sig_algorithm,
            public_key=public_key,
            created_at=int(time.time()),
        )
        self._keys[key_id] = key
        return key

    def sign(self, canonical_payload: bytes, key_id: str) -> bytes:
        """Sign with the Secure Enclave key using ``security sign``.

        The Security framework expects the data to sign, which it
        hashes internally. The key is resolved from the persisted
        PEM reference file written during ``generate()``.
        """
        key = self._keys.get(key_id)
        if key is None:
            raise KeyError(f"Secure Enclave key not found: {key_id}")

        # Resolve the persisted private key reference PEM
        priv_pem = os.path.join(self._keys_dir, f"{key_id}.pem")
        if not os.path.exists(priv_pem):
            raise KeyError(
                f"Secure Enclave key PEM not found at {priv_pem}; "
                f"the key may have been generated on another machine "
                f"or the ~/.seal/enclave-keys/ directory was removed."
            )

        with tempfile.TemporaryDirectory() as tmp:
            data_file = os.path.join(tmp, "data.bin")
            sig_file = os.path.join(tmp, "data.sig")
            Path(data_file).write_bytes(canonical_payload)

            try:
                subprocess.run(
                    [
                        "security",
                        "sign",
                        "-k",
                        priv_pem,  # PEM with keychain persistent reference
                        "-o",
                        sig_file,
                        data_file,
                    ],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                logger.error(
                    "Secure Enclave signing failed (exit=%d): %s",
                    exc.returncode,
                    exc.stderr.strip(),
                )
                raise HsmError(
                    f"Secure Enclave signing failed: {exc.stderr.strip()}"
                ) from exc
            except subprocess.TimeoutExpired:
                logger.error("Secure Enclave signing timed out after 30s")
                raise HsmError("Secure Enclave signing timed out after 30s")

            return Path(sig_file).read_bytes()

    def get_public_key(self, key_id: str) -> bytes | None:
        key = self._keys.get(key_id)
        return key.public_key if key else None

    def list_keys(self) -> list[HsmKey]:
        return list(self._keys.values())


# ---------------------------------------------------------------------------
# Software simulation provider (for testing without hardware)
# ---------------------------------------------------------------------------


class SoftwareSimProvider(HsmProvider):
    """Software simulation of HSM for testing / demo.

    Generates standard Ed25519 keys in software but routes through the
    same ``HsmProvider`` interface.  Private key bytes are stored in
    memory (NOT hardware-backed — for testing only).
    """

    name = "software-sim"
    supported_platforms = ["linux", "darwin", "windows"]
    sig_algorithm = SIG_ALG_ED25519

    def __init__(self):
        """Initialize with empty key stores (instance-level, not shared)."""
        self._keys: dict[str, HsmKey] = {}
        self._privkeys: dict[str, bytes] = {}

    @classmethod
    def detect(cls) -> bool:
        """Always available — pure Python."""
        return True

    def generate(self, label: str) -> HsmKey:
        """Generate an Ed25519 key pair in memory."""
        key_id = f"sim_{label}_{int(time.time())}"

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes_raw()

        key = HsmKey(
            key_id=key_id,
            label=label,
            provider_name=self.name,
            sig_algorithm=self.sig_algorithm,
            public_key=pub_bytes,
            created_at=int(time.time()),
        )
        self._keys[key_id] = key
        self._privkeys[key_id] = private_key.private_bytes_raw()
        return key

    def sign(self, canonical_payload: bytes, key_id: str) -> bytes:
        sk_bytes = self._privkeys.get(key_id)
        if sk_bytes is None:
            raise KeyError(f"Software key not found: {key_id}")
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(sk_bytes)
        return sk.sign(canonical_payload)

    def get_public_key(self, key_id: str) -> bytes | None:
        key = self._keys.get(key_id)
        return key.public_key if key else None

    def list_keys(self) -> list[HsmKey]:
        return list(self._keys.values())

    def delete_key(self, key_id: str) -> bool:
        if key_id in self._keys:
            del self._keys[key_id]
            self._privkeys.pop(key_id, None)
            return True
        return False


# ---------------------------------------------------------------------------
# PEM / key helpers
# ---------------------------------------------------------------------------


def _load_ec_pubkey_from_pem(pem_path: str) -> bytes:
    """Load an ECC P-256 public key from a PEM file and return raw SPKI bytes."""
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    from cryptography.hazmat.primitives.asymmetric import ec as ecc

    try:
        key = serialization.load_pem_public_key(pem_data)
    except Exception:
        # Some tools export SubjectPublicKeyInfo differently
        key = serialization.load_der_public_key(pem_data)
    if not isinstance(key, ecc.EllipticCurvePublicKey):
        raise ValueError("PEM does not contain an EC public key")
    # Return SPKI-encoded public key bytes
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# ECDSA P-256 verification
# ---------------------------------------------------------------------------


def verify_ecdsa_p256(
    signature: bytes,
    payload: bytes,
    public_key_der: bytes,
) -> bool:
    """Verify an ECDSA P-256 signature over a SHA-256 hash of the payload.

    Args:
        signature: Raw DER-encoded ECDSA signature.
        payload: The original payload bytes.
        public_key_der: SPKI/DER-encoded ECC P-256 public key.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        pk = serialization.load_der_public_key(public_key_der)
    except Exception:
        return False

    if not isinstance(pk, ec.EllipticCurvePublicKey):
        return False
    if not isinstance(pk.curve, ec.SECP256R1):
        return False

    payload_hash = hashlib.sha256(payload).digest()

    try:
        pk.verify(signature, payload_hash, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# HSM Manager — detection and routing
# ---------------------------------------------------------------------------


class HsmManager:
    """Detects available hardware providers and routes signing operations.

    Usage::

        mgr = HsmManager()
        providers = mgr.discover()       # [SoftwareSimProvider, ...]
        yk = mgr.get_provider("yubikey") # YubiKeyPIVProvider instance
        key = yk.generate("my-key")
        sig = yk.sign(canonical_payload, key.key_id)
    """

    _PROVIDER_CLASSES: list[type[HsmProvider]] = [
        YubiKeyPIVProvider,
        TPMProvider,
        SecureEnclaveProvider,
        SoftwareSimProvider,  # fallback — always available
    ]

    def __init__(self) -> None:
        self._providers: dict[str, HsmProvider] = {}

    def discover(self) -> list[HsmProvider]:
        """Probe all providers and return the available ones.

        Always includes ``SoftwareSimProvider`` at the end.
        """
        available: list[HsmProvider] = []
        for cls in self._PROVIDER_CLASSES:
            if cls.detect():
                provider = cls()  # type: ignore[abstract]
                self._providers[provider.name] = provider
                available.append(provider)
        return available

    def get_provider(self, name: str) -> HsmProvider | None:
        """Get a specific provider by name, discovering if needed."""
        if name not in self._providers:
            self.discover()
        return self._providers.get(name)

    @property
    def default_provider(self) -> HsmProvider:
        """Return the best available hardware provider, or software sim.

        Priority: YubiKey > TPM > Secure Enclave > SoftwareSim.
        """
        self.discover()
        for name in ("yubikey", "tpm", "enclave"):
            if name in self._providers:
                return self._providers[name]
        # SoftwareSim is always available
        return self._providers.get("software-sim", SoftwareSimProvider())

    def available_providers(self) -> list[dict]:
        """Return a summary of all detected providers (for CLI display)."""
        results: list[dict] = []
        self.discover()
        for name, provider in self._providers.items():
            results.append(
                {
                    "name": name,
                    "algorithm": provider.sig_algorithm,
                    "platforms": provider.supported_platforms,
                    "active": name != "software-sim",
                }
            )
        return results
