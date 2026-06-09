"""Seal — Verified Prompt Envelope Protocol & AI Agent Security."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("seal")
except PackageNotFoundError:
    __version__ = "0.1.0"

# Re-export from core.py (P1.2 reference implementation)
from seal.core import (
    HMAC_SIGNATURE_BYTES,
    VPE_VERSION,
    generate_key_pair,
    vpe_sign,
    vpe_sign_hardware,
    vpe_sign_hmac,
    vpe_sign_multi,
    vpe_verify,
    vpe_verify_hardware,
    vpe_verify_hmac,
    vpe_verify_multi,
)

# Re-export from vpe.py (P1.5 expanded implementation with multiple backends)
from seal.vpe import VPE_VERSION as _VPE_VERSION_ALT  # noqa: F811

from seal.audit import AuditLog
from seal.broker import SecretsBroker
from seal.credential_store import CredentialStore
from seal.hardware import HsmManager, HsmKey, SoftwareSimProvider, YubiKeyPIVProvider
from seal.federation import (
    DEFAULT_REGISTRY_PATH,
    FederationAuditLog,
    FederatedSignResult,
    ResolutionResult,
    TrustAnchorRegistry,
    resolve_trust_anchor,
    resolve_via_did,
    resolve_via_dns,
    vpe_federated_sign,
    vpe_federated_verify,
)
from seal.store import CounterStore, NonceStore

__all__ = [
    "AuditLog",
    "CounterStore",
    "CredentialStore",
    "DEFAULT_REGISTRY_PATH",
    "FederationAuditLog",
    "FederatedSignResult",
    "HsmKey",
    "HsmManager",
    "NonceStore",
    "ResolutionResult",
    "SecretsBroker",
    "SoftwareSimProvider",
    "TrustAnchorRegistry",
    "VPE_VERSION",
    "YubiKeyPIVProvider",
    "generate_key_pair",
    "resolve_trust_anchor",
    "resolve_via_did",
    "resolve_via_dns",
    "vpe_federated_sign",
    "vpe_federated_verify",
    "vpe_sign",
    "vpe_sign_hardware",
    "vpe_sign_hmac",
    "vpe_sign_multi",
    "vpe_verify",
    "vpe_verify_hardware",
    "vpe_verify_hmac",
    "vpe_verify_multi",
]
