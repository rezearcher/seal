# API Reference

Seal exposes a clean public API through the `seal` package. The reference implementation is in `seal.core` (Ed25519 via `cryptography`), with an expanded multi-backend implementation in `seal.vpe`.

## Package Layout

| Module | Description |
|--------|-------------|
| `seal` | Top-level re-exports of public API |
| `seal.core` | VPE sign/verify with Ed25519 (via `cryptography`) |
| `seal.vpe` | Expanded VPE with multi-backend (NaCl + cryptography) |
| `seal.audit` | Append-only JSONL audit log |
| `seal.broker` | `{SECRET:label}` placeholder resolver |
| `seal.credential_store` | Fernet-encrypted key-value store |
| `seal.store` | Persistent NonceStore and CounterStore (SQLite) |
| `seal.key_store` | Key lifecycle store with time-based metadata |
| `seal.key_manager` | Key lifecycle management registry |
| `seal.rollback` | VPE/Hermes integration rollback procedures |
| `seal.epd` | Embedded Prompt Detection scanner |
| `seal.cli` | Command-line interface |
| `seal.integration` | Hermes MCP middleware, Division signing |

## Quick Example

```python
from seal import generate_key_pair, vpe_sign, vpe_verify, vpe_sign_hmac

# Ed25519
keys = generate_key_pair()
env = vpe_sign("hello", scope={}, issuer="me", audience="agent:x",
               private_key=keys["private_key"])
result = vpe_verify(env, public_key=keys["public_key"])

# HMAC-SHA256 (symmetric, for internal use)
env = vpe_sign_hmac("hello", shared_secret=b"super-secret")
```
