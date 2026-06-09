# Seal

**Verified Prompt Envelope Protocol & AI Agent Security.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

---

Seal replaces linguistic injection detection with **cryptographic provenance verification** for AI agent prompts. Every prompt gets an Ed25519-signed envelope that proves who authorized it, what scope it has, and that it hasn't been tampered with.

- **VPE Core** — Sign/verify prompts with Ed25519 or HMAC-SHA256, **N-of-M multi-signature**, **hierarchical issuer cert chains**, and **hardware (HSM/TPM/Secure Enclave) signing**
- **EPD Scanner** — Pre-LLM injection detection: regex + LLM fallback, plus **Unicode-smuggling defense** (invisible tag-block / variation-selector payloads) and an adversarial fuzzer
- **Secrets Broker** — Keep credentials out of model context (`{SECRET:label}` proxy, Fernet-encrypted store, access audit)
- **Key lifecycle** — SQLite-backed key registry, rotation daemon, persistent nonce/counter replay protection
- **CLI** — 18 commands: `sign`, `verify`, `genkey`, `secrets`, `key {rotate,revoke,daemon,…}`, `audit`, `rollback`, `hardware`, `fuzz`, `status`
- **Integration** — MCP middleware for Hermes + Division audit trail, with one-toggle rollback
- **Tested** — 517 tests across core, EPD, crypto-bypass, key lifecycle, hardware, federation, and e2e suites

## Quickstart

```bash
pip install seal-vpe

# Generate a key pair
seal genkey

# Sign a prompt
seal sign "search the database for customer X" \
  --scope '{"allowed_tools": ["search"]}' \
  --issuer "user:rez"

# Verify an envelope
echo '<envelope>' | seal verify
```

### As a library

```python
from seal import generate_key_pair, vpe_sign, vpe_verify

keys = generate_key_pair()

envelope = vpe_sign(
    prompt="search the database for customer X",
    scope={"allowed_tools": ["search"]},
    issuer="user:rez",
    audience="agent:hermes-default",
    ttl_seconds=300,
    private_key=keys["private_key"],
)

result = vpe_verify(envelope, public_key=keys["public_key"])
assert result["valid"] is True
```

## Architecture

Seal has three subsystems:

```
┌─────────────────────────────────────────────────────────────┐
│                         Seal                                 │
├─────────────┬──────────────────────┬────────────────────────┤
│  VPE Core   │  EPD Scanner         │  Secrets Broker        │
│             │                      │                        │
│ Ed25519 /   │ Regex patterns +     │ Encrypted store +      │
│ HMAC-SHA256 │ LLM fallback for     │ {SECRET:label} proxy   │
│ signing &   │ injection detection  │ for tool calls         │
│ verification│                      │                        │
└─────────────┴──────────────────────┴────────────────────────┘
```

| Component | Description | Module |
|-----------|-------------|--------|
| **VPE Core** | Ed25519/HMAC sign/verify, multi-sig, cert chains, hardware signing, canonical JSON | `seal/core.py`, `seal/vpe.py` |
| **EPD Scanner** | Two-pass regex (91%+) + LLM, Unicode-smuggling defense (T11), fuzzer | `seal/epd/` |
| **Secrets Broker** | Fernet-encrypted credential store, placeholder resolution, audit log | `seal/broker.py`, `seal/credential_store.py` |
| **Key lifecycle** | SQLite key registry, rotation daemon, persistent nonce/counter stores | `seal/key_manager.py`, `seal/key_store.py`, `seal/store.py` |
| **Hardware / Federation / Rollback** | HSM signing; cross-agent trust; one-toggle rollback | `seal/hardware.py`, `seal/federation.py`, `seal/rollback.py` |
| **CLI** | 18 commands: `genkey`, `sign`, `verify`, `secrets`, `key`, `audit`, `rollback`, `hardware`, `fuzz`, `status` | `seal/cli.py` |
| **Integrations** | Hermes MCP middleware, Division memory signing + audit trail | `seal/integration/` |

> **Full module inventory & per-phase build status:** [`ARCHITECTURE.md`](ARCHITECTURE.md).

### VPE Envelope Format

```json
{
  "vpe_version": "1.0",
  "prompt": "search the database...",
  "scope": {"allowed_tools": ["search"]},
  "issuer": "user:rez",
  "audience": "agent:hermes-default",
  "doc_sha256": "abc123...",
  "ttl_seconds": 300,
  "nonce": "a1b2c3d4",
  "counter": 42,
  "signature": "ed25519_sig_hex..."
}
```

## Why VPE?

| Problem | Current Practice | VPE Fix |
|---------|-----------------|---------|
| Prompt injection | Linguistic filtering (~91% catch) | Cryptographic provenance |
| Scope escalation | No enforcement at prompt level | Envelope carries signed scope |
| Replay attacks | No protection | Nonce + counter per envelope |
| Credential leakage | Keys in prompt context | Secrets Broker proxy |
| Audit | None / manual log review | Signed, tamper-evident audit trail |

## Project Status

Phase 1-4 complete. [Full architecture & roadmap](ARCHITECTURE.md).

- Phase 1 — VPE Spec & Reference Implementation ✓
- Phase 2 — EPD Scanner ✓
- Phase 3 — Secrets Broker ✓
- Phase 4 — Hermes/Division Integration ✓
|- Phase 5 — Performance & Production Hardening (in progress)

## Reference Implementations

The VPE protocol has reference implementations in four languages, all passing the same test vector suite:

### TypeScript/Node.js

```bash
# Install
npm install seal-vpe

# Usage
import { vpeSign, vpeVerify, generateKeyPair } from 'seal-vpe';

const keys = generateKeyPair();
const envelope = vpeSign("prompt", { allowed_tools: ["search"], max_tokens: 1000, max_cost: 0.01, allowed_domains: [] }, "user:rez", "agent:hermes", "", 300, null, null, { privateKey: keys.privateKey });
const result = vpeVerify(envelope, keys.publicKey);
// { valid: true, reason: "ok" }
```

### Go

```bash
# Install
go get github.com/seal/vpe-go/vpe

# Usage
import "github.com/seal/vpe-go/vpe"

kp, _ := vpe.GenerateKeyPair()
env, _ := vpe.VpeSign("prompt", scope, "user:rez", "agent:hermes", "", 300, "", nil, &vpe.SignOptions{PrivateKey: kp.PrivateKey})
result := vpe.VpeVerify(env, kp.PublicKey)
// result.Valid == true
```

### Rust

```bash
# Add to Cargo.toml
cargo add vpe-rust

# Usage
use vpe_rust::{vpe_sign, vpe_verify, generate_key_pair};

let kp = generate_key_pair();
let env = vpe_sign("prompt", Some(scope), "user:rez", "agent:hermes", "", 300, None, None, &kp.private_key);
let result = vpe_verify(&env, &kp.public_key);
// result.valid == true
```

### Cross-language verification

Any language can verify envelopes signed by any other language — the canonical JSON serialization and Ed25519 signing are identical across all implementations:

```
Sign in Python  → Verify in TypeScript  ✓
Sign in Go      → Verify in Python     ✓
Sign in Rust    → Verify in Go         ✓
Sign in TS      → Verify in Rust       ✓
```

## Development

```bash
# Clone and install
git clone https://github.com/nousresearch/seal.git
cd seal

# Set up with uv
uv venv
uv pip install -e ".[dev]"

# Run tests
uv run pytest

# Lint
uv run ruff check .
```

## License

MIT — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
