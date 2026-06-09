# Architecture

## Overview

Seal is built around three core subsystems, with supporting subsystems for key
lifecycle, deployment, and advanced trust models layered on top:

```
┌─────────────────────────────────────────────────────────────┐
│                         Seal                                 │
├─────────────┬──────────────────────┬────────────────────────┤
│  VPE Core   │  EPD Scanner         │  Secrets Broker        │
│ Ed25519 /   │ Regex + LLM fallback │ Encrypted store +      │
│ HMAC / multi│ + Unicode-smuggling  │ {SECRET:label} proxy   │
│ -sig / cert │ defense (T11) for    │ for tool calls         │
│ chains / HW │ injection detection  │                        │
├─────────────┴──────────────────────┴────────────────────────┤
│ Supporting: SQLite stores · Key lifecycle + rotation daemon  │
│ · Hardware (HSM/TPM/Secure Enclave) · Federation · Rollback  │
│ · Division audit trail · Adversarial fuzzer                  │
└─────────────────────────────────────────────────────────────┘
```

> For the full module-by-module inventory and per-phase build status, see the
> root [`ARCHITECTURE.md` → What's Built](../ARCHITECTURE.md).

## Component Details

### VPE Core

**Purpose:** Cryptographic signing and verification of prompt envelopes.

**Modules:** `seal.core.py` (Ed25519 via `cryptography`), `seal.vpe.py` (multi-backend: NaCl or `cryptography`)

**Key Design Decisions:**

- **Ed25519** — Chosen over ECDSA for deterministic signatures (no randomness required), smaller keys, and constant-time verification
- **Canonical JSON** — Deterministic serialization with sorted keys prevents canonicalization attacks
- **HMAC-SHA256 fallback** — 10-100x faster for internal use; 32-byte signatures vs Ed25519's 64 bytes
- **Multi-signing** — `vpe_sign_multi()` / `vpe_verify_multi()` for N-of-M multi-party authorization
- **Hierarchical trust** — `verify_certificate()` / `verify_cert_chain()` walk a root→intermediate→signing key chain, enabling delegation and revocation without re-keying every agent
- **Hardware signing** — `vpe_sign_hardware()` / `vpe_verify_hardware()` keep the private key on a YubiKey/TPM/Secure Enclave

### EPD Scanner

**Purpose:** Lightweight pre-LLM injection detection as defense-in-depth.

**Modules:** `seal/epd/scanner.py`, `seal/epd/patterns.py`, `seal/epd/llm_classifier.py`

**Design:**

- **Pass 1 — Regex:** patterns across 5 categories (ignore-instructions, role-switch, delimiter confusion, hidden-instruction markers, tool hallucination). 91%+ detection rate.
- **Normalization:** strips **all** Unicode format chars (category Cf) + variation selectors and folds homoglyphs/leet before matching, defeating zero-width and interleaving obfuscation.
- **Unicode-smuggling defense (T11):** `_detect_hidden_unicode()` runs unconditionally — flags and decodes invisible **tag-block** (U+E0000–E007F) and **variation-selector** payloads (e.g. emoji + hidden ASCII), then re-scans the decoded text. See [Threat Model → T11](threat-model.md).
- **Pass 2 — LLM Classifier (optional):** Independent model (separate from execution model) classifies ambiguous cases, or `llm_scan_all` runs it on every prompt for semantic bypasses that leave no regex trace.

### Secrets Broker

**Purpose:** Keep credentials out of model context by replacing them with placeholders.

**Modules:** `seal/broker.py`, `seal/credential_store.py`, `seal/audit.py`

**Flow:**

1. Tool call arguments use `{SECRET:label}` placeholders
2. `SecretsBroker.wrap_tool_call()` resolves placeholders from encrypted store
3. `SecretsBroker.redact()` provides safe logging without exposing values
4. `AuditLog` records access events (never stores values)

### Supporting Subsystems

| Subsystem | Modules | Purpose |
|-----------|---------|---------|
| **Persistent stores** | `seal/store.py` | SQLite (WAL) `NonceStore` + `CounterStore` survive restarts; expired-nonce cleanup |
| **Key lifecycle** | `seal/key_manager.py`, `seal/key_store.py`, `seal/rotator.py` | SQLite key registry (generated→active→expiring→retired→revoked), auto-rotation guard, rotation daemon (`seal key daemon`) |
| **Hardware** | `seal/hardware.py` | HSM abstraction — YubiKey/TPM/Secure Enclave; private key never leaves the device |
| **Federation** | `seal/federation.py` | Cross-agent trust anchors and federated audit trail |
| **Rollback** | `seal/rollback.py` | One-toggle disable + full config rollback; audit data preserved |
| **Division audit** | `seal/division_audit.py`, `seal/integration/division_vpe_audit.py` | Store and query VPE verification results as Division memory episodes |
| **Adversarial fuzzer** | `seal/epd/fuzzer.py` | Mutation fuzzing of injection patterns (`seal fuzz`) to measure EPD catch rate |

## Data Flow

### Signing Flow

```
Issuer → vpe_sign() → canonical JSON → Ed25519 sign → envelope (JSON)
```

### Verification Flow

```
Envelope → parse JSON → required fields check → version check
→ signature check → audience check → TTL check → nonce check
→ counter check → scope enforcement → EPD scan (optional) → execute
```

### Secrets Broker Flow

```
Tool call with {SECRET:label}
  → SecretsBroker.resolve() → CredentialStore.get(label)
  → plaintext value → tool API call
  → AuditLog.log_access()
```

## Key Lifecycle

```
generated → active → expiring → retired
                                   → revoked (non-recoverable)
```

## Persistence

| Store | Backend | Location | Purpose |
|-------|---------|----------|---------|
| NonceStore | SQLite (WAL) | `~/.seal/store.db` | Replay prevention |
| CounterStore | SQLite (WAL) | `~/.seal/store.db` | Counter monotonicity |
| KeyStore | SQLite (WAL) | `~/.seal/keys.db` | Key lifecycle & rotation |
| CredentialStore | Fernet-encrypted file | `~/.seal/credentials.yaml.enc` | Secret storage |
| AuditLog | JSONL file | `~/.seal/audit.jsonl` | Access audit trail |

## Dependencies

| Dependency | Purpose | Required? |
|------------|---------|-----------|
| `cryptography` | Ed25519 via `cryptography.hazmat` | Yes |
| `PyNaCl` | Ed25519 via `nacl.bindings` (alternative backend) | No |
| `PyYAML` | Credential store serialization | No (falls back to JSON) |
| `sqlite3` | Persistent stores | Yes (stdlib) |

## See Also

- [VPE Protocol Specification](spec.md) — Full protocol spec
- [Integration Guide](integration.md) — How to add VPE to your agent
- [Threat Model](threat-model.md) — Security analysis
