# Architecture

## Overview

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

## Component Details

### VPE Core

**Purpose:** Cryptographic signing and verification of prompt envelopes.

**Modules:** `seal.core.py` (Ed25519 via `cryptography`), `seal.vpe.py` (multi-backend: NaCl or `cryptography`)

**Key Design Decisions:**

- **Ed25519** — Chosen over ECDSA for deterministic signatures (no randomness required), smaller keys, and constant-time verification
- **Canonical JSON** — Deterministic serialization with sorted keys prevents canonicalization attacks
- **HMAC-SHA256 fallback** — 10-100x faster for internal use; 32-byte signatures vs Ed25519's 64 bytes
- **Multi-signing** — `vpe_sign_multi()` signs with multiple keys for multi-party authorization

### EPD Scanner

**Purpose:** Lightweight pre-LLM injection detection as defense-in-depth.

**Modules:** `seal/epd/scanner.py`, `seal/epd/patterns.py`, `seal/epd/llm_classifier.py`

**Design:**

- **Pass 1 — Regex:** 20+ patterns across 5 categories (system prompt override, roleplay, code execution, context manipulation, data extraction). 91%+ detection rate.
- **Pass 2 — LLM Classifier (optional):** Independent model (separate from execution model) classifies ambiguous cases as injection/normal.

### Secrets Broker

**Purpose:** Keep credentials out of model context by replacing them with placeholders.

**Modules:** `seal/broker.py`, `seal/credential_store.py`, `seal/audit.py`

**Flow:**

1. Tool call arguments use `{SECRET:label}` placeholders
2. `SecretsBroker.wrap_tool_call()` resolves placeholders from encrypted store
3. `SecretsBroker.redact()` provides safe logging without exposing values
4. `AuditLog` records access events (never stores values)

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
