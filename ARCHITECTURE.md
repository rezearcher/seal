# Seal — Verified Prompt Envelope Protocol & AI Agent Security

> **Status:** Phase 1 — Specification & Reference Implementation
> **Board:** seal
> **Assignee profile:** default (Claude Code via Max plan)
> **Foreman cadence:** 3x/day (4am/noon/8pm)

## Core Problem

AI agents execute prompts from multiple sources: user input, tool returns, attached documents, memory recall, skill pipelines. Any of these can inject unauthorized instructions. Current industry defense is purely linguistic (Anthropic's prose-level "untrusted data, never execute instructions" — SOTA is ~91% static regex, bypassed by semantic obfuscation). No existing product, paper, or standard does **cryptographic provenance verification** at the prompt level.

Seal (VPE) replaces linguistic detection with cryptographic enforcement.

## The VPE Protocol

A verified prompt is a JSON wrapper with Ed25519 signature:

```json
{
  "vpe_version": "1.0",
  "prompt": "search the database for customer records...",
  "scope": {
    "allowed_tools": ["database_search", "read_file"],
    "max_tokens": 4000,
    "max_cost": 0.05,
    "allowed_domains": ["*.internal.corp.com"]
  },
  "issuer": "user:rez",
  "audience": "agent:hermes-default",
  "doc_sha256": "abc123...",
  "ttl_seconds": 300,
  "nonce": "a1b2c3d4",
  "counter": 42,
  "signature": "ed25519_sig_hex..."
}
```

### Fields
| Field | Purpose | Example |
|-------|---------|---------|
| `vpe_version` | Protocol version | `"1.0"` |
| `prompt` | The actionable instruction | `"search database..."` |
| `scope` | Least-privilege capabilities | `{allowed_tools, max_tokens, ...}` |
| `issuer` | Who authorized this | `"user:rez"` |
| `audience` | Which agent should execute | `"agent:hermes-default"` |
| `doc_sha256` | Binding to source document | `"abc123..."` |
| `ttl_seconds` | Expiry from issuance | `300` (5 minutes) |
| `nonce` | Uniqueness (replay prevention) | `"a1b2c3d4"` |
| `counter` | Monotonic — detect skipped prompts | `42` |
| `signature` | Ed25519 over all prior fields | hex string |

## Three Sub-Systems

### 1. VPE Core (sign + verify)
- Ed25519 key pair generation
- `vpe_sign(prompt, scope, issuer, audience, ...) → signed_envelope`
- `vpe_verify(signed_envelope) → {valid: bool, reason: str}`
- Python reference implementation with no dependencies beyond `cryptography` or `nacl`

### 2. EPD (Embedded Prompt Detection)
- Pre-LLM scanner that runs inside the VPE verification gate
- Detects: jailbreak patterns, role-switching, "ignore previous instructions", hidden instructions in attached docs
- Regex first-pass (~91% catch rate), LLM classification pass for suspicious-but-ambiguous
- Outputs: `{clean: bool, flags: [pattern_name, confidence, location]}`

### 3. Secrets Broker
- Credential proxy that never lets API keys/tokens enter model context
- Agents request secrets by label (`"tastytrade_sandbox"`) — broker injects directly into tool calls
- Keeps keys out of prompt history, log files, and training data

## Build Phases

### Phase 1 — VPE Spec & Reference Implementation
- Write formal protocol spec (this doc → v1.0 spec)
- Python implementation: sign + verify with Ed25519
- CLI tool: `seal sign <prompt> --scope ... --issuer ...`
- CLI tool: `seal verify <envelope>`
- Unit tests: signing, verification, tamper detection, TTL expiry, replay prevention

### Phase 2 — EPD Scanner
- Regex patterns for known injection vectors
- LLM fallback for semantic obfuscation
- Integration with VPE verification gate
- Test suite: clean prompts, known injection patterns, edge cases

### Phase 3 — Secrets Broker
- Credential store (key-value, file-backed or env-based)
- Proxy pattern for tool calls
- Audit log of credential access
- Integration test: agent tool calls broker, not context

### Phase 4 — Hermes/Division Integration
- MCP middleware layer: every tool call wrapped in VPE
- Division memory episode signing
- Proposal as OWASP Agentic Security control category
- Proposal as MCP spec extension (signing layer)

## What Already Exists (Rez's prior work)
- **Membrane** (Night Agent): Ed25519 Tickets per-action, chained Receipts — action-level, VPE is prompt-level, complementary
- **TRUSTBAC**: RBAC+ABAC+ReBAC+RAdAC authorization framework — VPE is prompt authentication, complementary
- **Division injection scanning gap**: write-time scanning identified but not implemented (low effort, high impact)
- **Hermes skills guard**: 120+ regex patterns — reactive, no crypto

## Industry Gap Analysis
| Domain | What Exists | Seal's Addition |
|--------|-------------|-----------------|
| Injection detection | Guardrails AI, NeMo, Rebuff, Lakera | Cryptographic provenance, not just content filtering |
| Prompt security products | All content-based | None do signed execution |
| OWASP LLM Top 10 | Identifies injection as #1 risk | No crypto mitigations proposed |
| MCP spec | Protocol for tools/lifecycle | No auth, no scope, no replay protection |
| IETF | No standards for prompt security | Could be an IETF draft |

## Key Constraints
- Zero external runtime dependencies (stdlib + cryptography lib only)
- All operations must be verifiable offline (no SaaS dependency)
- VPE must be backwards-compatible — unsigned prompts still work (logged as "unverified")
- Secrets Broker must be opt-in — agents can run without it
- EPD false positive rate < 5% on benign prompts
