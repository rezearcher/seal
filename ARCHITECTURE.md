# Seal — Verified Prompt Envelope Protocol & AI Agent Security

> **Status:** Phases 1–9 core capabilities **implemented and tested** — VPE Core (Ed25519 + HMAC + multi-sig + hierarchical cert chains + hardware signing), EPD Scanner (regex + LLM + Unicode-smuggling defense), Secrets Broker, persistent stores, full key lifecycle + rotation daemon, Hermes/Division integration, rollback, adversarial fuzzer, and benchmarks. **659 tests collected.**
> **Remaining:** external adoption only — P8 (cross-language ports, OWASP/MCP standardization) and P10 (production-bake). See per-phase status tags below.
> **Board:** seal
> **Assignee profile:** default (Claude Code via Max plan)
> **Foreman cadence:** 3x/day (4am/noon/8pm)

> ⚠️ **Doc-accuracy note:** the "Build Phases" sections below were the *original plan*. Each phase header now carries a status tag (✅ Implemented / 🟡 Partial / ⬜ External). For the authoritative inventory of what physically exists, see [What's Built](#whats-built-current-state) — keep that section in sync when modules land.

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

---

<a id="whats-built-current-state"></a>
## What's Built (current state)

> Authoritative inventory of modules that physically exist, with the test file that exercises each. **659 tests collected.** Keep this table current when modules land — it is the anti-confusion anchor for the roadmap below.

### VPE Core — signing & verification (Phase 1, plus 5.4 / 9.1 / 9.3 / 9.4)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/core.py` | 1229 | `vpe_sign`/`vpe_verify` (Ed25519), `vpe_sign_hmac`/`vpe_verify_hmac` (HMAC-SHA256, P5.4), `vpe_sign_multi`/`vpe_verify_multi` (N-of-M multi-sig, P9.3), `verify_certificate`/`verify_cert_chain` (hierarchical issuer chains, P9.1), `vpe_sign_hardware`/`vpe_verify_hardware` (P9.4), scope/nonce/counter/TTL enforcement | `test_core.py` (146), `test_crypto_bypass.py` (54) |
| `seal/vpe.py` | 589 | Envelope dataclasses, canonical JSON, multi-backend Ed25519 (NaCl or `cryptography`) | `test_core.py` |
| `seal/cli.py` | 649 | 18-command CLI (see below) | e2e |

### EPD Scanner — injection detection (Phase 2, plus 7.1 / 7.4)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/epd/scanner.py` | 349 | Two-pass scan (regex ~91% + optional LLM). Normalization strips **all** Unicode format chars (Cf) + variation selectors; `_detect_hidden_unicode()` flags/decodes invisible **tag-block & variation-selector smuggling** (threat-model **T11**), runs unconditionally | `test_epd.py` (57) |
| `seal/epd/patterns.py` | 615 | Regex patterns: jailbreaks, role-switch, ignore-instructions, delimiter confusion, hidden markers, tool hallucination, homoglyph/leet | — |
| `seal/epd/llm_classifier.py` | 145 | LLM tiebreaker / `llm_scan_all` catch-all pass (independent model) | `test_epd.py` |
| `seal/epd/fuzzer.py` | 955 | Pattern-mutation fuzzer, `seal fuzz` (P7.1 adversarial) | `test_epd.py` |
| `seal/epd/{config,models}.py` | 147 | `EPDConfig`, `EPDFlag`, `EPDResult` | `test_epd.py` |

### Secrets Broker — credentials out of context (Phase 3)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/secrets_broker.py` / `seal/broker.py` | 419 | `{SECRET:label}` placeholder resolution into tool calls, deep-copy + `redact()` | `test_broker.py` (12) |
| `seal/credential_store.py` | 183 | File store, **Fernet-encrypted at rest** | `test_credential_store.py` (11) |
| `seal/audit.py` | 234 | Append-only JSONL access audit (records access, never values) | `test_audit.py` (12) |

### Key lifecycle & persistence (Phase 5)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/store.py` | 247 | SQLite (WAL) `NonceStore` + `CounterStore`, expiry cleanup (P5.2) | `test_store.py` (32) |
| `seal/key_manager.py` / `seal/key_store.py` | 920 | SQLite key registry: generated→active→expiring→retired→revoked, auto-rotation guard (P5.5) | `test_key_manager.py` (37), `test_key_lifecycle.py` (27) |
| `seal/rotator.py` | 43 | Rotation daemon — one-shot (cron) or persistent (`seal key daemon`) | (lifecycle) |
| `benchmark_vpe_verify.py`, `benchmark_envelope_size.py` | — | P5.1 / P5.3 perf + size benchmarks | — |

### Deployment & integration (Phases 4 / 6)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/integration/hermes_vpe_middleware.py` | — | Wraps Hermes tool calls in VPE verify + EPD scan | `test_e2e_real_tools.py` (37) |
| `seal/integration/hermes_skills_guard.py` | — | VPE/EPD-backed skills guard | `test_e2e_real_tools.py` |
| `seal/integration/division_vpe_signer.py` / `division_vpe_audit.py` | — | Sign Division episodes; store/query VPE results in Division memory (P6.4) | `test_division_audit.py` (13) |
| `seal/division_audit.py` | 722 | Division audit-trail store + query | `test_division_audit.py` |
| `seal/rollback.py` | 472 | One-toggle disable + full config rollback, audit preserved (P6.5) | `test_graceful_degradation.py` (20) |

### Advanced (Phase 9)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/hardware.py` | 706 | HSM abstraction — YubiKey/TPM/Secure Enclave signing, key never leaves device (P9.4) | `test_hardware.py` (27) |
| `seal/federation.py` | 699 | Cross-agent trust anchors, federated audit (P9.5) | `test_federation.py` (32) |

### Standards, packaging & docs (Phase 8, partial)
- **`VPE_SPEC_v1.md`** (839 lines) — full protocol spec.
- **`proposals/`** — `owasp_agentic_security_vpe.md`, `mcp_signing_extension.md`, `SEP-vpe-signing-layer.mdx`; **`seal-community/`** — conference CFP drafts.
- **Docs site** — MkDocs (`mkdocs.yml`, `docs/` 18 pages: spec, API reference, CLI, integration, threat model, quickstart) → `docs.yml` CI deploy.
- **CI** — `.github/workflows/`: `test.yml`, `lint.yml`, `benchmark.yml`, `publish.yml` (PyPI `seal-vpe`).

### CLI surface (`seal …`)
`genkey` · `sign` · `verify` · `secrets {add,get,list,delete}` · `audit` · `key {rotate,revoke,disable,list,daemon}` · `rollback` · `hardware` · `fuzz` · `status`

---

## Security Notes / Known Limitations

- **Private keys unencrypted at rest:** `seal/key_manager.py` stores private keys raw (unencrypted) in the SQLite registry at `~/.seal/keys.db`. The module docstring acknowledges this: "encryption-at-rest is future work." Protect the file with restrictive filesystem permissions (`chmod 600`) until encryption-at-rest lands.
- **TTL enforcement requires `iat`:** In both `seal/core.py` and `seal/vpe.py`, TTL expiry is only enforced when the `iat`/`issued_at` field is present in the envelope. When `iat` is absent (backward-compat envelopes), TTL is silently skipped. Envelopes produced by `vpe_sign` always include `iat`.
- **Two credential store paths — only one is encrypted:** `seal/credential_store.py` (`seal.credential_store.CredentialStore`) is Fernet-encrypted at rest and is the current recommended implementation. `seal/secrets_broker.py` contains a legacy `CredentialStore` that writes credentials as **plaintext JSON** to `~/.hermes/secrets.json`; it is deprecated and emits a `DeprecationWarning` on import. Use `seal.broker` and `seal.credential_store` for all new integrations.
- **Cross-language ports not yet available (P8.5):** TypeScript, Go, and Rust ports are planned but not published. See the Phase 8 section below.

---

## Phase 5 — Performance & Production Hardening ✅ Implemented

> Persistent SQLite stores (`store.py`), key lifecycle + rotation (`key_manager.py`/`key_store.py`/`rotator.py`), HMAC path (`core.vpe_*_hmac`), and benchmarks all landed and tested.

**Goal:** Make VPE fast enough for real-time use and robust enough for production deployment.

### Subtasks

| ID | Task | Acceptance Criteria |
|----|------|--------------------|
| P5.1 | VPE verification benchmark | Measure overhead: `vpe_verify()` latency for envelopes of 1KB, 10KB, 100KB. Target < 5ms for 1KB, < 20ms for 100KB. Report breakdown (parsing, signature verify, scope check, nonce check, expiry check). |
| P5.2 | Persistent nonce/counter store | SQLite-backed `NonceStore` and `CounterStore`. Survive restarts. Automatic cleanup of expired nonces (>TTL). Thread-safe. Path: `~/.seal/store.db`. |
| P5.3 | Envelope size optimization | Canonical JSON without unnecessary whitespace. Optional field stripping (omit empty scope, omit default version). Benchmark size reduction vs. parse time. |
| P5.4 | HMAC-SHA256 alternative | For contexts where Ed25519 is overkill (internal trust, short-lived prompts). HMAC path: `vpe_sign_hmac()`, `vpe_verify_hmac()`. No key generation needed — shared secret. Document trade-offs: faster but no non-repudiation. |
| P5.5 | Key lifecycle management | Key generation → active → expiring → retired → revoked. Automatic rotation (generate new key N days before expiry). Graceful: old keys still verify signed envelopes, new envelopes use new key. CLI: `seal key rotate`, `seal key list`, `seal key revoke`. |

### Performance Targets
```
Metric                Current      Target
vpe_verify(1KB)       ~2ms         <5ms (benchmark first)
vpe_verify(100KB)     ~15ms        <20ms
Envelope overhead     ~500B        <300B (with optional stripping)
Nonce check           in-memory    SQLite, <1ms
```

---

## Phase 6 — Hermes Production Deployment 🟡 Partial

> Middleware, graceful degradation, Division audit trail (`division_audit.py`), and rollback (`rollback.py`) are built and tested. Live production wiring into a running Hermes/Division instance is deployment-dependent, not a code gap.

**Goal:** VPE middleware running in production, protecting real Hermes tool calls.

### Subtasks

| ID | Task | Acceptance Criteria |
|----|------|--------------------|
| P6.1 | Wire VPE into Hermes config | VPE middleware registered as optional plugin in Hermes `config.yaml`. Enabled/disabled via config toggle. No Hermes core modifications needed — MCP middleware layer only. |
| P6.2 | End-to-end test with real tools | Full chain: prompt → VPE sign → Hermes receives → VPE verify → scope check → EPD scan → tool call → response → VPE sign response. Test with `read_file`, `terminal`, `web_search`. |
| P6.3 | Graceful degradation | Unsigned prompts still work: logged as "unverified" with warning. Expired envelopes: logged, prompt still executed (configurable strict/lenient mode). Invalid signatures: rejected with clear error. |
| P6.4 | Division audit trail | Every VPE verification result stored in Division memory as episode: envelope hash, issuer, result (valid/invalid/expired), timestamp. Queryable: "show me all rejected prompts in the last hour." Hardened (L-010, `t_3035a8b3`): audit hashing no longer swallows all exceptions — canonicalization failure now logs a warning, marks the record `hash_computation_failed`, and emits a `degraded:`-prefixed identifier instead of a hash silently aliased to the nonce. The degraded fallback is retained-and-flagged, not removed; its failure branch is not yet covered by a test. |
| P6.5 | Rollback procedure | Disable VPE middleware with single config toggle. Script to roll back all VPE-related changes to Hermes config. No data loss on rollback — audit trail preserved. |

### Middleware Flow
```
Incoming prompt (raw or VPE-enveloped)
  → Detect: is this a VPE envelope or raw text?
  → If enveloped: vpe_verify() → if invalid: log + reject (strict) or log + warn (lenient)
  → If enveloped + valid: extract prompt + scope → pass to Hermes
  → If raw: log as unverified → pass to Hermes (with warning)
  → EPD scan on extracted prompt (always, regardless of envelope)
  → On response: optionally sign response envelope
```

---

## Phase 7 — Adversarial Testing ✅ Implemented

> Mutation fuzzer (`epd/fuzzer.py`, `seal fuzz`), cryptographic-bypass + scope-escalation suites (`test_crypto_bypass.py`, 54 tests), and the P7.4 LLM-bypass finding (→ `llm_scan_all`) are done. The **T11 Unicode-smuggling** defense is the latest adversarial hardening (see [Threat Model](docs/threat-model.md)).

**Goal:** Break VPE before someone else does.

### Subtasks

| ID | Task | Acceptance Criteria |
|----|------|--------------------|
| P7.1 | EPD pattern mutation fuzzing | Generate 1000+ mutations of known injection patterns (character insertion, deletion, substitution, encoding variations). Measure catch rate. Target: >95% on known patterns, >85% on novel mutations. |
| P7.2 | VPE cryptographic bypass attempts | Test: signature replay (reuse signature from different envelope), key confusion (substitute different key), malleability (reorder JSON fields), algorithm confusion (force HMAC path when Ed25519 expected). |
| P7.3 | Scope escalation attempts | Test: modify scope after signing, grant additional tools, extend TTL, change audience/issuer. Verify all scope modifications cause verification failure. |
|| P7.4 | LLM-based adversarial generation | Use an LLM to generate novel injection prompts designed to bypass EPD patterns. Feed output back into EPD pattern development. **Result: 71/73 prompts (97.3%) bypassed regex — regex alone cannot catch semantic attacks. Solution: ``llm_scan_all`` config option + LLM classifier.** |
| P7.5 | Third-party audit prep | Document attack surface, threat model, known limitations. Create security audit checklist. Reference comparable systems (JWT, PASETO, Sigstore) for comparison. |

### Test Metrics
```
|EPD catch rate          Target      Actual (P7.4)
|Known patterns          >95%        ~91% (regex)
|Mutations               >85%        N/A (P7.1)
|LLM-generated novel     >70% (stretch)  0% (regex alone, before llm_scan_all)
VPE bypass rate         0% (no cryptographic bypasses)
```

---

## Phase 8 — Standards & Community 🟡 Partial

> Proposals drafted (`proposals/`: OWASP, MCP extension, SEP), docs site + CI + PyPI packaging in place, CFP drafts written (`seal-community/`). **External-dependent / not done:** cross-language ports (P8.5 — TS/Go/Rust), and actual OWASP/MCP acceptance.

**Goal:** VPE becomes an industry reference — not just a local tool.

### Subtasks

| ID | Task | Acceptance Criteria |
|----|------|--------------------|
| P8.1 | Submit OWASP proposal | PR or submission to OWASP Agentic Security Top 10 repository. New control category: "Prompt Authentication & Cryptographic Verification" with VPE as reference implementation. |
| P8.2 | Draft MCP spec extension | Formal MCP spec extension proposal. Define: `vpe` field in MCP messages, key exchange mechanism, verification error codes. Submit as PR to MCP spec repo or IETF draft. |
| P8.3 | Open source release | Clean GitHub repo: README, LICENSE, CONTRIBUTING, issue templates, CI pipeline (GitHub Actions for tests + benchmarks). PyPI package: `pip install seal-vpe`. |
| P8.4 | Documentation site | Hosted docs (GitHub Pages or similar): protocol spec, API reference, integration guide, CLI reference, threat model. Quickstart: "Add VPE to your agent in 5 minutes." |
| P8.5 | Reference implementations (**⬜ NOT YET STARTED** — no packages published) | Port VPE to: TypeScript/Node.js, Go, Rust. Each must pass the same test vector suite (cross-language verification). Python implementation remains the canonical spec. `npm install seal-vpe`, `go get github.com/seal/vpe-go/vpe`, and `cargo add vpe-rust` will all 404 until this ships. |
| P8.6 | Community engagement | Blog post: "Why your AI agent needs cryptographic prompt verification." Conference talk CFP submissions (AI security conferences, OWASP events, Rust/NYC, etc.). Discussion with Hermes upstream for native support. |

### Standards Timeline
```
Month 1: OWASP proposal submission + first reference port (TypeScript)
Month 2: MCP spec extension draft + Go port
Month 3: Rust port + CI + documentation site
Month 4: Conference submissions + upstream discussions
Month 6: v1.0 release candidate
```

---

## Phase 9 — Advanced Features ✅ Implemented (core)

> Hierarchical issuer chains (`core.verify_cert_chain`, P9.1), key expiry/rotation (P9.2), multi-signature envelopes (`core.vpe_sign_multi`, P9.3), hardware signing (`hardware.py`, P9.4), and federation (`federation.py`, P9.5) are all built and tested. Trust-anchor discovery via DNS/DID remains the thinnest area.

**Goal:** Extend VPE beyond the reference implementation into a full prompt security framework.

### Subtasks

| ID | Task | Acceptance Criteria |
|----|------|--------------------|
| P9.1 | Hierarchical keys (issuer chains) | Key hierarchy: root CA → intermediate → signing key. Envelope includes cert chain. Verification walks the chain. Enables: team signing, delegation, revocation without re-keying all agents. |
| P9.2 | Time-based key expiry | Keys have `not_before` and `not_after` timestamps. Automatic rotation daemon. Integration with P5.5 key lifecycle. |
| P9.3 | Multi-signature envelopes | Requires N-of-M signatures before execution. Use case: "two of three team leads must approve this prompt." `vpe_sign` adds signature to existing envelope. `vpe_verify` checks threshold. |
| P9.4 | Hardware key support | YubiKey (PIV/OpenPGP), TPM, or macOS Secure Enclave for private key storage. Signing operation moves to hardware. Private key never leaves the device. |
| P9.5 | VPE federation (cross-agent trust) | Agent A can sign a prompt for Agent B if they share a trust anchor. Trust anchors are pre-shared or discovered via DNS/DID. Cross-agent audit trail. |

### Architecture (Hierarchical)
```
Root Key (offline, in vault)
  └── Issuer Key ("team:security")
       ├── Signing Key ("agent:hermes-prod")
       │    └── VPE envelopes for Hermes 1
       ├── Signing Key ("agent:hermes-staging")
       │    └── VPE envelopes for Hermes 2
       └── Backup Key (cold storage)
```

---

## Phase 10 — End State: Prompt Security Standard ⬜ External

> Adoption milestone, not a code deliverable — gated on outside acceptance (OWASP/MCP) or a 6-month production bake. Nothing to build here.

**Goal:** VPE is adopted beyond this project — referenced in OWASP, MCP, and used by other agent frameworks.

### Capabilities
- **Any Hermes agent** can verify prompt provenance cryptographically
- **Division memory** has signed episodes — tamper-evident history
- **EPD scanner** catches 95%+ of injection attempts before they reach the LLM
- **Secrets Broker** keeps credentials out of model context entirely
- **Multiple trust models**: HMAC (internal), Ed25519 (public), multi-sig (high-security)
- **Cross-framework**: TypeScript/Go/Rust ports interoperate with Python reference

### When to Stop
Seal is "done" when:
- VPE is referenced in OWASP Agentic Security Top 10 or MCP spec, OR
- It's been running in production for 6 months with zero VPE bypasses, OR
- You decide prompt-level crypto isn't the right approach and pivot

### Shutdown states
- **Paused:** Middleware disabled, CLI tools still work, audit data preserved
- **Archived:** Integrations removed, spec and proposals remain as reference
- **Open-sourced:** Project transferred to community ownership
