# OWASP Agentic Security Top 10 — Proposal: Add VPE as a New Control Category

> **Status:** Draft proposal
> **Author:** Hermes Agent / Seal Project
> **Date:** 2026-06-06
> **Target:** OWASP Agentic Security Top 10 (proposed new category)

---

## Abstract

The OWASP LLM Top 10 identifies **Prompt Injection (LLM01)** as the #1
risk in LLM-based applications. Current mitigations are exclusively
content-based: regex filters, perplexity scoring, classifier models, and
linguistic guardrails. None provide **cryptographic provenance
verification** — the ability to prove that a prompt was authorized by a
known entity and has not been tampered with since issuance.

This proposal introduces **VPE (Verified Prompt Envelope)** as a new
control category under "Prompt Injection Prevention": cryptographic
prompt-level signing and verification for AI agents.

---

## The Gap

| Mitigation | What It Prevents | What It Misses |
|-----------|-----------------|----------------|
| Regex filters | Known patterns (DAN, role-switching) | Semantic obfuscation, novel patterns |
| Guardrails API | Known injection payloads | Adversarial prompts, novel vectors |
| Perplexity scoring | Outlier prompts | Normal-looking malicious prompts |
| Content classifiers | Stylistic injection | Context-dependent attacks |
| **VPE (proposed)** | All of the above | Prompt injection from **trusted signers** (solved by scope) |

Every existing mitigation is **linguistic** — it reads the prompt and
tries to decide if it's malicious. A linguistic barrier can always be
bypassed by a sufficiently clever attacker (semantic obfuscation,
encoding, multi-step reasoning chains).

VPE changes the equation: instead of asking "is this prompt malicious?,"
it asks "was this prompt authorized by a trusted entity?" This is the
same shift that HTTPS brought to web security — from content-based
filtering to cryptographic identity.

---

## Proposed Control Category: VPE (LLM01b — Cryptographic Prompt Provenance)

We propose adding **VPE** as a sub-category under **LLM01: Prompt
Injection Prevention**, alongside existing content-based controls:

```
LLM01: Prompt Injection Prevention
├── LLM01a: Content-based filtering (existing)
│   ├── Regex guards
│   ├── Classifier models
│   ├── Perplexity scoring
│   └── Input sanitization
│
├── LLM01b: Cryptographic prompt provenance (NEW)
│   ├── VPE signing (issuer → agent)
│   ├── VPE verification (agent-side gate)
│   ├── Scope enforcement (allowed_tools, max_tokens, etc.)
│   ├── Replay protection (nonce, counter)
│   └── TTL-based expiry
│
└── LLM01c: Embedded prompt detection (NEW)
    ├── Two-pass scanner (regex + LLM classification)
    ├── Prompt-level injection patterns
    └── Confidence-scored flagging
```

### Control Objective

Ensure that every prompt executed by an AI agent was **cryptographically
authorized** by a known issuer for a specific **scope** within a bounded
**window**.

### Description

VPE wraps every prompt in a JSON envelope that includes:

- **Signature** — Ed25519 signature over all metadata fields, providing
  tamper-proof binding between prompt content and its authorization
  context
- **Scope** — Declared bounds on what the authorized prompt may do
  (allowed tools, max tokens, max cost, allowed domains)
- **Identity** — Distinguishable issuer and audience fields
- **Freshness** — TTL with absolute issued_at timestamp
- **Replay prevention** — Nonce (uniqueness) and monotonic counter
  (ordering)

### Verification Steps

Before executing any tool call, the agent must verify:

1. **Signature validity** — The envelope is signed by a known public key
2. **TTL check** — The envelope has not expired
3. **Replay check** — The nonce has not been seen before
4. **Counter check** — The counter is strictly increasing
5. **Scope check** — The requested tool/operation is within scope

**Fail mode** (recommended): reject the tool call and log the violation.
**Audit mode** (permissive): allow but log the violation for review.

### What VPE Does NOT Prevent

VPE is not a silver bullet. It does not prevent:

- Prompt injection from **compromised signers** (lose your private key,
  lose your security)
- Prompt injection in **unsigned channels** (user chat without VPE
  — handled by EPD or content filtering)
- Side-channel attacks (injection via tool output that the model
  re-interprets as instructions)
- Supply-chain attacks on the VPE implementation itself

These are addressed by defense in depth: content filtering for unsigned
channels, output filtering for tool returns, and secure key management
for signer keys.

---

## Implementation Guidance

### Architecture

```
User/Authored Prompt → VPE Signing Service
                            ↓
                   Signed VPE Envelope
                            ↓
                   Agent Security Gate
                   ├── VPE Verify (crypto)
                   ├── EPD Scan (injection)
                   └── Scope Check (allowed ops)
                            ↓
                   Tool Execution (if allowed)
```

### Key Management

- Signing keys should be hardware-backed (HSM, TPM, Apple Secure Enclave)
  in production
- Public keys can be distributed as part of agent configuration,
  verified out-of-band
- Key rotation should be supported with grace periods (overlapping
  validity windows)
- Lost private keys invalidate all previously signed prompts — plan
  for revocation

### Recommended Architecture

| Component | Implementation |
|-----------|---------------|
| Signing service | Sidecar process or MCP server (not in-model) |
| Verification gate | Plugin/hook in agent execution pipeline |
| Public key store | Config file, environment, or secrets manager |
| Nonce/counter state | In-memory with optional persistence |
| EPD complement | Two-pass scanner (regex + LLM) for unsigned prompts |

### Backwards Compatibility

- **Unsigned prompts** must still work — they are logged as "unsigned"
  but not rejected (unless the system is in enforce mode)
- **Graceful degradation** — if the VPE signing service is unavailable,
  the system should fall back to content-based guards
- **Hybrid mode** — signed prompts bypass content filtering; unsigned
  prompts receive full EPD scanning

---

## Risk Assessment

| Scenario | VPE Without | VPE With | Improvement |
|----------|-------------|----------|-------------|
| Known injection pattern | Blocked by regex | Blocked by regex or signature | Neutral |
| Novel injection (0-day) | Missed | Blocked (no signature = no execution in enforce mode) | **Critical** |
| Reused stolen session | Missed | Blocked (nonce check) | **High** |
| Reordered prompt sequence | Missed | Blocked (counter check) | **High** |
| Expired authorization | Manual revocation | Blocked (TTL) | **High** |
| Scoped tool escalation | Missed in content | Blocked (scope check) | **High** |
| Compromised signing key | N/A | Full bypass | **Regression** (mitigate w/ HSM) |

---

## Integration with Existing OWASP Framework

VPE complements existing OWASP LLM controls:

| OWASP Control | VPE Role |
|---------------|----------|
| LLM01: Prompt Injection | **Primary** — cryptographic provenance |
| LLM02: Insecure Output Handling | Indirect — signed outputs enable verification |
| LLM03: Training Data Poisoning | None — orthogonal concern |
| LLM04: Model Denial of Service | Scope (max_tokens) mitigates cost abuse |
| LLM05: Supply Chain | None — but VPE implementation is itself a supply chain concern |
| LLM06: Sensitive Information Disclosure | Secrets Broker integration (scope references) |
| LLM07: Insecure Plugin Design | Scope (allowed_tools) constrains plugin access |
| LLM08: Excessive Agency | **Primary** — scope limits tool access |
| LLM09: Overreliance | None — VPE doesn't affect output accuracy |
| LLM10: Model Theft | None — orthogonal concern |

---

## References

1. OWASP LLM Top 10 (v1.1): https://owasp.org/www-project-top-10-for-llm-applications/
2. Verified Prompt Envelope Protocol (VPE): ~/projects/seal/ARCHITECTURE.md
3. Seal Reference Implementation: ~/projects/seal/seal/
4. Hermes VPE Middleware Integration: ~/projects/seal/integration/hermes_vpe_middleware.py
5. Division Memory Episode Signing: ~/projects/seal/integration/division_vpe_signer.py
6. MCP Spec Signing Extension Proposal: ~/projects/seal/proposals/mcp_signing_extension.md
