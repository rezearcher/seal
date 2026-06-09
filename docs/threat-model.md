# Threat Model

This document describes the threat model for the Verified Prompt Envelope (VPE) protocol and the Seal implementation.

## Threat Assumptions

### Trusted Components

- **VPE signing process** — The private key holder and signing environment are trusted
- **Verifier agent** — The agent running verification is trusted to enforce scope correctly
- **Key distribution channel** — Public keys are distributed through an authenticated channel
- **Operating system** — The underlying OS is trusted for file permissions and process isolation

### Untrusted Components

- **Network** — All network communication is untrusted (MitM, replay, interception)
- **Third-party APIs** — External services receive signed prompts but could attempt modification
- **LLM providers** — The model may see plaintext prompts but cannot forge signatures
- **Memory/skill pipelines** — Prompts from memory recall or skill outputs may be malicious
- **Tool outputs** — Return values from tools could attempt injection

## Threat Scenarios

### T1: Prompt Tampering

**Threat:** An attacker intercepts a signed envelope in transit and modifies the `prompt` field.

**Mitigation:** Ed25519 signature covers all fields except `signature` itself. Any modification invalidates the signature. Verification step 2 (`INVALID_SIGNATURE`) catches this.

**Residual risk:** None if canonicalization is correct across implementations (see T6).

### T2: Replay Attack

**Threat:** An attacker captures a valid envelope and re-submits it to execute the same action again.

**Mitigation:** Two-layer replay protection:
1. **Nonce** — Unique per envelope; tracked in `NonceStore`. Duplicate nonce → `NONCE_REPLAY`.
2. **Counter** — Monotonically increasing per issuer; tracked in `CounterStore`. Non-monotonic → `COUNTER_NON_MONOTONIC`.

**Residual risk:** If both `NonceStore` and `CounterStore` are lost (e.g., database corruption), replays within TTL are possible. Mitigate with short TTLs and store backups.

### T3: Scope Escalation

**Threat:** A validly signed prompt attempts to use tools or access domains beyond its declared scope.

**Mitigation:** The `scope` field is part of the signed payload. The verifier enforces scope dynamically throughout execution:
- `allowed_tools` — Tool name checked before each call
- `max_tokens` — Generation capped
- `max_cost` — Cumulative cost tracked and enforced
- `allowed_domains` — Network targets validated per request

**Residual risk:** Implementation bugs in scope checking (e.g., off-by-one in token counting, race conditions in cost tracking).

### T4: Key Compromise

**Threat:** An attacker gains access to a private key (e.g., from disk, memory dump, or supply-chain attack).

**Mitigation:**
- Private keys stored with `0600` permissions
- Key rotation support: compromised keys can be revoked via `KeyStore.revoke_key()`
- Expiring keys: `not_after` limits the window of validity

**Residual risk:** A compromised key allows the attacker to sign arbitrary prompts until the key is revoked or expired. Detect via audit log anomalies.

### T5: Replay Across Verifiers

**Threat:** A nonce consumed at one verifier is replayed at a second verifier that shares the same public key but has a separate nonce store.

**Mitigation:** The `audience` field binds the envelope to a specific verifier. A prompt for `agent:hermes-default` is rejected by `agent:division` with `WRONG_AUDIENCE`.

**Residual risk:** If multiple verifiers share the same `audience` identity, they must share the nonce/counter store. Use `agent:*` wildcard with extreme caution.

### T6: Canonicalization Attack

**Threat:** Differences in JSON serialization between signer and verifier produce different canonical payloads, allowing the attacker to exploit ambiguity.

**Mitigation:**
- Strict field ordering defined in the spec
- Deterministic JSON serialization with sorted keys
- Rejection of JSON with duplicate keys
- Same crypto library recommended for both sign and verify

**Residual risk:** Floating-point precision differences (`42.0` vs `42`), non-ASCII whitespace handling, and UTF-8 normalization can cause mismatches between implementations.

### T7: Timing Side-Channel

**Threat:** An attacker uses signature verification timing to extract information about the public key or issuer registry.

**Mitigation:**
- Constant-time signature comparison (Ed25519 verification is naturally constant-time in the cryptography library)
- Error messages SHOULD NOT distinguish between `UNKNOWN_ISSUER` and `INVALID_SIGNATURE`

**Residual risk:** Memory access patterns in nonce/counter lookup could leak issuer activity.

### T8: EPD Evasion

**Threat:** An attacker crafts a prompt that passes EPD regex scanning but is still malicious.

**Mitigation:** Two-pass EPD: regex pass (91%+ detection rate) followed by optional LLM classifier pass for ambiguous cases. The LLM pass uses a different model than the execution model, providing independent assessment.

**Residual risk:** Adversarial prompt engineering can evade both passes. EPD is a defense-in-depth layer, not a replacement for cryptographic verification. Invisible-character evasion is handled separately under T11.

### T9: Credential Leakage via Secrets Broker

**Threat:** A secret value escapes the Secrets Broker and appears in logs, prompt history, or training data.

**Mitigation:**
- `resolve()` returns a deep copy — original argument structure with `{SECRET:label}` placeholders is never modified in place
- `redact()` replaces secrets with `***REDACTED***` for safe logging
- Audit log records *that* a credential was accessed, not the value itself
- Broker never prints, logs, or emits secret values

**Residual risk:** Tool output containing the resolved secret value could be included in the conversation history. The agent must ensure it does not log or store resolved tool arguments.

### T10: TTL Bypass

**Threat:** An attacker exploits clock skew to use an expired envelope.

**Mitigation:**
- Default TTL: 300 seconds (5 minutes) — short window
- Verifier uses its own clock for expiry check
- ±30 second clock skew tolerance recommended

**Residual risk:** With significant clock skew (>30 seconds), expired envelopes may be accepted. Mitigate with NTP synchronization and counters (which provide indefinite replay protection even after TTL).

### T11: Invisible Unicode Smuggling

**Threat:** An attacker hides an instruction in invisible code points that render as nothing (or as an innocent emoji) to a human reviewer but are read as text by the model. Two carriers:
- **Tag block (U+E0000–E007F):** ASCII smuggling — e.g. `😀` followed by tag characters that decode to `ignore all previous instructions`.
- **Variation selectors (U+FE00–FE0F, U+E0100–E01EF):** arbitrary bytes encoded as a run of selectors appended to a visible character.

Both survive NFKD normalization and combining-mark stripping untouched (tag chars have no decomposition; variation selectors are combining class 0), so the classic de-obfuscation pass never sees them. They can also be interleaved between visible letters (`i<tag>g<tag>nore`) to break up a phrase the regex would otherwise match.

**Mitigation:** When `normalize_obfuscation` is on, the EPD normalization pass drops *all* Unicode format characters (category `Cf`, which subsumes every zero-width/joiner and the entire tag block) plus variation selectors before pattern matching — closing the interleaving vector. Separately, a dedicated detector (`_detect_hidden_unicode`) runs **unconditionally** — independent of the `normalize_obfuscation` toggle, since it is high-signal, near-zero false-positive, and cheap, and a performance toggle must not silently disable a security control. It:
- Flags the *presence* of any tag-block run (confidence 0.95) — legitimate prompts effectively never contain these.
- Decodes the tag run back to ASCII and re-runs the full pattern set over it, so the flag reports *what* was smuggled.
- Flags runs of `>= 3` variation selectors (confidence 0.9), the byte-smuggling signature, while leaving a lone U+FE0F emoji-presentation selector (and a 2-selector pair) untouched to avoid false positives.

**Residual risk:** Detection covers the tag block and variation selectors specifically. A variation-selector payload of 1–2 selectors falls below the run threshold and is not flagged, but cannot carry a meaningful instruction. Other private-use or format characters used as a novel covert channel, or smuggling encodings the decode step doesn't recognize, would only be caught by the presence/strip heuristics, not decoded. Stripping is detection-only and does not rewrite the envelope payload — the verifier still sees (and signs over) the original bytes.

## Security Controls Summary

| Control | Threat | Implementation |
|---------|--------|----------------|
| Ed25519 signatures | T1 (tampering) | `seal.core.vpe_sign()` / `vpe_verify()` |
| Nonce + counter | T2 (replay) | `seal.store.NonceStore`, `CounterStore` |
| Scope enforcement | T3 (escalation) | `seal.vpe._check_scope()` |
| Key permissions (0600) | T4 (key compromise) | `seal.cli.cmd_genkey()` |
| Audience binding | T5 (cross-verifier replay) | `vpe_verify()` audience check |
| Deterministic JSON | T6 (canonicalization) | `seal.core._canonical_json()` |
| Constant-time crypto | T7 (side-channel) | Ed25519 via `cryptography` library |
| Two-pass EPD | T8 (injection evasion) | `seal.epd.scanner.EPDScanner` |
| Deep-copy resolution | T9 (credential leakage) | `seal.broker.SecretsBroker.resolve()` |
| Short TTL + counters | T10 (TTL bypass) | `ttl_seconds=300` default |
| Invisible-char strip + smuggling detector | T11 (Unicode smuggling) | `seal.epd.scanner._detect_hidden_unicode()` |

## Responsible Disclosure

If you discover a security vulnerability in Seal or the VPE protocol, please report it privately to the security contacts listed in [SECURITY.md](https://github.com/nousresearch/seal/blob/main/SECURITY.md). Do not file public issues for vulnerabilities.
