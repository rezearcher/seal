# Seal — role in the Assay + Seal product strategy

> **Seal is one half of a whole.** The product is a continuous AI-security
> **assurance loop** — *assess (Assay) → quantify the gap → apply Seal → re-assess
> → prove the improvement.* Seal is the trust/defense half; Assay is the evaluator
> half. Neither is the product alone.
>
> **Canonical strategy doc:** `assay/docs/PRODUCT_STRATEGY.md` (private repo
> `rezearcher/assay`). Read it for the full thesis, GTM, and roadmap. This file
> is the Seal-side pointer so the strategy is discoverable from this repo.

## Where Seal wins (the axes incumbents can't touch)

Assay scores three axes of agent security. Detection-only tools (e.g. ProtectAI
LLM Guard) only play axis 1. **Do not position Seal as "best injection detector"**
— LLM Guard's trained model currently beats Seal-EPD on raw detection (100 vs 90
on our battery). Seal's moat is the other two axes:

| Axis | Seal's position |
|---|---|
| 1. Prompt-injection detection (EPD) | Competitive, not best. Iterate via the loop; Seal-LLM mode can wrap a stronger classifier. Not the selling point. |
| **2. Provenance / trust / encryption (VPE)** | **Seal's core. Incumbents score 0.** Ed25519-signed prompt envelopes, issuer/scope, TTL-expiry + nonce-replay, secrets broker. Nothing else verifies *who authorized a prompt* and *that it wasn't tampered*. |
| **3. Memory integrity (frontier)** | **Open whitespace — Seal's growth.** Extend the trust model from prompt → memory: signed/verified memory writes, provenance on retrieved context. Defends memory poisoning / RAG injection / cross-agent contamination. |

## Seal's roadmap (its half of the loop)

- **Axis 2 — exposed for measurement:** Assay is adding a *provenance battery*
  (forged / replayed / tampered / scope-escalated envelopes). Seal already
  defends these → expected Seal ~100, LLM Guard 0. Keep the VPE verification path
  airtight (TTL + nonce-replay are done; watch for further stubbed checks).
- **Axis 3 — memory-trust (the build):** extend VPE-style signing/provenance to
  the memory layer. This is the differentiated, greenfield work.
- **Axis 1 — stay competitive:** feed Seal's LLM classification pass a stronger
  model; keep ingesting jailbreak corpora so the EPD doesn't fall behind.
- **Productize:** Seal as a **managed trust/memory filter** — a drop-in added to
  existing chat or memory connections, sold with Assay's continuous re-assessment
  proving ongoing value. Open-core: OSS the core, sell the managed service.

## Proven (2026-06-10)
VPE TTL-expiry + nonce-replay hardened; latent-injection patterns merged; LLM
classification pass wired to local Ollama (free). Assay measured Seal lifting a
live model F→A on injection, and 0→87.5 on the semantic frontier once the LLM
pass was on.
