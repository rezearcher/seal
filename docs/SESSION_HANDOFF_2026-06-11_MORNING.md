# Session handoff — Seal — 2026-06-11 MORNING

**Repo:** `/home/rez/projects/seal` · **Branch:** `master` (all session work merged + pushed)

> Companion handoff in `assay/docs/SESSION_HANDOFF_2026-06-11_MORNING.md`. Read
> both — Seal and Assay are one system (Seal = the product, Assay = the prover).

## TL;DR
Big session. Audited Seal for lies, fixed them, added modern-jailbreak EPD
coverage, built the **axis-3 memory-trust API**, **productized** install + CLI,
then spent the back half in a strategy + **empirical-validation** loop that
produced an honest thesis doc and a **red-team measurement rig**. The headline
honest finding: most of the *architecture* is still **theory** — and we now have
the rig to test it.

## READ THIS FIRST
- **`docs/THESIS_AND_VALIDATION.md`** — the canonical doc. The encrypt-sanitize-
  detect thesis, the coverage map, positioning, and a **PROVEN / THEORY /
  BLOCKED ledger** with every probe result. Do not cite the THEORY parts as
  fact. This is where the strategy lives now.
- **`docs/GETTING_STARTED.md`** — empirically-verified install/use (every command
  was run before writing). One-command install: `pip install
  git+https://github.com/rezearcher/seal.git`; then `seal quickstart`.

## What shipped to master this session (PRs #4–#7, all merged)
- **Truthfulness (#4):** TS/Go/Rust ports relabeled **Planned** (they 404, don't
  exist); disclosed unencrypted-keys-at-rest; deprecation-warned the plaintext
  `secrets_broker.CredentialStore`; test count 517→569; persistent `NonceStore`
  wired into `DivisionVPESigner`.
- **EPD modern coverage (#5):** regex patterns for 7 structural modern techniques
  (policy-puppetry, flipattack, codechameleon, cipher, artprompt, cot-hijacking,
  many-shot) + O(n) many-shot check (ReDoS-safe); LLM-classifier prompt extended
  for 4 semantic families. Measured lift (Assay, vs qwen3:8b): seal-epd **0→7/11**,
  seal-epd-llm **9/11**.
- **Memory-trust axis-3 (#6):** `seal/memory.py` — `sign_memory` / `verify_memory`
  / `verify_on_recall` over VPE. Rejects unsigned/forged/tampered/untrusted-writer/
  cross-namespace/replayed records. (Resolved a merge dup: kept the version that
  imports `_ENVELOPE_FIELDS` from `seal.core`.)
- **Productized (#7):** one-command install; new CLI subcommands `seal epd`,
  `seal memory`, `seal quickstart`; fixed pyyaml dep + `seal sign` None-key crash
  + seamless key auto-resolution.
- **Docs:** `THESIS_AND_VALIDATION.md` (thesis + ledger + all probe results).

Full suite on master: **~643 tests green** (before the in-flight key change below).

## ⚠️ Uncommitted / not-mine — DO NOT CLOBBER
- `git log` shows `7ed2c9a Fix G-009: encrypt private keys at rest + auto-migrate
  legacy raw keys` on master (addresses the keys-at-rest BLOCKER) **plus an
  uncommitted change in `seal/credential_store.py` (+11 lines)** that I did NOT
  make this session — likely the in-progress G-009 work (overnight agent or Rez).
  **Left untouched.** Whoever resumes: reconcile/commit that before building on it.

## The strategy thread (what the conversation actually decided)
1. **Encryption ≠ better detection.** A signature proves *not-tampered*, not
   *not-malicious*. Retired that claim.
2. **Provenance vs detection guard different threats:** provenance kills the
   *untrusted-source* injection (docs/tools/memory/agents) by denying authority;
   detection handles *trusted-source bad-content*. Seal needs both.
3. **Semantic detection is a parity REQUIREMENT, not a flaw to skip** — reach it
   by *wrapping* the best classifier, don't reinvent. Invent on the moat.
4. **Rez's transform thesis** ("change the frame, change the rules" — back-
   translation / SmoothLLM): first *directional* evidence FOR it (see Assay
   handoff §rig). Promising, not proven.

## Blockers still open (from the ledger)
- Discrimination 100 numbers are on **our own synthetic batteries** — must re-run
  vs independent benchmarks (JailbreakBench/HarmBench) to kill "teaching to the test."
- **Adoption**: provenance needs upstream to sign. Plan: wire Seal into **Hermes**
  (`seal/integration/hermes_vpe_middleware.py` exists) as the real-world test.
- Keys-at-rest: being addressed (G-009 above) — verify it's complete.
- Market: unvalidated.

## Next session — the open fork (Rez to pick; my vote = #1)
1. **Finish the transform proof** — add stronger attacks to the rig (policy-
   puppetry/many-shot/crescendo or JBB pre-optimized PAIR/GCG artifacts) to get a
   ~20-40% baseline ASR, then measure back-translation suppression conclusively.
2. **Validate in Hermes** — Seal as full proxy (sanitize+sign+detect); run real
   agentic attacks (indirect injection, memory poison, tool hijack).
3. **Harden the moat** — sanitize-and-forward (unbuilt; EPD detects, doesn't emit
   a cleaned message); independent-benchmark re-run; finish keys-at-rest.

## Hard constraints
Division read-only unless authorized. No success theater — nothing moves THEORY→
PROVEN without a reproduced Assay number. Surface blockers. Godmode is Hermes'
(local fixes OK, no upstream push).
