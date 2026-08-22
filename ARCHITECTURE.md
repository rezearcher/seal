# Seal — Verified Prompt Envelope Protocol & AI Agent Security

> **Status:** Phases 1–9 core capabilities **implemented and tested** — VPE Core (Ed25519 + HMAC + multi-sig + hierarchical cert chains + hardware signing), EPD Scanner (regex + LLM + Unicode-smuggling defense), Secrets Broker, persistent stores, full key lifecycle + rotation daemon, Hermes/Division integration, rollback, adversarial fuzzer, and benchmarks. **P9.5 federation shipped: Python-native DNS resolver (P9.5a), DID document resolution via HTTPS (P9.5b), trust anchor exchange protocol (P9.5c), and integration tests for DNS-discovered trust anchors (P9.5d). test_federation.py grew to 142 tests / 2264 lines. Total suite count (live uv run pytest -q, 2026-08-14): 1141 passed, 1 skipped at 81.20% coverage — supersedes the earlier 798-pass count, which rested on commit history (see the 2026-08-14 sync entry).**

> **Remaining:** external adoption only — P8 (cross-language port **publishing** + OWASP/MCP standardization) and P10 (production-bake). Cross-language ports (TS/Go/Rust) are **implemented in-repo with their own test suites** (vpe-ts/, vpe-go/, vpe-rust/, P8.5a, commits bb9896c + later) AND now share a **single canonical cross-language test-vector fixture** (tests/vectors/vpe_vectors.json, 22 vectors, generated from the Python reference) consumed by an automated interop test in all four languages (commits f7c2af4 fixture+tests, e50ce42/f575146 TTL fix).

Checked the seal project architecture and recent progress; core capabilities implemented, external adoption pending, testing coverage at 81.20% as of 2026-08-14. This includes VPE Core and EPD Scanner, enhancing interoperability across cross-language ports.

**Additional Notes**: No blockers were noted for the project.

## Sync 2026-08-22 — Review-persona cycle (t_8fa7c95b, t_a1f0de05, t_ddde11df)

Three "Review Beautifier findings" tasks closed in the prior 24h. **Verified against git: they produced no product-code changes.** Their only material output is `kanban_tasks.md` (commit `193551d`, +53/-10), which now holds a review-persona findings backlog. The remaining 24h commits are non-functional: a 1-char whitespace fix in `vpe-ts/tests/core.test.ts` (`cc78d2a`) and an empty `.gitkeep` (`b4df749`). No commit references any of the three task IDs.

These are **triage passes, not implementations** — the findings they surfaced are candidate work, not shipped. Status verified in code:

- **Beautifier / Task 1 — refactor duplicate function in `vpe.py`:** No duplicate top-level function exists (`grep def … | uniq -d` is empty; every def occurs once). Finding is moot or already covered by the earlier `_canonical_json_multi → _canonical_json` consolidation (`4ad7a63`, t_c010d85c). **No change shipped; nothing left to do here.**
- **Beautifier / Task 2 — enhance error handling in `seal/hardware.py`:** **GAP — not separately implemented.** `hardware.py` is now 899 LOC / 20 `HsmError` raises. The growth from the last-synced 884 LOC traces to `b3800d0` (the Lie-Detector missing-keys task, already documented in the 2026-07-18 sync), not to a distinct Task-2 commit.
- **Lie Detector / Task 3 — missing-key error handling in `hardware.py`:** Shipped in `b3800d0` (+51 in `hardware.py`, +37 in `tests/test_hardware.py`); previously documented. No new work this cycle.
- **Gap Analyzer / Task 4 — address ARCHITECTURE.md coverage gaps (research):** This doc-sync is that pass. No new coverage gaps closed by the review cycle itself.

Core-capability and test-suite claims above are unchanged and unaffected by this cycle. Per standing seal doc-sync policy, the 1141-pass / 81.20%-coverage figure still rests on the 2026-08-14 commit history (the sandbox cannot run pytest), and no fresh pass status is asserted here.