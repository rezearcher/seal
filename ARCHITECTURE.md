# Seal — Verified Prompt Envelope Protocol & AI Agent Security

> **Status:** Phases 1–9 core capabilities **implemented and tested** — VPE Core (Ed25519 + HMAC + multi-sig + hierarchical cert chains + hardware signing), EPD Scanner (regex + LLM + Unicode-smuggling defense), Secrets Broker, persistent stores, full key lifecycle + rotation daemon, Hermes/Division integration, rollback, adversarial fuzzer, and benchmarks. **P9.5 federation shipped: Python-native DNS resolver (P9.5a), DID document resolution via HTTPS (P9.5b), trust anchor exchange protocol (P9.5c), and integration tests for DNS-discovered trust anchors (P9.5d). test_federation.py now measures 145 `def test_` functions / 2393 lines (verified 2026-08-25; the earlier "142 / 2264" figure was stale). Total suite count (live uv run pytest -q, 2026-08-24): 1112 passed, 1 skipped at 84.67% coverage — supersedes the earlier 1141-pass count, which rested on commit history (see the 2026-08-22 sync entry).**

> **Remaining:** external adoption only — P8 (cross-language port **publishing** + OWASP/MCP standardization) and P10 (production-bake). Cross-language ports (TS/Go/Rust) are **implemented in-repo with their own test suites** (vpe-ts/, vpe-go/, vpe-rust/, P8.5a, commits bb9896c + later) AND now share a **single canonical cross-language test-vector fixture** (tests/vectors/vpe_vectors.json, generated from the Python reference) consumed by an automated interop test in all four languages (commits f7c2af4 fixture+tests, e50ce42/f575146 TTL fix). **As of 2026-08-27 (t_032c2fb1) all three port suites — plus their interop-vector tests — run in GitHub Actions CI** (`.github/workflows/test.yml`, jobs `vpe-ts`/`vpe-rust`/`vpe-go`); previously the ports were tested only locally, so cross-language drift could never fail a build (see 2026-08-27 sync entry).

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

## Sync 2026-08-24 — Fresh green-suite verification (t_aec7c393)

Live suite re-run from the repo root (`cd /home/rez/projects/seal && uv run pytest --cov -q`; rootdir `/home/rez/projects/seal`, not `$HOME`): **1112 passed, 1 skipped, 141 subtests, 84.67% coverage** in 11m19s — green, above the 80% coverage gate. This resolves the "no fresh pass status is asserted here" caveat from the 2026-08-22 entry: the 1141-pass / 81.20% figure had not been freshly verified since 2026-08-14, and the board's headline health claim is now measured, not inherited.

- **Count delta 1141 → 1112 (−29):** fully explained by `refactor(key-store)` `54e4b58` (t_ae0a9778, 2026-08-19), which deleted the dead/duplicate `seal/key_store.py` (405 LOC) and its `tests/test_key_store.py` (426 LOC) — an intentional removal of dead code and its tests, not a regression. That commit's own verification reported 1110 passed; the live count is now 1112 (net +2 from subsequent work).
- **Coverage 81.20% → 84.67%:** rises because the deleted module's uncovered lines left the coverage denominator; no thresholds were relaxed and no tests skipped to force green.
- No regressions found in any commit since the 2026-08-14 count (refactor(key-store), hygiene commits, review cycle). The suite passes unchanged; the 2026-08-22 review-persona triage produced no product-code changes, so nothing there affects the count.
- G01 (PyPI trusted publisher) remains a separate human-gated item, untouched by this pass. **See the 2026-08-25 sync entry below: the PyPI publish is an OPEN GAP, not shipped.**

## Sync 2026-08-25 — PyPI publish REOPENED as open gap + green-suite entry corroborated (t_aec7c393, t_0764fc6d, t_8fd465b3)

Three tasks closed in the prior 24h. Verified against code/metadata (sandbox blocks command execution and outbound network, so all findings below rest on source + prior committed runs, not on fresh live probes this session):

- **t_aec7c393 — Fresh green-suite verification + dated sync entry:** Already recorded in the 2026-08-24 sync entry above (1112 passed, 1 skipped, 84.67% coverage, 11m19s). That live run predates this session; the full suite could not be re-run here (`uv run pytest` needs ~11m and is blocked in this sandbox). **No fresh pass status is asserted this session** — the green claim rests on the 2026-08-24 committed run. Structural sanity checks that DID pass this session: 54 test files present; `tests/vectors/vpe_vectors.json` interop fixture exists; `seal.cli:main` (`seal/cli.py:982`) is wired with 29 subparsers; `seal/hardware.py` = 899 LOC. The federation test count was corrected in the header (145 `def test_` / 2393 lines, was stale at 142 / 2264).

- **t_0764fc6d (REOPEN) + t_8fd465b3 (BLOCKED) — Publish seal-vpe to PyPI: OPEN GAP, NOT SHIPPED.** `pyproject.toml` declares `name = "seal-vpe"`, `version = "0.1.0"` with a `seal = "seal.cli:main"` entry point, but the package is **not published to PyPI**. t_a40992b1 was marked done, yet t_0764fc6d reopened it precisely because `seal-vpe` returns **404 on PyPI**; t_8fd465b3 is **BLOCKED on a PyPI credential** and only recorded the correction. This is a **human-gated blocker (missing PyPI credential / trusted-publisher setup = G01)**, not a code defect — nothing in-repo is broken. The docs already reflect this honestly (`docs/cli.md`, `docs/quickstart.md`, `docs/GETTING_STARTED.md`, `docs/integration.md` all state `pip install seal-vpe` fails / returns 404 and direct users to `git+https` or a locally built wheel). **Note:** the 404 could not be re-confirmed live this session (outbound network blocked); the gap status rests on the REOPEN task, the blocked publish task, and the existing docs — all in agreement. Until a PyPI credential is provided and the publish lands (P8.3b), `pip install seal-vpe` remains unavailable.

## Sync 2026-08-26 — Fail-fast wrong-rootdir guard for test entrypoints (t_babc61a6)

One task closed in the prior 24h, verified against code (commit `fac86fd`; guard branch confirmed by source, full-suite path not exercised — from the repo root it would launch the ~11m suite, and running from a wrong cwd needs sandbox approval, so the refusal branch was reviewed at the source level).

- **t_babc61a6 — Fail-fast wrong-rootdir guard: SHIPPED.** New `scripts/test.sh` (executable, 24 LOC) is now the canonical Python test entrypoint. It resolves the repo root from `${BASH_SOURCE[0]}` and, if the invocation cwd differs, prints `refusing: run from the repo root (cwd=… , repo root=…)` and exits `2` **before** invoking pytest; otherwise it `exec python3 -m pytest "$@"` with all args passed through unchanged. `Makefile:21` (`test-python`) now delegates through the wrapper (`bash scripts/test.sh tests/ -x -q`), and `README.md:225` gained the dev note that the suite must run from the repo root. This closes the **t_ff898242-class vacuous-run hole**: a suite invoked from `$HOME` (or any non-root cwd) makes pytest pick a bogus rootdir, collect nothing meaningful, and silently report a false green. The guard makes that failure loud (exit 2) instead of a vacuous pass.
- **Scope:** build/test tooling only — no product-code (`seal/`), no test-logic, and no coverage change. `uv run pytest` from the repo root (the path all prior green-suite runs used) is unaffected; the wrapper only adds a refusal for the wrong-cwd case. The 2026-08-24 green-suite figure (1112 passed, 1 skipped, 84.67% coverage) stands unchanged.

## Sync 2026-08-27 — Cross-language port suites wired into CI (t_032c2fb1)

One task closed in the prior 24h, verified against source (`.github/workflows/test.yml`, commit `4761ec2`). **CI wiring is confirmed in the workflow file; a live GitHub Actions run could not be triggered from this sandbox, so the jobs were at the time proven *defined and self-consistent* — unverified by a live run. That caveat is superseded: the follow-up sync entry below (t_3cb799e6) records the first observed-green run (push `33071796355`, commit `98da04e`).**

- **t_032c2fb1 — Wire vpe-ts/vpe-rust/vpe-go port suites into GitHub Actions CI: SHIPPED (wiring verified).** `test.yml` gained three parallel top-level jobs alongside the existing `test` (Python) job:
  - `vpe-ts` — Node 22, `npm ci` + `npm test` in `vpe-ts/` (jest, incl. interop vectors). Depends on `vpe-ts/package-lock.json` for `npm ci` and the `cache-dependency-path` — **present** (verified).
  - `vpe-rust` — stable toolchain + `Swatinem/rust-cache`, `cargo test` in `vpe-rust/`.
  - `vpe-go` — Go 1.22, `go test ./...` in `vpe-go/`; `./...` recurses into `vpe-go/vpe/` where `interop_vectors_test.go` lives (verified).
- **Interop coverage now enforced by CI in all four languages.** Each port's interop-vector test (`vpe-ts/tests/interop_vectors.test.ts`, `vpe-rust/tests/interop_vectors_test.rs`, `vpe-go/vpe/interop_vectors_test.go`) runs inside its port job; the Python side (`tests/test_interop_vectors.py`) runs in the `test` job via pytest. All four validate against the shared fixture `tests/vectors/vpe_vectors.json` (present, verified). This closes the drift-never-fails hole the task title names: before this commit the ports were tested only locally, so a cross-language divergence (or a fixture regenerated on one side) could land on master without failing a build.
- **Trigger paths:** the port jobs share the workflow's `push`/`pull_request` triggers on `main`/`master` with `paths-ignore` for `*.md`/`docs/**`/`proposals/**`. **Note this means a change confined to `.md` files does not run any suite, including the port jobs — expected for a docs-only push, but a port change accompanied only by a doc edit would still trigger via the code path.**
- **Scope:** CI/build tooling only — no product-code (`seal/`) and no test-logic changes; the ports and their tests already existed (P8.5a). This task only added the CI jobs that execute them. Prior green-suite and coverage figures are unaffected.

## Sync 2026-08-27 — Cross-language port CI jobs observed green (t_3cb799e6)

Follow-up to the t_032c2fb1 entry above. On push `33071796355` (commit `98da04e`, 2026-08-27T12:25Z) the Tests workflow ran **all five jobs green**: `test` (3.11), `test` (3.12), `vpe-ts`, `vpe-rust`, `vpe-go`. This is the first observed-green run of the cross-language drift protection t_032c2fb1 added — the jobs are no longer merely wired, they are proven green in a live GitHub Actions run. The caveat in the t_032c2fb1 entry above (jobs "proven *defined and self-consistent*" absent a live run) is hereby superseded, so future foreman cycles stop re-verifying a proven claim.

- **t_3cb799e6 — Re-sync ARCHITECTURE.md: SHIPPED (doc-only).** Added this dated sync entry recording the observed-green run (push `33071796355`, five green jobs) and corrected the stale unverified-run caveat in the t_032c2fb1 entry. Verified against the live GitHub Actions run via `gh run view 33071796355`: conclusion `success`, all five jobs completed successfully.
- **Scope:** documentation only — no product-code (`seal/`), no test-logic, and no workflow-file changes. `uv run ruff check .` passes (no Python touched). Prior green-suite and coverage figures are unaffected.

## Sync 2026-08-28 — Ruff format drift fix + origin-push of the CI wiring (t_e8e5ccc3, t_f0f42d99)

Two more tasks closed in the prior 24h, both build/CI hygiene. Verified against source (`.github/workflows/lint.yml`, the three named files, git history). **The ruff format check could not be executed live this session — every `ruff format --check` invocation was refused by the sandbox permission layer — so the "format-clean" claims below rest on the reformatting commit + the enforcing config, not on a fresh probe.**

- **t_e8e5ccc3 — Fix ruff format drift on 3 files breaking Lint CI: SHIPPED (per commit `98da04e`), Lint-green NOT independently confirmed this session.** The **Lint** workflow (`.github/workflows/lint.yml`, separate from `test.yml`) runs two gates: `uv run ruff check .` (lint.yml:36) and `uv run ruff format --check .` (lint.yml:39). The latter is the one format drift breaks. Commit `98da04e` ("style(format): ruff format drift on seal/core.py, test_hermes_skills_guard, test_vpe") reformatted the three files — all three present and confirmed on disk (`seal/core.py`, `tests/test_hermes_skills_guard.py`, `tests/test_vpe.py`). **Caveat / open verification gap:** the observed-green run cited in the t_3cb799e6 entry (`33071796355`) is the **Tests** workflow (`test.yml`), which does **not** run ruff — so it does *not* prove the **Lint** workflow is green. A live-green Lint run post-fix was not confirmed here (the `ruff format --check` probe was blocked). Treat Lint-green as claimed-by-commit, not observed, until a foreman cycle can run `uv run ruff format --check .` or read `gh run` for the Lint workflow.
- **t_f0f42d99 — Push unpushed CI commits (port-suite jobs absent from origin `test.yml`): SHIPPED per task + memory, origin state NOT re-verified this session.** The port-suite CI jobs (t_032c2fb1, commit `4761ec2`) and the accompanying doc-sync (`f52f990`) had been committed **locally but never pushed**, so the cross-language drift protection wired into `test.yml` was not actually running on origin — a fabricated-done that this task corrected by pushing. Prior codebase memory records commits `4761ec2` + `f52f990` reaching origin on 2026-08-27 with CI run `#33058087008` green. **Caveat:** origin/master state could not be re-checked here (git commands are out of scope for this doc-sync pass, outbound network blocked); the push-landed status rests on the task + memory + the fact that the later observed-green Tests run (t_3cb799e6) necessarily executed on origin. No product-code or workflow-logic changed — this was a delivery (push) action only.

## Sync 2026-08-28 — Lint workflow observed green (foreman verification)

Resolves the open caveat in the t_e8e5ccc3 entry above ("Lint-green NOT independently confirmed this session"). Verified live this foreman cycle:

- `uv run ruff format --check .` → `67 files already formatted`, exit 0 — format-clean confirmed locally (the exact gate lint.yml:39 runs).
- `gh run list --workflow=lint.yml` → latest Lint run `33071796403` (push `style(format): ruff format drift…`, 2026-08-27T12:25:35Z) = **success**. The prior Lint failures (`33058087074`, `32848308658`) predate the fix commit `98da04e`.

## Sync 2026-08-29 — Backlog adjudication + thesis-ledger Lamarck entry (t_da70723c, t_ccb218fc)

Two tasks closed in the prior 24h, both documentation/adjudication (no product-code touched this cycle).

- **t_da70723c — Adjudicate stale `new_tasks.md`/`kanban_tasks.md` findings: SHIPPED (doc-only).** The recurring "enhance error handling in `seal/hardware.py`" finding is **DEAD** — the error-handling pass is already shipped, so the re-proposal is a stale premise, not open work. **Verified in code this session:** `grep -n "raise HsmError" seal/hardware.py` = **20 raise sites** in structured `except → raise HsmError(...) from exc` chains, **0 bare excepts** (`grep -E 'except:\s*$'` empty), file = 899 LOC. This matches the GAP resolution already recorded in the 2026-08-22 entry (Beautifier/Task 2) and the Lie-Detector `b3800d0` shipment.
  - **Correction to propagate, do not copy the backlog figure:** `new_tasks.md:14` and the task title assert "**22 `HsmError` raise-sites**". That "22" is the `grep -c HsmError` *line* count (22 lines contain the token — including the class definition and a non-raise `HsmError(...)` construction), **not** the number of `raise` statements. The verified raise-site count is **20**. Downstream docs should say **20 `raise HsmError` sites / 899 LOC**, not 22 raises.
- **t_ccb218fc — Record Lamarck memory-poison [PROVEN] in `docs/THESIS_AND_VALIDATION.md` ledger: SHIPPED (doc-only, commit `b628f6f`).** **Verified present** at `docs/THESIS_AND_VALIDATION.md:86–92` under the "[PROVEN] — reproduced with Assay this session" section: Lamarck live-system, always-on signed-provenance gate rejected **16087/16087** poison events; evidence at `~/projects/lamarck/experiments/m1_seal_collapse/` (`collapse_test.py`, `RESULTS.md`) + `proposals/lamarck-first-client.md`. This is the first live-system (not synthetic-benchmark) [PROVEN] datapoint in the ledger.
- **Scope:** documentation only — no `seal/`, test-logic, or workflow changes. Prior green-suite (1112 passed / 84.67%, 2026-08-24) and CI figures are unaffected.

Both Lint-workflow gates are now observed green, not merely claimed-by-commit. The t_e8e5ccc3 "claimed-by-commit, not observed" caveat is hereby superseded. No product-code or workflow-file changes — verification/doc-sync only.
## Sync 2026-08-30 — Five closures, zero code (t_f2a318ac, t_a4a902b9, t_ef4642cb, t_90d10fd4, t_aa6f0317)

Five cards closed in the prior 24h. **Verified against git: no commit references any of the five task IDs, and no product-code changed.** They are adjudication/triage closures, not implementations — nothing to record as shipped:

- **t_a4a902b9 — Refactor Duplicated Code: AUTO-CLOSED duplicate** of `seal/t_8c774745` ("Eliminate Duplicated Code"), which **remains OPEN**. The board comment cites prior external completion (commit `fc70e5b`); the real card is the open one.
- **t_ef4642cb — Optimize Loops: AUTO-CLOSED duplicate** of `seal/t_14fd76dc` ("Optimize O(n²) Loops"), which **remains OPEN**; recreated as t_aa6f0317 for durable state.
- **t_aa6f0317 — Optimize Loops: closed with CRITIC FAIL on its own acceptance predicate** (LLM-auditor card, no machine-checkable predicate). Worker examined the indexed files and found **no loop structures / no O(n²) instances** in the visible Python files (seal/epd/patterns.py is regex-only); no commit landed.
- **t_90d10fd4 — Optimize Loops: closed done, empty result**; comment states recent repo commits already addressed the loop work. No commit references the task ID.
- **t_f2a318ac — Handle Silent Exceptions: closed done, empty result**; no commit references the task ID.

Per standing seal doc-sync policy (same as the 2026-08-22 review-persona cycle): these are **triage passes, not implementations** — the findings they surfaced are candidate work, not shipped. Core-capability and test-suite claims above are unchanged; prior green-suite figure (1112 passed / 84.67%, 2026-08-24) stands.

## Sync 2026-08-31 — Silent chmod OSError swallow fixed in `_ensure_seal_dir()` (t_66912521)

One task closed in the prior 24h — a real product-code change (unlike the prior five triage-only closures). **Verified in code this session** (`seal/cli.py:70-75`), matching commit `2d76e2c` in the recent-commits list.

- **t_66912521 — Fix silent chmod OSError swallow in `seal/cli.py::_ensure_seal_dir()` (L-001): SHIPPED (verified in code).** `_ensure_seal_dir()` no longer swallows `chmod` failures silently. The `SEAL_DIR.chmod(0o700)` call is now wrapped in `try/except OSError as exc` and logs `log.warning("cannot set 0700 perms on seal dir %s: %s", SEAL_DIR, exc)` on failure (module logger `log = logging.getLogger(__name__)` at `cli.py:60`). Prior behaviour was a bare `pass` that hid a failure to restrict the credential-directory permissions — a security-relevant silent failure (L-001). The `mkdir(parents=True, exist_ok=True)` on the line above is intentionally left to raise (directory creation failure should be fatal); only the best-effort permission hardening is now warned-and-continued rather than swallowed. Callers at `cli.py:139` and `cli.py:986` are unchanged.
- **Scope:** single-function product-code change in `seal/cli.py` — no test-logic, workflow, or coverage change recorded for this task. Prior green-suite figure (1112 passed / 84.67%, 2026-08-24) is unaffected; the sandbox cannot re-run pytest, so no fresh pass status is asserted here.

## Benchmark baseline (2026-08-31)

Benchmark results are now durable: `.github/workflows/benchmark.yml` invokes the canonical benchmark scripts (`uv run python benchmark_vpe_verify.py`, `uv run python benchmark_envelope_size.py`) instead of the old inline ad-hoc script, tees each to `benchmark_*.log`, and the upload-artifact step picks those logs up (previously the step printed to stdout only, so the weekly Monday run shipped no artifact). This baseline supersedes the pre-wiring status-quo where ARCHITECTURE.md claimed benchmarks with targets but no recorded measurements existed.

Baselines measured 2026-08-31, local x86_64, `uv run` from repo root (100 runs/size):

- **VPE verify latency (avg):** 1KB (1,008 B envelope): **0.068 ms** — PASS (<5 ms target); 10KB (10,008 B): **0.090 ms** — PASS (<10 ms); 100KB (100,008 B): **0.239 ms** — PASS (<20 ms). Phase breakdown dominated by Ed25519 verify (~45–87%) + canonical JSON rebuild (~8–38%); envelope throughput ~15–418 MB/s by size.
- **Compact-envelope overhead (deterministic, asserted in CI):** **216 B** for compact Ed25519 envelopes vs the <300 B target — PASS; 124 B saved vs standard (36% on a 1-B prompt). Compact parse is ~33% faster; compact verify ≈ standard verify (~0.054 ms both).
- **CI assertion policy:** latency targets are reported (not gated — noisy on shared GitHub runners); the deterministic <300 B compact-overhead target is asserted by `benchmark_envelope_size.py` (printed as `pass_target`).
