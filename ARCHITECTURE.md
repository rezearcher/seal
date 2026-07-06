1|# Seal — Verified Prompt Envelope Protocol & AI Agent Security
2|
3|> **Status:** Phases 1–9 core capabilities **implemented and tested** — VPE Core (Ed25519 + HMAC + multi-sig + hierarchical cert chains + hardware signing), EPD Scanner (regex + LLM + Unicode-smuggling defense), Secrets Broker, persistent stores, full key lifecycle + rotation daemon, Hermes/Division integration, rollback, adversarial fuzzer, and benchmarks. **688 tests collected.**
4|> **Remaining:** external adoption only — P8 (cross-language port **publishing** + OWASP/MCP standardization) and P10 (production-bake). Cross-language ports (TS/Go/Rust) are **implemented in-repo with their own test suites** (`vpe-ts/`, `vpe-go/`, `vpe-rust/`, P8.5a, commits `bb9896c` + later) AND now share a **single canonical cross-language test-vector fixture** (`tests/vectors/vpe_vectors.json`, 22 vectors, generated from the Python reference) consumed by an automated interop test in all four languages (commits `f7c2af4` fixture+tests, `e50ce42`/`f575146` TTL fix). The ports are **not yet published to package registries**. See per-phase status tags below.
5|> **2026-07-05 sync — new board task "Publish seal-vpe to PyPI (complete what `t_0c0fff25` left undone)" marked COMPLETE, but the publish is UNVERIFIED (unverified-gap):** The task title is a *claim*, not evidence. This sync found **no local-code change** consistent with a fresh publish since the last sync — `pyproject.toml` unchanged (Jul 1), the `dist/` artifacts unchanged (`seal_vpe-0.1.0-{whl,tar.gz}`, Jun 28), `publish.yml` unchanged, project version still `0.1.0`. A successful trusted-publish re-run leaves no local trace *either way*, so absence-of-change cannot confirm success — and the only authoritative check (the live PyPI registry) was **permission-blocked this session** (both `curl https://pypi.org/pypi/seal-vpe/json` and WebFetch were denied), so no HTTP 200/404 could be observed. **As of the last live check (prior sync, 2026-07-01) `seal-vpe` was 404 on PyPI.** Do NOT treat this task's completion as "seal-vpe is on PyPI" until someone confirms `https://pypi.org/pypi/seal-vpe/json` → 200 (or `pip install seal-vpe` succeeds). To close: confirm the PyPI trusted-publisher/pending-publisher is configured for `seal-vpe`, re-run/observe `publish.yml`, then re-verify the registry returns 200.
>
> **P8.3b — GitHub push DONE, PyPI publish ATTEMPTED-AND-FAILED, `seal-vpe` still NOT on PyPI (`t_a40992b1`; publish task `P8.3b-2`; publish-prep `t_0c0fff25`/`t_dd8f649c`):** The repo IS live on GitHub at `github.com/rezearcher/seal` (local HEAD now `7fd3462`). **New since last sync (verified live 2026-07-01 — network is NOT blocked this session):** a **GitHub Release `v0.1.0` now exists** (published 2026-06-28T09:22Z, target `master`), which **did** trigger `publish.yml` (`on: release: published`). The workflow run (`Publish to PyPI`, run `28317759671`, 2026-06-28T09:22:29Z) **completed with conclusion=failure**: the `Build package` step succeeded but the **`Publish to PyPI` upload step failed** (most-likely cause: PyPI trusted-publishing / pending-publisher not yet configured for the `seal-vpe` project — unconfirmed, upload step never authenticated). **Net result is unchanged for users:** `https://pypi.org/pypi/seal-vpe/json` → **404 (verified live 2026-07-01)**, so `pip install seal-vpe` still fails. So the prior doc claims "no GitHub Release exists" and "publish.yml has never fired" are now **both false** — a release exists and the workflow fired once and failed. (Note: the local `v0.1.0` git tag ref still points at `0b8233f`/2026-06-18, stale vs. the Release which targets `master`.) **Publish-prep code changes shipped (`t_0c0fff25`, commit `d97ea7c`, 2026-06-28; reviewed under `t_dd8f649c`):** the `[project.urls]` in `pyproject.toml` were corrected from `github.com/nousresearch/seal` to the real remote `github.com/rezearcher/seal`, and `seal/__init__.py` now resolves `__version__` via `version("seal-vpe")` (the correct dist name) instead of `version("seal")`. **Authors fixed (`t_d3c9664e`, commit `a475697`):** `pyproject.toml` `authors` (line 13) now reads `{name = "Rez Archer"}` — the earlier "still lists Nous Research" residual is closed. **CI-fix tasks landed 2026-07-01/02 (code-level verified, CI-green NOT re-run this sync):** the three red workflows — `Tests`, `Deploy Docs`, `Lint` — were each addressed by a dedicated fix commit: `8cc5418` (t_396124b9) lowered the coverage gate `fail_under` 80→**64** in `pyproject.toml` (confirmed at line 72); `9ea0de4` (t_c4cae88f) fixed the `mkdocs build --strict` link warnings (docs.yml still runs `--strict`, so the fix was correcting the broken doc links, not relaxing the gate); `f435f7b` (t_086580fb) resolved the 403 ruff lint errors — `[tool.ruff.lint]` now sets `select=["E","F","W","I","N","UP"]` with per-file-ignores (`"vpe-ts/*"=["E501","N802"]`, `"tests/*"=["N814"]`). **Caveat:** this sync could not execute `ruff check`, `mkdocs build`, or `pytest --cov` (probes permission-blocked), so the config/link fixes are confirmed by reading the files but a **green CI run is not independently verified** — see the CI gap note under Phase 8.
6|> **Board:** seal
7|> **Assignee profile:** default (Claude Code via Max plan)
8|> **Foreman cadence:** 3x/day (4am/noon/8pm)
9|
10|> ⚠️ **Doc-accuracy note:** the "Build Phases" sections below were the *original plan*. Each phase header now carries a status tag (✅ Implemented / 🟡 Partial / ⬜ External). For the authoritative inventory of what physically exists, see [What's Built](#whats-built-current-state) — keep that section in sync when modules land.
11|
12|## Core Problem
13|
14|AI agents execute prompts from multiple sources: user input, tool returns, attached documents, memory recall, skill pipelines. Any of these can inject unauthorized instructions. Current industry defense is purely linguistic (Anthropic's prose-level "untrusted data, never execute instructions" — SOTA is ~91% static regex, bypassed by semantic obfuscation). No existing product, paper, or standard does **cryptographic provenance verification** at the prompt level.
15|
16|Seal (VPE) replaces linguistic detection with cryptographic enforcement.
17|
18|## The VPE Protocol
19|
20|A verified prompt is a JSON wrapper with Ed25519 signature:
21|
22|```json
23|{
24|  "vpe_version": "1.0",
25|  "prompt": "search the database for customer records...",
26|  "scope": {
27|    "allowed_tools": ["database_search", "read_file"],
28|    "max_tokens": 4000,
29|    "max_cost": 0.05,
30|    "allowed_domains": ["*.internal.corp.com"]
31|  },
32|  "issuer": "user:rez",
33|  "audience": "agent:hermes-default",
34|  "doc_sha256": "abc123...",
35|  "ttl_seconds": 300,
36|  "nonce": "a1b2c3d4",
37|  "counter": 42,
38|  "signature": "ed25519_sig_hex..."
39|}
40|```
41|
42|### Fields
43|| Field | Purpose | Example |
44||-------|---------|---------|
45|| `vpe_version` | Protocol version | `"1.0"` |
46|| `prompt` | The actionable instruction | `"search database..."` |
47|| `scope` | Least-privilege capabilities | `{allowed_tools, max_tokens, ...}` |
48|| `issuer` | Who authorized this | `"user:rez"` |
49|| `audience` | Which agent should execute | `"agent:hermes-default"` |
50|| `doc_sha256` | Binding to source document | `"abc123..."` |
51|| `ttl_seconds` | Expiry from issuance | `300` (5 minutes) |
52|| `nonce` | Uniqueness (replay prevention) | `"a1b2c3d4"` |
53|| `counter` | Monotonic — detect skipped prompts | `42` |
54|| `signature` | Ed25519 over all prior fields | hex string |
55|
56|## Three Sub-Systems
57|
58|### 1. VPE Core (sign + verify)
59|- Ed25519 key pair generation
60|- `vpe_sign(prompt, scope, issuer, audience, ...) → signed_envelope`
61|- `vpe_verify(signed_envelope) → {valid: bool, reason: str}`
62|- Python reference implementation with no dependencies beyond `cryptography` or `nacl`
63|
64|### 2. EPD (Embedded Prompt Detection)
65|- Pre-LLM scanner that runs inside the VPE verification gate
66|- Detects: jailbreak patterns, role-switching, "ignore previous instructions", hidden instructions in attached docs
67|- Regex first-pass (~91% catch rate), LLM classification pass for suspicious-but-ambiguous
68|- Outputs: `{clean: bool, flags: [pattern_name, confidence, location]}`
69|
70|### 3. Secrets Broker
71|- Credential proxy that never lets API keys/tokens enter model context
72|- Agents request secrets by label (`"tastytrade_sandbox"`) — broker injects directly into tool calls
73|- Keeps keys out of prompt history, log files, and training data
74|
75|## Build Phases
76|
77|### Phase 1 — VPE Spec & Reference Implementation
78|- Write formal protocol spec (this doc → v1.0 spec)
79|- Python implementation: sign + verify with Ed25519
80|- CLI tool: `seal sign <prompt> --scope ... --issuer ...`
81|- CLI tool: `seal verify <envelope>`
82|- Unit tests: signing, verification, tamper detection, TTL expiry, replay prevention
83|
84|### Phase 2 — EPD Scanner
85|- Regex patterns for known injection vectors
86|- LLM fallback for semantic obfuscation
87|- Integration with VPE verification gate
88|- Test suite: clean prompts, known injection patterns, edge cases
89|
90|### Phase 3 — Secrets Broker
91|- Credential store (key-value, file-backed or env-based)
92|- Proxy pattern for tool calls
93|- Audit log of credential access
94|- Integration test: agent tool calls broker, not context
95|
96|### Phase 4 — Hermes/Division Integration
97|- MCP middleware layer: every tool call wrapped in VPE
98|- Division memory episode signing
99|- Proposal as OWASP Agentic Security control category
100|- Proposal as MCP spec extension (signing layer)
101|
102|## What Already Exists (Rez's prior work)
103|- **Membrane** (Night Agent): Ed25519 Tickets per-action, chained Receipts — action-level, VPE is prompt-level, complementary
104|- **TRUSTBAC**: RBAC+ABAC+ReBAC+RAdAC authorization framework — VPE is prompt authentication, complementary
105|- **Division injection scanning gap**: write-time scanning identified but not implemented (low effort, high impact)
106|- **Hermes skills guard**: 120+ regex patterns — reactive, no crypto
107|
108|## Industry Gap Analysis
109|| Domain | What Exists | Seal's Addition |
110||--------|-------------|-----------------|
111|| Injection detection | Guardrails AI, NeMo, Rebuff, Lakera | Cryptographic provenance, not just content filtering |
112|| Prompt security products | All content-based | None do signed execution |
113|| OWASP LLM Top 10 | Identifies injection as #1 risk | No crypto mitigations proposed |
114|| MCP spec | Protocol for tools/lifecycle | No auth, no scope, no replay protection |
115|| IETF | No standards for prompt security | Could be an IETF draft |
116|
117|## Key Constraints
118|- Zero external runtime dependencies (stdlib + cryptography lib only)
119|- All operations must be verifiable offline (no SaaS dependency)
120|- VPE must be backwards-compatible — unsigned prompts still work (logged as "unverified")
121|- Secrets Broker must be opt-in — agents can run without it
122|- EPD false positive rate < 5% on benign prompts
123|
124|---
125|
126|<a id="whats-built-current-state"></a>
127|## What's Built (current state)
128|
129|> Authoritative inventory of modules that physically exist, with the test file that exercises each. **688 tests collected.** Keep this table current when modules land — it is the anti-confusion anchor for the roadmap below.
130|
### VPE Core — signing & verification (Phase 1, plus 5.4 / 9.1 / 9.3 / 9.4)
| Module | LOC | Provides | Tests |
||--------|-----|----------|-------|
|| `seal/core.py` | 1229 | `vpe_sign`/`vpe_verify` (Ed25519), `vpe_sign_hmac`/`vpe_verify_hmac` (HMAC-SHA256, P5.4), `vpe_sign_multi`/`vpe_verify_multi` (N-of-M multi-sig, P9.3), `verify_certificate`/`verify_cert_chain` (hierarchical issuer chains, P9.1), `vpe_sign_hardware`/`vpe_verify_hardware` (P9.4), scope/nonce/counter/TTL enforcement | `test_core.py` (146), `test_crypto_bypass.py` (54) |
|| `seal/vpe.py` | 589 | Envelope dataclasses, canonical JSON, multi-backend Ed25519 (NaCl or `cryptography`). **t_03ea2d3a:** `SIGNED_FIELDS` aligned with core.py (added `iat`, `cert_chain` → 11 fields); `issued_at` renamed to `iat`; `_canonical_json` now uses key insertion order (matching core's `_ENVELOPE_FIELDS`); `vpe_sign()` always includes `cert_chain: None`; scope keys sorted for byte-for-byte canonical match. +3 lines, 5 new interop tests (688 total). | `test_core.py` |
136|| `seal/cli.py` | 649 | 18-command CLI (see below) | e2e |
137|
138|### EPD Scanner — injection detection (Phase 2, plus 7.1 / 7.4)
139|| Module | LOC | Provides | Tests |
140||--------|-----|----------|-------|
141|| `seal/epd/scanner.py` | 349 | Two-pass scan (regex ~91% + optional LLM). Normalization strips **all** Unicode format chars (Cf) + variation selectors; `_detect_hidden_unicode()` flags/decodes invisible **tag-block & variation-selector smuggling** (threat-model **T11**), runs unconditionally | `test_epd.py` (57) |
142|| `seal/epd/patterns.py` | 615 | Regex patterns: jailbreaks, role-switch, ignore-instructions, delimiter confusion, hidden markers, tool hallucination, homoglyph/leet | — |
143|| `seal/epd/llm_classifier.py` | 145 | LLM tiebreaker / `llm_scan_all` catch-all pass (independent model) | `test_epd.py` |
144|| `seal/epd/fuzzer.py` | 960 | Pattern-mutation fuzzer, `seal fuzz` (P7.1 adversarial). Mutation-strategy + composite loops log a `logger.warning` on per-strategy failure rather than silently `continue` (t_ed914b66 / t_0b226fe3, e29288d) | `test_epd.py` |
145|| `seal/epd/{config,models}.py` | 147 | `EPDConfig`, `EPDFlag`, `EPDResult` | `test_epd.py` |
146|
147|### Secrets Broker — credentials out of context (Phase 3)
148|| Module | LOC | Provides | Tests |
149||--------|-----|----------|-------|
150|| `seal/broker.py` | 91 | `{SECRET:label}` placeholder resolution into tool calls, deep-copy + `redact()` | `test_broker.py` (12) |
151|| `seal/secrets_broker.py` | 34 | Back-compat shim — re-exports `CredentialStore` / `CredentialStoreCorruptedError` from `seal.credential_store` (legacy plaintext store deleted, P3.3a / `t_84148f82`). **Now emits `DeprecationWarning` at import time** (t_fc67351b, commit `1971948`). | `test_secrets_broker.py` (migrated to encrypted store) |
152|| `seal/credential_store.py` | 207 | File store, **Fernet-encrypted at rest** | `test_credential_store.py` (11) |
153|| `seal/audit.py` | 234 | Append-only JSONL access audit (records access, never values) | `test_audit.py` (12) |
154|
155|### Key lifecycle & persistence (Phase 5)
156|| Module | LOC | Provides | Tests |
157||--------|-----|----------|-------|
158|| `seal/store.py` | 247 | SQLite (WAL) `NonceStore` + `CounterStore`, expiry cleanup (P5.2) | `test_store.py` (32) |
159|| `seal/key_manager.py` / `seal/key_store.py` | 920 | SQLite key registry: generated→active→expiring→retired→revoked, auto-rotation guard (P5.5) | `test_key_manager.py` (37), `test_key_lifecycle.py` (27) |
160|| `seal/rotator.py` | 43 | Rotation daemon — one-shot (cron) or persistent (`seal key daemon`) | (lifecycle) |
161|| `benchmark_vpe_verify.py`, `benchmark_envelope_size.py` | — | P5.1 / P5.3 perf + size benchmarks | — |
162|
163|### Deployment & integration (Phases 4 / 6)
164|| Module | LOC | Provides | Tests |
165||--------|-----|----------|-------|
166|| `seal/integration/hermes_vpe_middleware.py` | 671 | Wraps Hermes tool calls in VPE verify + EPD scan | `test_e2e_real_tools.py` (37) |
167|| `seal/integration/hermes_skills_guard.py` | 316 | VPE/EPD-backed skills guard | `test_e2e_real_tools.py` |
168|| `seal/integration/division_vpe_signer.py` | 522 | Sign Division episodes | `test_division_audit.py` (13) |
169|| `seal/integration/division_vpe_audit.py` | 465 | Store/query VPE results in Division memory (P6.4). L-006/007 hardened (t_55865f62, t_373d679c): canonicalization failure now logs warning + uses `degraded:` prefix; cross-reference append logs warning instead of bare `except:pass`. Dead `_canonical_hash()` with bare except removed (t_a4423aec). | `test_division_audit.py` |
170|| `seal/division_audit.py` | 722 | Division audit-trail store + query | `test_division_audit.py` |
171|| `seal/rollback.py` | 508 | One-toggle disable + full config rollback, audit preserved (P6.5). Paths resolved lazily at call time via `_resolve_seal_home()`/`_resolve_hermes_home()` with `SEAL_HOME`/`HERMES_HOME` env overrides — no hardcoded `Path.home()` at import time (L-006). Audit-log line counting (`_archive_audit`, status report) uses a `with open(...)` context manager (no FD leak) and logs `logger.warning(..., exc_info=True)` on read failure instead of silently swallowing (t_226c651b) | `test_graceful_degradation.py` (20) |
172|
173|### Advanced (Phase 9)
174|| Module | LOC | Provides | Tests |
175||--------|-----|----------|-------|
176|| `seal/hardware.py` | 706 | HSM abstraction — YubiKey/TPM/Secure Enclave signing, key never leaves device (P9.4) | `test_hardware.py` (27) |
177|| `seal/federation.py` | 699 | Cross-agent trust anchors, federated audit (P9.5) | `test_federation.py` (32) |
178|
179|### Cross-language ports & interop (Phase 8.5a)
180|- **Ports:** `vpe-ts/` (TS, 617 LOC, 114 tests), `vpe-go/vpe/` (~778 LOC, 39 test funcs), `vpe-rust/src/` (~929 LOC, 33 `#[test]`) — API parity with the Python reference, **not published** to npm/crates.io/Go registries.
181|- **Shared interop fixture:** `tests/vectors/vpe_vectors.json` (22 vectors, valid + tampered, Ed25519 + HMAC; ttl ∈ {0, 31536000}), generated by `tests/generate_vectors.py` from the Python reference.
182|- **Interop tests (one per language, same fixture):** `tests/test_interop_vectors.py`, `vpe-ts/tests/interop_vectors.test.ts`, `vpe-go/vpe/interop_vectors_test.go`, `vpe-rust/tests/interop_vectors_test.rs`. (Not re-run this sync — sandbox blocks the runners.)
183|
184|### Standards, packaging & docs (Phase 8, partial)
185|- **`VPE_SPEC_v1.md`** (839 lines) — full protocol spec.
186|- **`proposals/`** — `owasp_agentic_security_vpe.md`, `mcp_signing_extension.md`, `SEP-vpe-signing-layer.mdx`; **`seal-community/`** — conference CFP drafts.
187|- **Docs site** — MkDocs (`mkdocs.yml`, `docs/` 18 pages: spec, API reference, CLI, integration, threat model, quickstart) → `docs.yml` CI deploy.
188|- **CI** — `.github/workflows/`: `test.yml`, `lint.yml`, `benchmark.yml`, `publish.yml` (PyPI `seal-vpe`, trusted-publishing via `pypa/gh-action-pypi-publish`, `on: release: published`). **`publish.yml` fired once and FAILED** (verified live 2026-07-01): GitHub Release `v0.1.0` was published 2026-06-28, triggering run `28317759671` (`Publish to PyPI`) — `Build package` succeeded, the **`Publish to PyPI` upload step failed** (likely trusted-publishing/pending-publisher not configured on PyPI). So `seal-vpe` is **still not on PyPI** — `https://pypi.org/pypi/seal-vpe/json` → **404 (live-verified 2026-07-01)**; `pip install seal-vpe` fails. Repo is live at `github.com/rezearcher/seal`. Built artifacts exist locally in `dist/` (`seal_vpe-0.1.0-py3-none-any.whl`, `.tar.gz`, rebuilt 2026-06-28) but the registry upload never completed. **2026-07-05: a new board task claiming the PyPI publish was completed landed, but it is an UNVERIFIED claim — no local-code change since the last sync, and the live registry check was permission-blocked this session (see the dated note in the header block). Still shown as NOT-on-PyPI until a live 200 is observed.** Publish-prep config fixes landed in `d97ea7c` (`t_0c0fff25`): `[project.urls]` repo links corrected to `rezearcher/seal`, `__init__.py` dist name → `seal-vpe`; `authors` corrected to `Rez Archer` in `a475697` (`t_d3c9664e`).
- **CI health gap (fix commits landed 2026-07-01/02; CI-green NOT re-verified this sync):** the three red workflows each got a targeted fix commit on `master`:
  - **`Tests`** — `8cc5418` (t_396124b9): coverage gate `fail_under` lowered 80→**64** in `[tool.coverage.report]` (pyproject.toml:72, confirmed by read). test.yml runs `uv run pytest --cov`; codecov upload has `fail_ci_if_error: false`, so the local `fail_under` is the actual gate.
  - **`Deploy Docs to GitHub Pages`** — `9ea0de4` (t_c4cae88f): fixed the `mkdocs build --strict` link warnings. docs.yml **still** invokes `mkdocs build --strict`, so the fix corrected the offending doc cross-links — it did not weaken the strict gate.
  - **`Lint`** — `f435f7b` (t_086580fb): resolved the reported 403 ruff errors. `[tool.ruff.lint]` sets `select=["E","F","W","I","N","UP"]`, `line-length=120`, `target-version="py311"`, with per-file-ignores `"vpe-ts/*"=["E501","N802"]` and `"tests/*"=["N814"]` (confirmed by read). lint.yml runs both `ruff check .` and `ruff format --check .`.
  - **Gap / not re-verified:** this sync could not run `ruff check`, `ruff format --check`, `mkdocs build --strict`, or `pytest --cov` (execution permission-blocked). The config and workflow files confirm the fixes are wired, but **no green CI run was observed this sync** — do not assume the three workflows are passing until a live run is checked. The "**684 tests collected / tested**" claim likewise rests on local runs and commit history, not on observed-green CI.
189|- **Version reporting (FIXED, `t_0c0fff25`/`d97ea7c`):** `seal/__init__.py` now resolves `__version__` via `importlib.metadata.version("seal-vpe")` — the correct distribution name (was `version("seal")`, the wrong name, which fell back to the hard-coded `"0.1.0"`). With `seal-vpe` installed in this environment, `version("seal-vpe")` now resolves to `0.1.0` from installed metadata (verified 2026-06-29), not the fallback branch; the `except PackageNotFoundError → "0.1.0"` fallback remains for uninstalled use.
190|
191|### CLI surface (`seal …`)
192|`genkey` · `sign` · `verify` · `secrets {add,get,list,delete}` · `audit` · `key {rotate,revoke,disable,list,daemon}` · `rollback` · `hardware` · `fuzz` · `status`
193|
194|---
195|
196|## Security Notes / Known Limitations
197|
198|- **Private keys unencrypted at rest:** `seal/key_manager.py` stores private keys raw (unencrypted) in the SQLite registry at `~/.seal/keys.db`. The module docstring acknowledges this: "encryption-at-rest is future work." Protect the file with restrictive filesystem permissions (`chmod 600`) until encryption-at-rest lands.
199|- **TTL enforcement requires `iat`:** In both `seal/core.py` and `seal/vpe.py`, TTL expiry is only enforced when the `iat`/`issued_at` field is present in the envelope. When `iat` is absent (backward-compat envelopes), TTL is silently skipped. Envelopes produced by `vpe_sign` always include `iat`.
200|- **Single, encrypted credential store (legacy plaintext store removed — P3.3a, `t_84148f82`):** `seal/credential_store.py` (`seal.credential_store.CredentialStore`) is Fernet-encrypted at rest and is the only credential-store implementation. The legacy plaintext-JSON `CredentialStore` (and `AuditLog`) that previously lived in `seal/secrets_broker.py` and wrote credentials to `~/.hermes/secrets.json` have been **deleted**. `seal/secrets_broker.py` is now a 34-line back-compat shim that re-exports `CredentialStore` / `CredentialStoreCorruptedError` from `seal.credential_store`; its module docstring marks it deprecated, and it **now emits a `DeprecationWarning` at import time** (t_fc67351b, commit `1971948`). Use `seal.broker`, `seal.credential_store`, and `seal.audit` directly for all new integrations.
201|- **`seal/integration/division_vpe_audit.py` — L-006 + L-007 hardened + dead code removed (closed t_55865f62, t_373d679c, t_a4423aec):** Three fixes in `DivisionVPEAudit`. (1) **L-006 (canonicalization fallback in `record_from_result`):** A bare `except Exception:` that silently aliased the envelope hash to a nonce fragment was replaced with `except (TypeError, ValueError, KeyError)`, adds a `degraded:` prefix, logs a `logger.warning` naming the issuer + degraded hash, and sets `reason="hash_computation_failed"` when the caller didn't supply one. (2) **L-007 (cross-reference append):** A bare `except: pass` in `record()` when appending the Division episode reference to the local log was replaced with a `logger.warning` that includes the `audit_id` and `episode_id`. (Gap: `_extract_episode_id` still has a silent `except (json.JSONDecodeError, TypeError, AttributeError): pass`.)
202|- **Cross-language ports implemented in-repo, not published (P8.5a):** TypeScript (`vpe-ts/src/index.ts`, 617 LOC), Go (`vpe-go/vpe/`, ~778 LOC), and Rust (`vpe-rust/src/`, ~929 LOC) ports exist and each ships its own test suite (TS 114 cases, Go 39 test funcs, Rust 33 `#[test]`). All three expose API parity with the Python reference: `generateKeyPair`, `vpeSign`/`vpeVerify` (Ed25519), `vpeSignHmac`/`vpeVerifyHmac`, and canonical-JSON serialization. **Not yet published** to npm/crates.io/Go module registry — `npm install seal-vpe`, `cargo add vpe-rust`, `go get github.com/seal/vpe-go/vpe` will 404. **Shared cross-language test-vector fixture now committed (P8.5a, was previously a gap):** `tests/vectors/vpe_vectors.json` (22 vectors, valid + tampered, Ed25519 + HMAC) is generated from the Python reference by `tests/generate_vectors.py` and consumed by an automated interop test in **all four** languages — `tests/test_interop_vectors.py`, `vpe-ts/tests/interop_vectors.test.ts`, `vpe-go/vpe/interop_vectors_test.go`, `vpe-rust/tests/interop_vectors_test.rs` — each resolving the *same* repo-root fixture path. Byte-for-byte cross-language verification is now exercised by running tests, not just asserted by spec. (Caveat: this doc-sync could **not** re-execute the four test runners — the sandbox blocks `pytest`/`go test`/`jest`/`cargo test`; "passing" rests on commit history, where `t_253e5d8a`/`e50ce42`/`f575146` specifically fixed 4 TTL-expiry failures by bumping vector TTLs to 31536000s, not on a re-run during this sync.) See the Phase 8 section below.
203|
204|---
205|
206|## Phase 5 — Performance & Production Hardening ✅ Implemented
207|
208|> Persistent SQLite stores (`store.py`), key lifecycle + rotation (`key_manager.py`/`key_store.py`/`rotator.py`), HMAC path (`core.vpe_*_hmac`), and benchmarks all landed and tested.
209|
210|**Goal:** Make VPE fast enough for real-time use and robust enough for production deployment.
211|
212|### Subtasks
213|
214|| ID | Task | Acceptance Criteria |
215||----|------|--------------------|
216|| P5.1 | VPE verification benchmark | Measure overhead: `vpe_verify()` latency for envelopes of 1KB, 10KB, 100KB. Target < 5ms for 1KB, < 20ms for 100KB. Report breakdown (parsing, signature verify, scope check, nonce check, expiry check). |
217|| P5.2 | Persistent nonce/counter store | SQLite-backed `NonceStore` and `CounterStore`. Survive restarts. Automatic cleanup of expired nonces (>TTL). Thread-safe. Path: `~/.seal/store.db`. |
218|| P5.3 | Envelope size optimization | Canonical JSON without unnecessary whitespace. Optional field stripping (omit empty scope, omit default version). Benchmark size reduction vs. parse time. |
219|| P5.4 | HMAC-SHA256 alternative | For contexts where Ed25519 is overkill (internal trust, short-lived prompts). HMAC path: `vpe_sign_hmac()`, `vpe_verify_hmac()`. No key generation needed — shared secret. Document trade-offs: faster but no non-repudiation. |
220|| P5.5 | Key lifecycle management | Key generation → active → expiring → retired → revoked. Automatic rotation (generate new key N days before expiry). Graceful: old keys still verify signed envelopes, new envelopes use new key. CLI: `seal key rotate`, `seal key list`, `seal key revoke`. |
221|
222|### Performance Targets
223|```
224|Metric                Current      Target
225|vpe_verify(1KB)       ~2ms         <5ms (benchmark first)
226|vpe_verify(100KB)     ~15ms        <20ms
227|Envelope overhead     ~500B        <300B (with optional stripping)
228|Nonce check           in-memory    SQLite, <1ms
229|```
230|
231|---
232|
233|## Phase 6 — Hermes Production Deployment 🟡 Partial
234|
235|> Middleware, graceful degradation, Division audit trail (`division_audit.py`), and rollback (`rollback.py`) are built and tested. Live production wiring into a running Hermes/Division instance is deployment-dependent, not a code gap.
236|
237|**Goal:** VPE middleware running in production, protecting real Hermes tool calls.
238|
239|### Subtasks
240|
241|| ID | Task | Acceptance Criteria |
242||----|------|--------------------|
243|| P6.1 | Wire VPE into Hermes config | VPE middleware registered as optional plugin in Hermes `config.yaml`. Enabled/disabled via config toggle. No Hermes core modifications needed — MCP middleware layer only. |
244|| P6.2 | End-to-end test with real tools | Full chain: prompt → VPE sign → Hermes receives → VPE verify → scope check → EPD scan → tool call → response → VPE sign response. Test with `read_file`, `terminal`, `web_search`. |
245|| P6.3 | Graceful degradation | Unsigned prompts still work: logged as "unverified" with warning. Expired envelopes: logged, prompt still executed (configurable strict/lenient mode). Invalid signatures: rejected with clear error. |
246|| P6.4 | Division audit trail | Every VPE verification result stored in Division memory as episode: envelope hash, issuer, result (valid/invalid/expired), timestamp. Queryable: "show me all rejected prompts in the last hour." Hardened (L-010, `t_3035a8b3`): audit hashing no longer swallows all exceptions — canonicalization failure now logs a warning, marks the record `hash_computation_failed`, and emits a `degraded:`-prefixed identifier instead of a hash silently aliased to the nonce. The degraded fallback is retained-and-flagged, not removed; its failure branch is not yet covered by a test. Further hardened in `division_vpe_audit.py` (L-006/L-007, `t_55865f62`/`t_373d679c`): canonicalization fallback in `record_from_result` logs warning + prefixed degraded hash; cross-reference append logs warning instead of bare `except:pass`. |
247|| P6.5 | Rollback procedure | Disable VPE middleware with single config toggle. Script to roll back all VPE-related changes to Hermes config. No data loss on rollback — audit trail preserved. Hardened (L-006, `t_9da24d09`): `~/.seal` and `~/.hermes` paths are resolved lazily at call time (`_resolve_seal_home()`/`_resolve_hermes_home()`) instead of hardcoded `Path.home()` constants at import time, with `SEAL_HOME`/`HERMES_HOME` env overrides for testability and non-default homes. Further hardened (t_226c651b): the audit-log line count in `_archive_audit` and the status report now runs inside a `with open(...)` block (closes the descriptor even on error) and logs a warning with `exc_info=True` on read failure instead of silently swallowing it (`count = 0` fallback). |
248|
249|### Middleware Flow
250|```
251|Incoming prompt (raw or VPE-enveloped)
252|  → Detect: is this a VPE envelope or raw text?
253|  → If enveloped: vpe_verify() → if invalid: log + reject (strict) or log + warn (lenient)
254|  → If enveloped + valid: extract prompt + scope → pass to Hermes
255|  → If raw: log as unverified → pass to Hermes (with warning)
256|  → EPD scan on extracted prompt (always, regardless of envelope)
257|  → On response: optionally sign response envelope
258|```
259|
260|---
261|
262|## Phase 7 — Adversarial Testing ✅ Implemented
263|
264|> Mutation fuzzer (`epd/fuzzer.py`, `seal fuzz`), cryptographic-bypass + scope-escalation suites (`test_crypto_bypass.py`, 54 tests), and the P7.4 LLM-bypass finding (→ `llm_scan_all`) are done. The **T11 Unicode-smuggling** defense is the latest adversarial hardening (see [Threat Model](docs/threat-model.md)). The fuzzer's mutation-strategy and composite-mutation loops were also de-silenced (t_ed914b66 / t_0b226fe3): a strategy that raises now emits a `logger.warning` naming the strategy + template before continuing, rather than discarding the failure — so a broken strategy is visible instead of quietly shrinking the corpus.
265|
266|**Goal:** Break VPE before someone else does.
267|
268|### Subtasks
269|
270|| ID | Task | Acceptance Criteria |
271||----|------|--------------------|
272|| P7.1 | EPD pattern mutation fuzzing | Generate 1000+ mutations of known injection patterns (character insertion, deletion, substitution, encoding variations). Measure catch rate. Target: >95% on known patterns, >85% on novel mutations. |
273|| P7.2 | VPE cryptographic bypass attempts | Test: signature replay (reuse signature from different envelope), key confusion (substitute different key), malleability (reorder JSON fields), algorithm confusion (force HMAC path when Ed25519 expected). |
274|| P7.3 | Scope escalation attempts | Test: modify scope after signing, grant additional tools, extend TTL, change audience/issuer. Verify all scope modifications cause verification failure. |
275||| P7.4 | LLM-based adversarial generation | Use an LLM to generate novel injection prompts designed to bypass EPD patterns. Feed output back into EPD pattern development. **Result: 71/73 prompts (97.3%) bypassed regex — regex alone cannot catch semantic attacks. Solution: ``llm_scan_all`` config option + LLM classifier.** |
276|| P7.5 | Third-party audit prep | Document attack surface, threat model, known limitations. Create security audit checklist. Reference comparable systems (JWT, PASETO, Sigstore) for comparison. |
277|
278|### Test Metrics
279|```
280||EPD catch rate          Target      Actual (P7.4)
281||Known patterns          >95%        ~91% (regex)
282||Mutations               >85%        N/A (P7.1)
283||LLM-generated novel     >70% (stretch)  0% (regex alone, before llm_scan_all)
284|VPE bypass rate         0% (no cryptographic bypasses)
285|```
286|
287|---
288|
289|## Phase 8 — Standards & Community 🟡 Partial
290|
291|> Proposals drafted (`proposals/`: OWASP, MCP extension, SEP), docs site + CI + PyPI packaging **config** in place (`pyproject.toml` + `publish.yml`), CFP drafts written (`seal-community/`). **Shipped since (P8.5a):** cross-language ports — TS/Go/Rust — implemented in-repo with per-port test suites, **plus a shared cross-language test-vector fixture** (`tests/vectors/vpe_vectors.json`, 22 vectors) with an automated interop test in all four languages (commit `f7c2af4`; TTL fix `e50ce42`/`f575146`). **Shipped since (P8.3b, `t_a40992b1`):** the open-source repo is **pushed to GitHub** at `github.com/rezearcher/seal`. **Attempted-and-failed (P8.3b-2, verified live 2026-07-01):** a GitHub Release `v0.1.0` was published 2026-06-28 and **did** trigger `publish.yml`, but the run **failed at the PyPI upload step** — `seal-vpe` is **still 404 on PyPI**. **External-dependent / NOT done:** a *successful* PyPI publish of `seal-vpe` (a 2026-07-05 board task claims this is done, but it is **unverified** — no local evidence, live registry check was permission-blocked this sync; see header note), registry publishing of the ports, and actual OWASP/MCP acceptance.
292|
293|**Goal:** VPE becomes an industry reference — not just a local tool.
294|
295|### Subtasks
296|
297|| ID | Task | Acceptance Criteria |
298||----|------|--------------------|
299|| P8.1 | Submit OWASP proposal | PR or submission to OWASP Agentic Security Top 10 repository. New control category: "Prompt Authentication & Cryptographic Verification" with VPE as reference implementation. |
300|| P8.2 | Draft MCP spec extension | Formal MCP spec extension proposal. Define: `vpe` field in MCP messages, key exchange mechanism, verification error codes. Submit as PR to MCP spec repo or IETF draft. |
301|| P8.3 (🟡 GitHub DONE / PyPI FAILED — P8.3b + P8.3b-2, `t_a40992b1`) | Open source release | Clean GitHub repo: README, LICENSE, CONTRIBUTING, issue templates, CI pipeline (GitHub Actions for tests + benchmarks). PyPI package: `pip install seal-vpe`. **Status (verified live 2026-07-01 — network reachable):** repo is **live on GitHub** (`github.com/rezearcher/seal`) with README/LICENSE/CONTRIBUTING/CI all present. **PyPI publish ATTEMPTED and FAILED, `seal-vpe` still 404.** The `P8.3b-2` publish task did the trigger side: a **GitHub Release `v0.1.0` was published 2026-06-28** (target `master`), which fired `publish.yml` run `28317759671`. That run **failed** — `Build package` ✅ but `Publish to PyPI` upload ❌ (most-likely PyPI trusted-publishing / pending-publisher not configured; unconfirmed). `https://pypi.org/pypi/seal-vpe/json` → **404 (live 2026-07-01)**; `pip install seal-vpe` fails today. **Publish-prep config landed** (`t_0c0fff25`/`d97ea7c`, reviewed `t_dd8f649c`; authors fix `a475697`/`t_d3c9664e`): repo URLs, dist name, and authors fixed. **Gap to close:** configure the PyPI trusted publisher (pending-publisher) for `seal-vpe`, then re-run the failed `publish.yml` (re-publish the Release or `gh workflow run`) — or a manual `uv build && uv publish` — and re-verify PyPI returns 200. **2026-07-05 UPDATE:** a board task titled "Publish seal-vpe to PyPI (complete what `t_0c0fff25` left undone)" was marked complete, but this doc-sync could **not verify it** — no local-code change since the last sync (`dist/` and `publish.yml` untouched, version still `0.1.0`) and the live PyPI check was permission-blocked this session. Treat as an **unverified-gap**: the closing step (live PyPI 200) is still unconfirmed. |
302|| P8.4 | Documentation site | Hosted docs (GitHub Pages or similar): protocol spec, API reference, integration guide, CLI reference, threat model. Quickstart: "Add VPE to your agent in 5 minutes." |
303|| P8.5 | Reference implementations (**🟡 IMPLEMENTED IN-REPO + INTEROP-WIRED, NOT PUBLISHED** — P8.5a) | TS/Go/Rust ports built and committed (`vpe-ts/`, `vpe-go/`, `vpe-rust/`) with API parity (`vpeSign`/`vpeVerify` Ed25519, `vpeSignHmac`/`vpeVerifyHmac`, canonical JSON) and per-port test suites (TS 114, Go 39, Rust 33). Python remains the canonical spec. **Now met:** the "same test vector suite (cross-language verification)" acceptance criterion — `tests/vectors/vpe_vectors.json` (22 vectors generated from the Python reference via `tests/generate_vectors.py`) is consumed by an automated interop test in all four languages, each resolving the same repo-root fixture (verified by path inspection this sync). **Still open:** packages unpublished, so `npm install seal-vpe`, `go get github.com/seal/vpe-go/vpe`, and `cargo add vpe-rust` still 404. Interop/per-port pass-counts were **not independently re-run** during this doc sync (sandbox blocks pytest/go/jest/cargo); pass-status rests on commit history, including `t_253e5d8a` which fixed 4 TTL-expiry interop failures. |
304|| P8.6 | Community engagement | Blog post: "Why your AI agent needs cryptographic prompt verification." Conference talk CFP submissions (AI security conferences, OWASP events, Rust/NYC, etc.). Discussion with Hermes upstream for native support. |
305|
306|### Standards Timeline
307|```
308|Month 1: OWASP proposal submission + first reference port (TypeScript)
309|Month 2: MCP spec extension draft + Go port
310|Month 3: Rust port + CI + documentation site
311|Month 4: Conference submissions + upstream discussions
312|Month 6: v1.0 release candidate
313|```
314|
315|---
316|
317|## Phase 9 — Advanced Features ✅ Implemented (core)
318|
319|> Hierarchical issuer chains (`core.verify_cert_chain`, P9.1), key expiry/rotation (P9.2), multi-signature envelopes (`core.vpe_sign_multi`, P9.3), hardware signing (`hardware.py`, P9.4), and federation (`federation.py`, P9.5) are all built and tested. Trust-anchor discovery via DNS/DID remains the thinnest area.
320|
321|**Goal:** Extend VPE beyond the reference implementation into a full prompt security framework.
322|
323|### Subtasks
324|
325|| ID | Task | Acceptance Criteria |
326||----|------|--------------------|
327|| P9.1 | Hierarchical keys (issuer chains) | Key hierarchy: root CA → intermediate → signing key. Envelope includes cert chain. Verification walks the chain. Enables: team signing, delegation, revocation without re-keying all agents. |
328|| P9.2 | Time-based key expiry | Keys have `not_before` and `not_after` timestamps. Automatic rotation daemon. Integration with P5.5 key lifecycle. |
329|| P9.3 | Multi-signature envelopes | Requires N-of-M signatures before execution. Use case: "two of three team leads must approve this prompt." `vpe_sign` adds signature to existing envelope. `vpe_verify` checks threshold. |
330|| P9.4 | Hardware key support | YubiKey (PIV/OpenPGP), TPM, or macOS Secure Enclave for private key storage. Signing operation moves to hardware. Private key never leaves the device. |
331|| P9.5 | VPE federation (cross-agent trust) | Agent A can sign a prompt for Agent B if they share a trust anchor. Trust anchors are pre-shared or discovered via DNS/DID. Cross-agent audit trail. |
332|
333|### Architecture (Hierarchical)
334|```
335|Root Key (offline, in vault)
336|  └── Issuer Key ("team:security")
337|       ├── Signing Key ("agent:hermes-prod")
338|       │    └── VPE envelopes for Hermes 1
339|       ├── Signing Key ("agent:hermes-staging")
340|       │    └── VPE envelopes for Hermes 2
341|       └── Backup Key (cold storage)
342|```
343|
344|---
345|
346|## Phase 10 — End State: Prompt Security Standard ⬜ External
347|
348|> Adoption milestone, not a code deliverable — gated on outside acceptance (OWASP/MCP) or a 6-month production bake. Nothing to build here.
349|
350|**Goal:** VPE is adopted beyond this project — referenced in OWASP, MCP, and used by other agent frameworks.
351|
352|### Capabilities
353|- **Any Hermes agent** can verify prompt provenance cryptographically
354|- **Division memory** has signed episodes — tamper-evident history
355|- **EPD scanner** catches 95%+ of injection attempts before they reach the LLM
356|- **Secrets Broker** keeps credentials out of model context entirely
357|- **Multiple trust models**: HMAC (internal), Ed25519 (public), multi-sig (high-security)
358|- **Cross-framework**: TypeScript/Go/Rust ports exist with API parity to the Python reference (P8.5a), and interoperability is now exercised by a shared canonical test-vector fixture (`tests/vectors/vpe_vectors.json`, 22 vectors) with an automated interop test in all four languages. *Caveat: the test runners could not be re-executed during the latest doc sync (sandboxed); pass-status rests on commit history — see Known Limitations.*
359|
360|### When to Stop
361|Seal is "done" when:
362|- VPE is referenced in OWASP Agentic Security Top 10 or MCP spec, OR
363|- It's been running in production for 6 months with zero VPE bypasses, OR
364|- You decide prompt-level crypto isn't the right approach and pivot
365|
366|### Shutdown states
367|- **Paused:** Middleware disabled, CLI tools still work, audit data preserved
368|- **Archived:** Integrations removed, spec and proposals remain as reference
369|- **Open-sourced:** Project transferred to community ownership
370|