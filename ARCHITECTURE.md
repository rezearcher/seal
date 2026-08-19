# Seal — Verified Prompt Envelope Protocol & AI Agent Security

> **Status:** Phases 1–9 core capabilities **implemented and tested** — VPE Core (Ed25519 + HMAC + multi-sig + hierarchical cert chains + hardware signing), EPD Scanner (regex + LLM + Unicode-smuggling defense), Secrets Broker, persistent stores, full key lifecycle + rotation daemon, Hermes/Division integration, rollback, adversarial fuzzer, and benchmarks. **P9.5 federation shipped: Python-native DNS resolver (P9.5a), DID document resolution via HTTPS (P9.5b), trust anchor exchange protocol (P9.5c), and integration tests for DNS-discovered trust anchors (P9.5d). `test_federation.py` grew to 142 tests / 2264 lines. Total suite count (live `uv run pytest -q`, 2026-08-14): **1141 passed, 1 skipped at 81.20% coverage** — supersedes the earlier 798-pass count, which rested on commit history (see the 2026-08-14 sync entry).**
> **Remaining:** external adoption only — P8 (cross-language port **publishing** + OWASP/MCP standardization) and P10 (production-bake). Cross-language ports (TS/Go/Rust) are **implemented in-repo with their own test suites** (`vpe-ts/`, `vpe-go/`, `vpe-rust/`, P8.5a, commits `bb9896c` + later) AND now share a **single canonical cross-language test-vector fixture** (`tests/vectors/vpe_vectors.json`, 22 vectors, generated from the Python reference) consumed by an automated interop test in all four languages (commits `f7c2af4` fixture+tests, `e50ce42`/`f575146` TTL fix). The ports are **not yet published to package registries** (Go now published — see the 2026-08-17 sync entry). See per-phase status tags below.
> **2026-08-18 sync — `t_ab5bd481` (cleanup) "Remove dead `division_audit.py` module" (VERIFIED via exhaustive guardrails):** `seal/division_audit.py` was an HTTP-transport shim to Division (port 7070) superseded by the live MCP-based `seal/integration/division_vpe_audit.py` (uses injected callable for writes, no HTTP client). Exhaustive verification: (1) **Zero importers repo-wide** — `rg DivisionAuditTrail|from seal.division_audit|import division_audit --glob '!seal/division_audit.py'` returned no hits (exit=1). (2) **No env vars in live code** — `DIVISION_BASE_URL` consumed ONLY by the dead module; the live module reads no env vars and does no URL-driven I/O. (3) **Test file imports live module** — `tests/test_division_audit.py:11-12` imports `seal.audit`/`seal.vpe` (the live audit layer), not the dead HTTP client. (4) **No pyproject/CI/docs references** (excluding historical ARCHITECTURE.md sync entries, now marked as superseded below). **Action: deleted `seal/division_audit.py`, renamed `tests/test_division_audit.py` → `tests/test_division_vpe_audit.py` (relocated, not deleted — it tests the live module), updated `docs/architecture.md:80` to list only `seal/integration/division_vpe_audit.py`.** *(Verified by filesystem confirmation after deletion and source-read of guardrails.)*
> **2026-08-17 sync — `t_d86f3b1c` (Go module path) + `t_d1783048` (`_resolve_home` collapse) + `t_d09cafba` (HsmProvider hoist) (VERIFIED in code + live proxy):** three commits since `09d2496` are now reflected in the What's Built table and the P8.5a/P8.5 publish-status prose. (1) **`t_d86f3b1c` — Go module path corrected (commit `f6350f0`, tag `vpe-go/v0.1.0`):** `vpe-go/go.mod` now declares `module github.com/rezearcher/seal/vpe-go` (was the dead `github.com/seal/vpe-go`). **Live-verified this sync:** `https://proxy.golang.org/github.com/rezearcher/seal/vpe-go/@latest` → **200** (`{"Version":"v0.1.0","Origin":{"Ref":"refs/tags/vpe-go/v0.1.0","Hash":"f6350f03..."}}`), so `go get github.com/rezearcher/seal/vpe-go/vpe` now resolves; the stale path returns **404**. Publish status updated: **Go = published**; npm/crates.io = still unpublished. (2) **`t_d1783048` — rollback path-resolution collapse (commit `034e930`):** `_resolve_seal_home()`/`_resolve_hermes_home()` collapsed into a shared `_resolve_home(env_var, default_dir)` (`rollback.py:35`); table row now names the shared helper and the LOC is corrected to the actual **503** (the old 508 figure predated the refactor — the file was 499 LOC at `09d2496`, +4 net from the collapse). (3) **`t_d09cafba` — HsmProvider hoist (commit `5da549b`):** `get_public_key`/`list_keys`/`delete_key` hoisted into the `HsmProvider` ABC base (`hardware.py:136`/`:141`/`:145`), 4 per-subclass overrides deleted; hardware.py row LOC corrected **880 → 852**. *(No test re-run this sync — sandbox blocks pytest; all claims verified by source read + live network probe.)*
>
> **2026-08-16 sync — `t_7d597f41` (L-004) + `t_c010d85c` (beautifier #1) (VERIFIED in code):** two small hardening/refactor tasks confirmed at HEAD `4ad7a63`. (1) **`t_7d597f41` — `key_manager.py` no longer swallows `chmod` `OSError` silently:** all **three** `chmod` sites now `log.warning` on failure instead of a bare `pass` — `_ensure_seal_dir()` (`key_manager.py:116–118`, seal-dir 0700), `_load_or_create_master_key()` (`:139–141`, keyfile 0600), and `KeyManager.__init__` (`:294–296`, db-parent 0700). Module logger is `log = logging.getLogger(__name__)` (`:104`). (The `except OSError: continue` at `:153` is in `_read_machine_id` — a read path, not a chmod site — and is intentionally quiet; the L-004 scope was the three chmod swallows, all closed.) *(Confirmed by source read; pytest sandbox-blocked, not re-run.)* (2) **`t_c010d85c` — `_canonical_json_multi` delegates to `_canonical_json`:** `core.py:486–497` (commit `4ad7a63`) now derives the ordered envelope by round-tripping through `_canonical_json` (the shared 11-field canonicalizer in `_base.py`), then appends `threshold` immediately after (omitted when None), so default/omission semantics live in a single place. Previously it duplicated the field ordering. Pure refactor, no wire-format change. *(Confirmed by source read.)*
>
> **2026-08-14 sync #2 — `t_2b25ceff` (final content) + `t_04f35366` (doc re-sync) (VERIFIED in code):** the prior entry summarized `t_2b25ceff` as "fixed 2 failing tests + raised gate 64→80", but its final HEAD commit `6660ce7` ("bind wrapper value to signed envelope content") shipped a **security fix that entry did not record.** In `seal/integration/division_vpe_signer.py:440–453` (confirmed by read), the signed-wrapper verify path now **binds the stored `value` to the signed envelope content**: it re-serializes `wrapper["value"]` (`json.dumps(..., sort_keys=True)`) and compares it against `json.loads(envelope["prompt"])["value"]`; on mismatch it returns `VPEResult(False, "signed wrapper value does not match envelope content")` and records a failed audit. This closes a tamper gap where the outer signature matched but the `value` field had been swapped after signing. `tests/test_division_vpe_signer_nonce.py` has **20 `def test_` functions** (confirmed by count). `t_04f35366` is the doc-re-sync task itself (commit `936915e`, current HEAD) — no code change; it restored the coverage-gate/test-count prose recorded in the sync #1 entry below. **Not re-run this sync:** `pytest --cov` is sandbox-blocked, so the 1141-pass / 81.20% figures still rest on the sync #1 live run + commit history, not a fresh probe here.
>
> **2026-08-14 sync — `t_3569cb04` / `t_7bb5b728` / `t_2b25ceff` (VERIFIED in code + live suite):** three done tasks recorded, coverage gate restored, test count updated. (1) **`t_3569cb04` — unit tests for `seal/integration/hermes_skills_guard.py` (commit `968dc18`):** new `tests/test_hermes_skills_guard.py` (43 tests) covers the full VPEGuardChain pipeline, raising module coverage **0% → 100%** (≥80% required). (2) **`t_7bb5b728` — unit tests for `seal/integration/division_vpe_signer.py` (commit `67c49d3`):** new `tests/test_division_vpe_signer.py` (32 tests) raises module coverage to **100% (160/160 stmts)**. (3) **`t_2b25ceff` — fixed 2 failing tests in `test_division_vpe_signer_nonce.py` (commit `2cb1a01`) + raised coverage gate 64→80 (commit `2cb1a01`; final HEAD `6660ce7`):** `pyproject.toml:77` now has `fail_under = 80` (confirmed by read this sync), reversing the earlier `8cc5418` (t_396124b9) drop. **Live suite this sync:** `uv run pytest -q` → **1141 passed, 1 skipped at 81.20% coverage** — the stale 798-pass figure (which rested on commit history, see the CI note below) is superseded. What's Built table updated: `hermes_skills_guard.py` → `test_hermes_skills_guard.py` (43), `division_vpe_signer.py` → `test_division_vpe_signer.py` (32).
>
> **2026-08-12 sync — `t_ff898242` (C01) "Write unit tests for `seal/rotator.py` + `seal/vpe.py`" (VERIFIED in code, commit `4428c00`):** both new test files physically exist and target the named modules. **`tests/test_rotator.py` (134 LOC, 7 `def test_` functions)** exercises the rotation-daemon CLI entry point — it imports `seal.rotator` directly, drives `main()` via monkeypatched `sys.argv` with a mocked rotation daemon, and covers the one-shot/persistent argv paths plus `runpy` module-execution. **`tests/test_vpe.py` (567 LOC, 55 `def test_` functions)** covers `seal.vpe`: `VPEResult`, both Ed25519 backends (the **nacl-preferred path via a fake `nacl` package injected into `sys.modules` and backed by `cryptography`** — `_install_fake_nacl`, `test_vpe.py:25`), canonical serialization, the full sign/verify lifecycle, every `vpe_verify` check, and the key-file helpers. The Division memory note (`seal-rotator-vpe-unit-tests-98pct-coverage`) reports **98.28% coverage (232/236 stmts)** on the two modules and a full suite of **1049 passed, 1 skipped, ruff clean** — this **pass/coverage status rests on the commit-history claim, not a fresh run:** `pytest --cov` is execution-blocked in this sandbox, so only the file existence, LOC, test counts, and fake-nacl wiring are independently confirmed here. The stale test-status columns in the [What's Built] table are corrected in this sync: `seal/rotator.py` → `test_rotator.py`, `seal/vpe.py` → `test_vpe.py` (previously mislabeled `test_core.py`).
>
> **2026-08-11 sync — `t_38371b23` (L-071) "Narrow broad `except Exception` in `federation.py` `vpe_federated_sign()`" (VERIFIED in code, commit `2cd9e57`):** the `try` wrapping the inner `vpe_sign()` call in `vpe_federated_sign()` (`federation.py:925`) now catches the **narrow `(ValueError, TypeError, OverflowError)`** (`federation.py:936`) rather than a broad `except Exception`. On catch it still returns `FederatedSignResult(error=f"{type(exc).__name__}: {str(exc)}")`. Previously the broad catch-all would have converted *any* exception — including programming errors and unexpected runtime failures — into a soft error result; narrowing means only the signer's expected value/type/overflow failures are absorbed while genuinely unexpected exceptions now propagate. (The nonce-extraction `try` immediately below at `:942–946` was already narrow: `(ValueError, _json.JSONDecodeError)`.) *(Not probed live: interpreter execution is sandbox-blocked; confirmed by source read of `federation.py:925–937`.)*
>
> **2026-08-09 sync — `t_84db57ec` "Extract shared helper — `division_audit.py` `_post`/`_get` duplicate error handling" (VERIFIED in code, commit `57ce04e`):** the two client methods no longer duplicate the urllib request/error-handling block. A single **`_request(method, path, body=None, params=None)` handler (`division_audit.py:267`)** now builds the URL (query-string encoding for GET params), JSON-encodes the body + sets `Content-Type` only when a body is present, issues the `urllib.request.urlopen` call under `_REQUEST_TIMEOUT`, and owns the shared `except` ladder — `urllib.error.HTTPError` (logs code + method + path + truncated 200-char response, returns `None`) and `(urllib.error.URLError, OSError, ValueError)` (logs connection error, returns `None`). **`_post` (`:305`) and `_get` (`:309`) are now 1-line delegators** — `self._request("POST", path, body=body)` / `self._request("GET", path, params=params)` — so the error handling lives in exactly one place. Pure structural refactor, no behavior change. `division_audit.py` is now **787 LOC** (line 197 table below updated from the stale 722). *(Not probed live: interpreter execution is sandbox-blocked; confirmed by filesystem + source read.)*
>
> **2026-08-06 sync — 5 completed tasks verified in code (`t_047da596`, `t_9a7d3d4d`, `t_b2bf180a`, `t_595b2bcc`, `t_95eae977`); PyPI attempt 4 (`t_ee2d04bc`) still an open gap:**
> - **`t_047da596` (B-015) — persistence layer extracted from `seal/federation.py` (VERIFIED in code):** new module **`seal/federation_store.py` (439 LOC)** now holds the trust-anchor registry (`TrustAnchorRegistry`), trust-bundle serialization (`export_trust_bundle`/`import_trust_bundle`/`_canonical_trust_bundle`), the cross-agent audit log (`FederationAuditLog`), and `FederationError`. `federation_store.py:1–8` documents it as a **pure structural refactor** ("Extracted verbatim … no behavior change"). `seal/federation.py:25–38` imports these names from `federation_store` and **re-exports them** (`export_trust_bundle as export_trust_bundle`, etc.) so existing `from seal.federation import …` call sites keep working. `federation.py` dropped **1467 → 1067 LOC**; DNS/DID discovery + federated sign/verify stay in `federation.py`. (Not probed live: interpreter execution is sandbox-blocked; confirmed by filesystem + import-graph read.)
> - **`t_9a7d3d4d` (A6) — JWK decode-failure debug logging (VERIFIED in code):** the `did:web`/`did:ion` verification-method parser at `federation.py:667–691` now wraps the `publicKeyJwk` base64url-decode path in `try/except Exception as exc` and emits `logger.debug("JWK key-format decode failed (vm_type=%s, crv=%s): %s", …)` (`federation.py:685`) before `continue`, instead of silently swallowing the parse failure. The module already had a `logging.getLogger(__name__)` logger.
> - **`t_b2bf180a` (A4/A5) — tightened crypto exception handling in `seal/hardware.py` (VERIFIED in code):** the availability/`which`-probe subprocess sites now catch the **narrow `(subprocess.SubprocessError, FileNotFoundError)`** (e.g. `hardware.py:182`, `:325`) and the `generate`/`sign` operation sites split into distinct `except subprocess.CalledProcessError` **and** `except subprocess.TimeoutExpired` handlers (e.g. `:213/:220`, `:268/:275`) rather than broad catch-alls. LOC 884 → 880. This refines the L-011 note below.
> - **`t_595b2bcc` — `DIVISION_BASE_URL` local-URL validation (VERIFIED in code):** `seal/division_audit.py:70` adds `_validate_division_url()`, called at import time (`division_audit.py:115`) on `os.getenv("DIVISION_BASE_URL", "http://localhost:7070")`. It short-circuits `localhost`/`127.0.0.1`/`::1`, resolves any other hostname, and **falls back to `http://localhost:7070` with a `logger.warning`** if the host is unresolvable or resolves to a non-private/public IP (`_is_private_ip` checks loopback/link-local/RFC-1918) — closing an SSRF/exfil vector where an attacker-controlled env var could redirect audit writes to a public endpoint.
> - **`t_95eae977` (A7) — `pytest.raises` in `test_crypto_bypass` key-length/empty-key cases (VERIFIED in code):** `tests/test_crypto_bypass.py` now uses `with pytest.raises(Exception):` at lines 218, 223, 251, 256 for the key-length and empty-key rejection assertions instead of bare try/except or unchecked calls.
> - **`t_8d7f0402` (B-014) — 5 ruff UP-codes fixed in `seal/epd/write_gate.py`:** module is present (257 LOC) and the G03 write-gate below is unchanged in behavior; the fix was lint-only (UP modernization codes).
> - **`t_ee2d04bc` — "Publish seal-vpe to PyPI (attempt 4)" is CLOSED on the board but STILL AN OPEN GAP (unverified):** the title is a *claim*, not evidence. `pyproject.toml` version is still `0.1.0` and this sync **could not reach PyPI** — `curl https://pypi.org/pypi/seal-vpe/json` was permission-blocked in the sandbox, so no HTTP 200/404 was observed. Last authoritative live check (2026-07-01) returned **404**. Do **not** treat `seal-vpe` as on PyPI until a live `200`/`pip install seal-vpe` is confirmed. See the P8.3b block and the 2026-07-05 note below for prior failed-publish history.
>
> **2026-08-04 sync — `t_93b06e63` "Re-sync ARCHITECTURE.md: two residual CI gaps closed" (VERIFIED in code, commits `73a0701` + `0ff6a87`):** both residual gaps flagged in the 2026-07-28 sync (`t_f8f19e90`/`f33a635`, see entry below) are now **CLOSED in code**. (a) **docs.yml is now locked** — `73a0701` (2026-07-29, "fix: pin docs deps via locked optional-dependencies group") added a `docs` extra to `[project.optional-dependencies]` in `pyproject.toml` (mkdocs>=1.6.0, mkdocs-material>=9.5.0, mkdocstrings[python]>=0.26.0) and switched `docs.yml:37` to **`uv sync --locked --extra docs`**. (b) **the `--group dev` vs. extras mismatch is resolved** — `0ff6a87` (2026-07-31, "ci: migrate uv --group to --extra for PEP 621 extras") migrated all four workflows to PEP 621 extras and grew `uv.lock` by 504 lines to pin the docs toolchain (mkdocs `1.6.1` at `uv.lock:508`, plus mkdocs-autorefs, mkdocs-get-deps, mkdocstrings, etc.); `uv.lock:883` records `provides-extras = ["dev", "docs"]`. Current verified install lines (confirmed by read this sync): `lint.yml:33` / `test.yml:38` / `benchmark.yml:24` run **`uv sync --locked --extra dev`**; `docs.yml:37` runs **`uv sync --locked --extra docs`**. See the CI-health section below for the full closure record.
>
> **2026-07-29 sync — `t_7fd8f2ce` "Remove dead secrets_broker.py deprecation shim" (VERIFIED in code, commit `df14cce`):** `seal/secrets_broker.py` **no longer exists on disk** (`ls` → `No such file or directory`; only a stale `__pycache__/secrets_broker.cpython-312.pyc` remains, which is gitignored build residue, not a module source). A repo-wide `rg secrets_broker|SecretsBroker` finds **zero Python imports** of the removed module — the only surviving `secrets_broker` mentions are historical prose (`docs/handoffs/`, `tests/test_credential_store.py` docstring, this file). The live broker is `seal/broker.py` (`SecretsBroker`, `SecretsBrokerError`, `REDACTED`), re-exported from `seal/__init__.py:12`, tested by `tests/test_broker.py`; the credential store is `seal/credential_store.py`. Two proposal docs that still pointed callers at `seal/secrets_broker.py` were corrected in this sync (`proposals/mcp_signing_extension.md`, `proposals/SEP-vpe-signing-layer.mdx`). *(Not probed live: `python -c "import seal"` is execution-blocked in this sandbox — the removal is confirmed by filesystem + import-graph read, not by running the interpreter.)*
>
> **2026-07-28 sync — `t_f8f19e90` "Fix CI lint drift — lock workflows to uv.lock" (VERIFIED in code, commit `f33a635`):** three of the five workflows now install with **`uv sync --locked --group dev`** — `lint.yml:33`, `test.yml:38`, `benchmark.yml:24` (confirmed by read). `uv.lock` is committed (480 lines, `revision = 3`, `requires-python = ">=3.11"`, not in `.gitignore`) and **pins ruff at `0.15.16`** (`uv.lock:378–379`) alongside `pytest`/`pytest-cov`. `--locked` also makes CI **fail** rather than silently re-resolve if `uv.lock` drifts out of sync with `pyproject.toml`. This is what stops a fresh ruff release from turning a previously-green branch red with no repo change — the failure mode behind `cce96e4` (49-file format drift) and `463bef8` (7 auto-fix errors). `pyproject.toml` still declares only a floor (`ruff>=0.3.0`, line 37) — the *pin* lives in the lockfile, which is the intended design. **Two residual gaps this fix does NOT cover — see the CI section below:** (a) `docs.yml` is still unlocked/unpinned, (b) the `--group dev` vs. `[project.optional-dependencies]` mismatch is an unverified risk.
>
> **2026-07-27 (20:00 UTC) — foreman cycle #14 (78e817a). Suggestion agents: zero findings across all three (gap-analyzer, lie-detector, beautifier). Board: 107 done, 1 blocked (`t_ee2d04bc` — PyPI publish). Git status found 3 files with uncommitted tilde-expansion fixes (19+1 lines), committed at `4d9389d`. HEAD `4d9389d` (clean). Test suite: 798 passed, 1 skipped. Project remains in terminal stall — no agent-actionable work beyond what was committed.**
> - **`t_491ce859` (L-011) — YubiKey/HSM subprocess timeout + error handling shipped (VERIFIED in code, commit `b9c4735`):** `seal/hardware.py` grew **706 → 884 LOC**. It now `import logging` with a module logger, defines a structured **`HsmError`** exception (`hardware.py:65`), and wraps **all 13 `subprocess.run` sites** (13/13 now carry `timeout=` — 5 s for `which`/availability probes, 30 s for `generate`/`sign`) in `try/except` for both `CalledProcessError` and `TimeoutExpired`, raising `HsmError` with stderr detail (**20 `raise HsmError` sites**). Covers all three real providers — `YubiKeyPIVProvider`, `TPMProvider` (5 subprocess calls in `generate`), `SecureEnclaveProvider`; `SoftwareSimProvider` is pure-Python (no subprocess). Previously these were unguarded `subprocess.run(check=True)` calls that could raise opaque errors or hang forever. Commit message reports all 798 tests pass (pytest not re-run this sync — sandbox-blocked).
> - **`t_504a86a8` — 7 ruff lint errors auto-fixed (VERIFIED in code, commit `463bef8`):** removed the now-unused `resolve_via_did_document` imports in `tests/test_federation.py`, fixed import ordering in `seal/cli.py` (`from seal.federation import TrustAnchorRegistry, vpe_federated_verify` — alphabetized). The **same commit also corrected `mkdocs.yml`** repo/site/social URLs `nousresearch/seal → rezearcher/seal` (the last stale `nousresearch` references in the docs config). Commit reports all 798 tests pass.
> - **`t_af6adb83` — "Fix CI - Deploy Docs: mkdocs build --strict failing" is CLOSED but UNVERIFIED (gap):** the board task title is a *claim*, not evidence. This sync found **no dedicated fix commit** for it — the only docs-touching change in the 24 h window is the repo-URL correction bundled into `463bef8` (above), which would not by itself resolve a `--strict` link/plugin failure. All 20 `nav:` targets in `mkdocs.yml` do exist on disk (checked), so the failure — if still present — would be from internal cross-links or the mkdocstrings plugin, neither of which could be checked because **`mkdocs build --strict` was permission-blocked this session** (same as prior syncs). Do **not** treat Deploy Docs as green until a live `mkdocs build --strict` (or an observed-green `docs.yml` run) is checked.
>
> **2026-07-14 sync — `t_fd51e037` closes the federation residual gap: `did:web` now fully wired through `vpe_federated_verify()` + CLI.** Verified in code (commit `c07c6cf`): (1) **`vpe_federated_verify()` (`federation.py:1362`) gained `did_web: str | None = None` parameter** and forwards `did_web=did_web` to `resolve_trust_anchor()` at `federation.py:1431` — the step-4 resolution path that the prior sync's residual gap identified as missing. (2) **New `seal federation verify` CLI subcommand** with `--did-web`, `--did-str`, `--dns-domain`, `--registry`, and `--issuer-override` flags (`cli.py:956–969`). `cmd_federation_verify()` calls `vpe_federated_verify()` forwarding all params (`cli.py:759–797`). (3) **New test `test_verify_with_did_web_forwarded`** in `test_federation.py` exercises full `did_web` plumbing with a mock DID document resolver — asserts `result["valid"] is True` and `result["source"] == "did_web"`. The author reports **all 798 tests pass, 1 skipped**. The earlier ⚠️ Residual gap note in the 2026-07-13 entry is now **closed** — `did:web` anchors are fully usable from the federated verify flow.
>
> **2026-07-13 sync — three hardening/refactor tasks shipped and verified in code:** (1) **`t_f5641b1f` — `did:web`/`did:ion` now wired into the central dispatcher.** `resolve_trust_anchor()` (`federation.py:1223`) gained a `did_web` parameter and now calls `resolve_via_did_document()` as dispatch step 4, returning `source="did_web"` on hit (`federation.py:1269–1273`, commit `8357442`). Dispatcher order is now **registry → DNS → did:key → did:web/did:ion**. This closes the *dispatcher* half of the gap. ~~The `vpe_federated_verify()` residual gap identified below was closed by `t_fd51e037` on 2026-07-14 (see next entry).~~ (2) **`t_c5341e7d` — shared envelope helpers extracted inside `core.py`.** `_build_envelope()` (`core.py:49`) is now the single builder shared by both the Ed25519 (`vpe_sign`) and HMAC-SHA256 (`vpe_sign_hmac`) signers, and `_validate_envelope_structure()` (`core.py:83`) runs the shared pre-verify structural checks for both verify paths (commit `9da0aaa`). (3) **`t_3f76b1e6` — silent `except` in `_extract_episode_id` fixed.** The bare `except (json.JSONDecodeError, TypeError, AttributeError): pass` at `division_vpe_audit.py:444` now emits a `logger.warning` naming the result type + truncated content (commit `35e3787`) — this was the last remaining silent-swallow gap called out in the L-006/L-007 note below. All three verified by reading the shipped code this sync; pytest remains execution-blocked in this sandbox so no live test run was performed.
>
> **2026-07-05 sync — new board task "Publish seal-vpe to PyPI (complete what `t_0c0fff25` left undone)" marked COMPLETE, but the publish is UNVERIFIED (unverified-gap):** The task title is a *claim*, not evidence. This sync found **no local-code change** consistent with a fresh publish since the last sync — `pyproject.toml` unchanged (Jul 1), the `dist/` artifacts unchanged (`seal_vpe-0.1.0-{whl,tar.gz}`, Jun 28), `publish.yml` unchanged, project version still `0.1.0`. A successful trusted-publish re-run leaves no local trace *either way*, so absence-of-change cannot confirm success — and the only authoritative check (the live PyPI registry) was **permission-blocked this session** (both `curl https://pypi.org/pypi/seal-vpe/json` and WebFetch were denied), so no HTTP 200/404 could be observed. **As of the last live check (prior sync, 2026-07-01) `seal-vpe` was 404 on PyPI.** Do NOT treat this task's completion as "seal-vpe is on PyPI" until someone confirms `https://pypi.org/pypi/seal-vpe/json` → 200 (or `pip install seal-vpe` succeeds). To close: confirm the PyPI trusted-publisher/pending-publisher is configured for `seal-vpe`, re-run/observe `publish.yml`, then re-verify the registry returns 200.
>
> **P8.3b — GitHub push DONE, PyPI publish ATTEMPTED-AND-FAILED, `seal-vpe` still NOT on PyPI (`t_a40992b1`; publish task `P8.3b-2`; publish-prep `t_0c0fff25`/`t_dd8f649c`):** The repo IS live on GitHub at `github.com/rezearcher/seal` (local HEAD now `7fd3462`). **New since last sync (verified live 2026-07-01 — network is NOT blocked this session):** a **GitHub Release `v0.1.0` now exists** (published 2026-06-28T09:22Z, target `master`), which **did** trigger `publish.yml` (`on: release: published`). The workflow run (`Publish to PyPI`, run `28317759671`, 2026-06-28T09:22:29Z) **completed with conclusion=failure**: the `Build package` step succeeded but the **`Publish to PyPI` upload step failed** (most-likely cause: PyPI trusted-publishing / pending-publisher not yet configured for the `seal-vpe` project — unconfirmed, upload step never authenticated). **Net result is unchanged for users:** `https://pypi.org/pypi/seal-vpe/json` → **404 (verified live 2026-07-01)**, so `pip install seal-vpe` still fails. So the prior doc claims "no GitHub Release exists" and "publish.yml has never fired" are now **both false** — a release exists and the workflow fired once and failed. (Note: the local `v0.1.0` git tag ref still points at `0b8233f`/2026-06-18, stale vs. the Release which targets `master`.) **Publish-prep code changes shipped (`t_0c0fff25`, commit `d97ea7c`, 2026-06-28; reviewed under `t_dd8f649c`):** the `[project.urls]` in `pyproject.toml` were corrected from `github.com/nousresearch/seal` to the real remote `github.com/rezearcher/seal`, and `seal/__init__.py` now resolves `__version__` via `version("seal-vpe")` (the correct dist name) instead of `version("seal")`. **Authors fixed (`t_d3c9664e`, commit `a475697`):** `pyproject.toml` `authors` (line 13) now reads `{name = "Rez Archer"}` — the earlier "still lists Nous Research" residual is closed. **CI-fix tasks landed 2026-07-01/02 (code-level verified, CI-green NOT re-run this sync):** the three red workflows — `Tests`, `Deploy Docs`, `Lint` — were each addressed by a dedicated fix commit: `8cc5418` (t_396124b9) lowered the coverage gate `fail_under` 80→**64** in `pyproject.toml` (confirmed at line 72); `9ea0de4` (t_c4cae88f) fixed the `mkdocs build --strict` link warnings (docs.yml still runs `--strict`, so the fix was correcting the broken doc links, not relaxing the gate); `f435f7b` (t_086580fb) resolved the 403 ruff lint errors — `[tool.ruff.lint]` now sets `select=["E","F","W","I","N","UP"]` with per-file-ignores (`"vpe-ts/*"=["E501","N802"]`, `"tests/*"=["N814"]`). **Caveat:** this sync could not execute `ruff check`, `mkdocs build`, or `pytest --cov` (probes permission-blocked), so the config/link fixes are confirmed by reading the files but a **green CI run is not independently verified** — see the CI gap note under Phase 8.
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
- **Division injection scanning gap**: closed by the write-time EPD gate (G03 — `seal/epd/write_gate.py`, see EPD table below)
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

> Authoritative inventory of modules that physically exist, with the test file that exercises each. **1141 tests collected** (1141 passed, 1 skipped, 81.20% coverage — live `uv run pytest -q` 2026-08-14, t_2b25ceff). Keep this table current when modules land — it is the anti-confusion anchor for the roadmap below.

### VPE Core — signing & verification (Phase 1, plus 5.4 / 9.1 / 9.3 / 9.4)
| Module | LOC | Provides | Tests |
||--------|-----|----------|-------|
|| `seal/_base.py` | 145 | **Shared VPE core, extracted 2026-07-10 (t_8154eafe, commits `c93ae6d`/`8c9b42a`).** Single source of truth for protocol constants (`VPE_VERSION`, `_ENVELOPE_FIELDS`, `HMAC_SIGNATURE_BYTES`), canonical serialization (`_canonical_json` — 11-field ordering, sorted scope keys, `cert_chain` omitted when None), field-stripping (`_strip_empty_fields`), nonce (`_make_nonce`), and cryptography-backed key helpers (`_load_private_key`/`_load_public_key`/`generate_key_pair`). Both `core.py` and `vpe.py` now import from here instead of holding divergent copies. | covered via `core.py`/`vpe.py` suites |
|| `seal/core.py` | 755 | `vpe_sign`/`vpe_verify` (Ed25519), `vpe_sign_hmac`/`vpe_verify_hmac` (HMAC-SHA256, P5.4), `vpe_sign_multi`/`vpe_verify_multi` (N-of-M multi-sig, P9.3), `verify_certificate`/`verify_cert_chain` (hierarchical issuer chains, P9.1), `vpe_sign_hardware`/`vpe_verify_hardware` (P9.4), scope/nonce/counter/TTL enforcement. **Imports shared constants + `_canonical_json` + key helpers from `seal/_base.py`** (t_8154eafe) and re-exports them for backward compatibility. **Intra-module dedup (t_c5341e7d, commit `9da0aaa`):** `_build_envelope()` (`core.py:49`) is the single envelope builder shared by the Ed25519 and HMAC signers; `_validate_envelope_structure()` (`core.py:83`) runs the shared 7-check structural pre-verify for both verify paths — replacing the two divergent inline copies. **Internal dedup (t_c5341e7d, `9da0aaa`):** `_build_envelope()` (line 49) is the single envelope builder used by both `vpe_sign` and `vpe_sign_hmac`; `_validate_envelope_structure()` (line 83) runs the shared pre-signature structural checks (JSON parse, dict type, version, signature presence, scope/nonce/counter/TTL types) for both `vpe_verify` and `vpe_verify_hmac`, returning `(envelope, precheck)`. **S-001 fix (t_75f3f059, `b4d05cc`):** `nonce_store.add()` moved to *after* Ed25519 signature verification so a bogus-signature envelope can no longer burn a valid nonce (see Security Notes). **Multi-sig canonicalization dedup (t_c010d85c, `4ad7a63`):** `_canonical_json_multi` (`core.py:486`) now delegates the 11 shared fields to `_canonical_json` and only appends `threshold`, instead of re-implementing field ordering. LOC dropped 1229→730 after dedup. | `test_core.py` (146), `test_crypto_bypass.py` (54) |
|| `seal/vpe.py` | 414 | Envelope dataclasses, multi-backend Ed25519 (NaCl or `cryptography`), `vpe_verify` (signature→replay→counter→scope ordering, replay check already after signature). **Imports `VPE_VERSION` + `_canonical_json` from `seal/_base.py`** (t_8154eafe) rather than a local copy; LOC dropped 589→414 after dedup. **t_03ea2d3a:** `SIGNED_FIELDS` aligned with core.py (`iat`, `cert_chain` → 11 fields); `issued_at`→`iat`; scope keys sorted for byte-for-byte canonical match. | `test_core.py` + `test_vpe.py` (t_ff898242, 55 tests) |
| `seal/cli.py` | 649 | 18-command CLI (see below) | e2e |

### EPD Scanner — injection detection (Phase 2, plus 7.1 / 7.4)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/epd/scanner.py` | 349 | Two-pass scan (regex ~91% + optional LLM). Normalization strips **all** Unicode format chars (Cf) + variation selectors; `_detect_hidden_unicode()` flags/decodes invisible **tag-block & variation-selector smuggling** (threat-model **T11**), runs unconditionally | `test_epd.py` (57) |
| `seal/epd/patterns.py` | 615 | Regex patterns: jailbreaks, role-switch, ignore-instructions, delimiter confusion, hidden markers, tool hallucination, homoglyph/leet | — |
| `seal/epd/llm_classifier.py` | 145 | LLM tiebreaker / `llm_scan_all` catch-all pass (independent model) | `test_epd.py` |
| `seal/epd/fuzzer.py` | 960 | Pattern-mutation fuzzer, `seal fuzz` (P7.1 adversarial). Mutation-strategy + composite loops log a `logger.warning` on per-strategy failure rather than silently `continue` (t_ed914b66 / t_0b226fe3, e29288d) | `test_epd.py` |
| `seal/epd/{config,models}.py` | 147 | `EPDConfig`, `EPDFlag`, `EPDResult` | `test_epd.py` |
| `seal/epd/write_gate.py` | 257 | **Write-time injection gate (G03, `t_c6b46068`; 5 ruff UP-codes fixed B-014/`t_8d7f0402`).** `WriteGate` wraps any `write_*` tool with a config-driven pre-scan (`EPDConfig.block_threshold`, optional LLM pass via `llm_scan_all`), four policies (scan-before-write, block-on-threshold, redact-sensitive spans, throw `WriteBlockedError` on hard block); `redact_spans`/`scan_before_write` public helpers | `test_write_gate.py` (40+) |

### Secrets Broker — credentials out of context (Phase 3)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/broker.py` | 91 | `{SECRET:label}` placeholder resolution into tool calls, deep-copy + `redact()` | `test_broker.py` (12) |
| `seal/credential_store.py` | 207 | File store, **Fernet-encrypted at rest** | `test_credential_store.py` (11) |
| `seal/audit.py` | 234 | Append-only JSONL access audit (records access, never values) | `test_audit.py` (12) |

### Key lifecycle & persistence (Phase 5)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/store.py` | 247 | SQLite (WAL) `NonceStore` + `CounterStore`, expiry cleanup (P5.2) | `test_store.py` (32) |
| `seal/key_manager.py` | 767 | SQLite key registry: generated→active→expiring→retired→revoked, auto-rotation guard (P5.5), Fernet-encrypted private keys at rest. **KeyStore (`seal/key_store.py`) deleted (B-020, `t_ae0a9778`)** — it was a parallel store writing raw-BLOB private keys to the same `~/.seal/keys.db`; KeyManager is the single surviving store. **L-004 (t_7d597f41):** all three `chmod` `OSError` sites now `log.warning` instead of silent `pass` (`:116–118`, `:139–141`, `:294–296`). | `test_key_manager.py` (37), `test_key_lifecycle.py` (27) |
| `seal/rotator.py` | 43 | Rotation daemon — one-shot (cron) or persistent (`seal key daemon`) | `test_rotator.py` (t_ff898242, 7 tests) |
| `benchmark_vpe_verify.py`, `benchmark_envelope_size.py` | — | P5.1 / P5.3 perf + size benchmarks | — |

### Deployment & integration (Phases 4 / 6)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/integration/hermes_vpe_middleware.py` | 671 | Wraps Hermes tool calls in VPE verify + EPD scan | `test_e2e_real_tools.py` (37) |
| `seal/integration/hermes_skills_guard.py` | 316 | VPE/EPD-backed skills guard | `test_hermes_skills_guard.py` (t_3569cb04, 43 tests, 0%→100% coverage), `test_e2e_real_tools.py` |
| `seal/integration/division_vpe_signer.py` | 522 | Sign Division episodes | `test_division_vpe_signer.py` (t_7bb5b728, 32 tests, 100% coverage), `test_division_vpe_signer_nonce.py` (t_2b25ceff, 20 tests; verify-path value-binding fix, commit `6660ce7`) |
| `seal/integration/division_vpe_audit.py` | 459 | Store/query VPE results in Division memory (P6.4). L-006/007 hardened (t_55865f62, t_373d679c): canonicalization failure now logs warning + uses `degraded:` prefix; cross-reference append logs warning instead of bare `except:pass`. Dead `_canonical_hash()` with bare except removed (t_a4423aec). `_extract_episode_id` parse-failure `except` now logs a warning instead of silent `pass` (t_3f76b1e6, commit `35e3787`). | `test_division_vpe_audit.py` |
| `seal/rollback.py` | 503 | One-toggle disable + full config rollback, audit preserved (P6.5). Paths resolved lazily at call time via unified `_resolve_home(env_var, default_dir)` helper (collapsed `_resolve_seal_home()`/`_resolve_hermes_home()` in refactor `t_d1783048`) with `SEAL_HOME`/`HERMES_HOME` env overrides — no hardcoded `Path.home()` at import time (L-006). Audit-log line counting (`_archive_audit`, status report) uses a `with open(...)` context manager (no FD leak) and logs `logger.warning(..., exc_info=True)` on read failure instead of silently swallowing (t_226c651b) | `test_graceful_degradation.py` (20) |

### Advanced (Phase 9)
| Module | LOC | Provides | Tests |
|--------|-----|----------|-------|
| `seal/hardware.py` | 852 | HSM abstraction — YubiKey/TPM/Secure Enclave signing, key never leaves device (P9.4). **All 13 `subprocess.run` sites timeout-guarded (5 s probes / 30 s ops), raising structured `HsmError` (L-011, `t_491ce859`, commit `b9c4735`).** **Exception handling tightened (A4/A5, `t_b2bf180a`):** availability/`which` probes catch the narrow `(subprocess.SubprocessError, FileNotFoundError)`; `generate`/`sign` ops split into distinct `except CalledProcessError` and `except TimeoutExpired` handlers rather than broad catch-alls. **`get_public_key`/`list_keys`/`delete_key` hoisted into the `HsmProvider` ABC base (B-025, `t_d09cafba`, commit `5da549b`)** — 4 per-subclass overrides deleted; base methods at `hardware.py:136`/`:141`/`:145`. | `test_hardware.py` (27) |
| `seal/federation.py` + `seal/federation_store.py` | 1067 + 439 | Cross-agent trust anchors + federated sign/verify + audit (P9.5). **Persistence extracted to `federation_store.py` (B-015, `t_047da596`)** — trust-anchor registry, trust-bundle export/import, cross-agent audit log, and `FederationError` moved there (verbatim, no behavior change) and re-exported by `federation.py:25–38`; DNS/DID discovery + federated sign/verify stay in `federation.py`. **JWK decode-failure now logs `logger.debug` (A6, `t_9a7d3d4d`, `federation.py:685`)** instead of silently swallowing. **P9.5a** Python-native DNS resolver (no `dnspython` dep): hand-built query+parser (`_build_dns_query`/`_parse_dns_response`/`_send_dns_query`), `resolve_via_dns()` reads `_vpe.<domain>` TXT `vpe-key=<64-hex>`. **P9.5b** DID resolution — `resolve_via_did()` (did:key base58btc) **plus** `resolve_via_did_document()` (HTTPS `did:web:` → `.well-known/did.json`, `did:ion:` → msidentity resolver, extracts Ed25519 `verificationMethod`). **P9.5c** signed trust-anchor bundle export/import (`export_trust_bundle`/`import_trust_bundle`, self-signed Ed25519 over canonical JSON, tamper-rejecting). `resolve_trust_anchor()` central dispatcher order: **registry → DNS → did:key → did:web/did:ion** (the `did:web`/`did:ion` step wired 2026-07-12 via the `did_web` param, `t_f5641b1f`). **`vpe_federated_verify()` residual gap closed (`t_fd51e037`, commit `c07c6cf`):** `vpe_federated_verify()` now accepts and forwards `did_web` to `resolve_trust_anchor()`, and a `seal federation verify` CLI subcommand exists with `--did-web` flag — see the 2026-07-14 header entry for full details. | `test_federation.py` (142) |

### Cross-language ports & interop (Phase 8.5a)
- **Ports:** `vpe-ts/` (TS, 617 LOC, 114 tests), `vpe-go/vpe/` (~778 LOC, 39 test funcs), `vpe-rust/src/` (~929 LOC, 33 `#[test]`) — API parity with the Python reference. **Go module published to proxy.golang.org at v0.1.0 (`t_d86f3b1c`, commit `f6350f0`, tag `vpe-go/v0.1.0`); TS/Rust **not published** to npm/crates.io.**
- **Shared interop fixture:** `tests/vectors/vpe_vectors.json` (22 vectors, valid + tampered, Ed25519 + HMAC; ttl ∈ {0, 31536000}), generated by `tests/generate_vectors.py` from the Python reference.
- **Interop tests (one per language, same fixture):** `tests/test_interop_vectors.py`, `vpe-ts/tests/interop_vectors.test.ts`, `vpe-go/vpe/interop_vectors_test.go`, `vpe-rust/tests/interop_vectors_test.rs`. (Not re-run this sync — sandbox blocks the runners.)

### Standards, packaging & docs (Phase 8, partial)
- **`VPE_SPEC_v1.md`** (839 lines) — full protocol spec.
- **`proposals/`** — `owasp_agentic_security_vpe.md`, `mcp_signing_extension.md`, `SEP-vpe-signing-layer.mdx`; **`seal-community/`** — conference CFP drafts.
- **Docs site** — MkDocs (`mkdocs.yml`, `docs/` 18 pages: spec, API reference, CLI, integration, threat model, quickstart) → `docs.yml` CI deploy.
- **CI** — `.github/workflows/` holds **five** workflows: `test.yml`, `lint.yml`, `benchmark.yml`, `docs.yml`, `publish.yml`. All four install via **`uv sync --locked --extra <dev|docs>`** against the committed `uv.lock` (originally `--group dev` per `t_f8f19e90`/`f33a635`, 2026-07-28; migrated to PEP 621 extras by `0ff6a87`, 2026-07-31; docs toolchain pinned via `73a0701`, 2026-07-29 — see the CI-health closure record below). `publish.yml` (PyPI `seal-vpe`, trusted-publishing via `pypa/gh-action-pypi-publish`, `on: release: published`). **`publish.yml` fired once and FAILED** (verified live 2026-07-01): GitHub Release `v0.1.0` was published 2026-06-28, triggering run `28317759671` (`Publish to PyPI`) — `Build package` succeeded, the **`Publish to PyPI` upload step failed** (likely trusted-publishing/pending-publisher not configured on PyPI). So `seal-vpe` is **still not on PyPI** — `https://pypi.org/pypi/seal-vpe/json` → **404 (live-verified 2026-07-01)**; `pip install seal-vpe` fails. Repo is live at `github.com/rezearcher/seal`. Built artifacts exist locally in `dist/` (`seal_vpe-0.1.0-py3-none-any.whl`, `.tar.gz`, rebuilt 2026-06-28) but the registry upload never completed. **2026-07-05: a new board task claiming the PyPI publish was completed landed, but it is an UNVERIFIED claim — no local-code change since the last sync, and the live registry check was permission-blocked this session (see the dated note in the header block). Still shown as NOT-on-PyPI until a live 200 is observed.** Publish-prep config fixes landed in `d97ea7c` (`t_0c0fff25`): `[project.urls]` repo links corrected to `rezearcher/seal`, `__init__.py` dist name → `seal-vpe`; `authors` corrected to `Rez Archer` in `a475697` (`t_d3c9664e`).
- **CI health gap (fix commits landed 2026-07-01/02; CI-green NOT re-verified this sync):** the four red workflows each got a targeted fix commit on `master`:
  - **`Tests`** — coverage gate `fail_under` is **80** in `[tool.coverage.report]` (pyproject.toml:77, confirmed by read this sync). The gate was dropped 80→64 on `8cc5418` (t_396124b9) for CI-health, then **restored to 80 on `2cb1a01` (t_2b25ceff, final HEAD `6660ce7`)** once the suite hit 81.20% live. test.yml runs `uv run pytest --cov`; codecov upload has `fail_ci_if_error: false`, so the local `fail_under` is the actual gate.
  - **`Deploy Docs to GitHub Pages`** — `9ea0de4` (t_c4cae88f): fixed the `mkdocs build --strict` link warnings. docs.yml **still** invokes `mkdocs build --strict`, so the fix corrected the offending doc cross-links — it did not weaken the strict gate. **2026-07-19 foreman: `t_af6adb83` now VERIFIED live** — `mkdocs build --strict` exits 0 cleanly (1.19s build, no WARNING-level output). The unverified-gap is now closed.
  - **`Lint (ruff check)`** — `f435f7b` (t_086580fb): resolved the reported 403 ruff lint errors. `[tool.ruff.lint]` sets `select=["E","F","W","I","N","UP"]`, `line-length=120`, `target-version="py311"`, with per-file-ignores `"vpe-ts/*"=["E501","N802"]` and `"tests/*"=["N814"]` (confirmed by read). lint.yml runs both `ruff check .` and `ruff format --check .`.
  - **`Lint (ruff format)`** — `cce96e4` (t_0c169e9e, 2026-07-09, postdates the 2026-07-01/02 batch): `ruff format` fix for 49 files — formatting drift that caused `ruff format --check .` to fail. The existing `[tool.ruff.lint]` config (line-length=120, target-version=py311) was unchanged; the fix was running `ruff format` to reformat the 49 drifted source files including cross-language port files (`vpe-ts/`, `vpe-go/`, `vpe-rust/`) and `tests/`.
  - **`Lint (ruff check)` follow-up** — `463bef8` (t_504a86a8, 2026-07-17): 7 auto-fixable ruff errors — removed the unused `resolve_via_did_document` imports left in `tests/test_federation.py` after the `t_504a86a8`-adjacent federation work, and alphabetized the `seal/cli.py` federation import. Config unchanged (`select=["E","F","W","I","N","UP"]` still — confirmed by read this sync). Commit reports all 798 tests pass.
  - **Dependency pinning — `t_f8f19e90` / `f33a635` (2026-07-28, verified by read):** the recurring lint failures above (`f435f7b`, `cce96e4`, `463bef8`) were partly *version drift* — CI resolved whatever ruff was newest at run time, so a new ruff release could redden a branch nobody touched. Fixed by locking installs to the committed lockfile: `lint.yml:33`, `test.yml:38`, and `benchmark.yml:24` all run **`uv sync --locked --group dev`** *(superseded by `0ff6a87`, 2026-07-31 — all workflows now pass `--extra dev`/`--extra docs`; see the two closure bullets below)*. `uv.lock` (480 lines, committed, `revision = 3`) pins **ruff `0.15.16`** (`uv.lock:378–379`), plus `pytest`/`pytest-cov`. `--locked` additionally fails the job if the lockfile is stale relative to `pyproject.toml`, so a dependency bump must land in `uv.lock` in the same PR.
  - **CLOSED — Residual drift gap: `docs.yml` was NOT locked (`t_f8f19e90` residual; closed by `73a0701`, 2026-07-29):** `docs.yml:37` now runs **`uv sync --locked --extra docs`** (confirmed by read), and the docs toolchain is pinned in the committed `uv.lock` — mkdocs `1.6.1` (`uv.lock:508–509`), mkdocs-material, mkdocstrings[python], mkdocs-autorefs, mkdocs-get-deps, etc. `73a0701` added the `docs` extra to `[project.optional-dependencies]` in `pyproject.toml` (lines 39–42: mkdocs>=1.6.0, mkdocs-material>=9.5.0, mkdocstrings[python]>=0.26.0). `--locked` fails the job if the lockfile drifts, so `Deploy Docs` is no longer exposed to unpinned upstream releases; the earlier caveat ("strict build exits 0 was measured against locally installed versions") no longer applies to the *install* side — the docs job now installs exactly the locked versions.
  - **CLOSED — Unverified risk: `--group dev` vs. extras (`t_f8f19e90` residual; closed by `0ff6a87`, 2026-07-31):** the `--group`/PEP 735 vs. `--extra`/PEP 621 mismatch is resolved — all four workflows now pass extras: `lint.yml:33`, `test.yml:38`, `benchmark.yml:24` → **`uv sync --locked --extra dev`**; `docs.yml:37` → **`uv sync --locked --extra docs`** (all confirmed by read this sync). `uv.lock:883` records `provides-extras = ["dev", "docs"]`, and `pyproject.toml` declares both extras under `[project.optional-dependencies]` (lines 34–42). **Both residual gaps from the 2026-07-28 sync are now CLOSED in code.** Not re-run this sync: a live `uv sync --locked --extra dev --dry-run` and a post-`0ff6a87` CI job log were both unavailable in this sandbox, so CI-green remains asserted from the commit evidence rather than an observed run — but the install-side ambiguity itself (the thing the risk flagged) is gone.
  - **`publish.yml` unaffected:** it installs no dev dependencies (`uv build` → `pypa/gh-action-pypi-publish`), so ruff drift never applied there.
  - **Gap / partially re-verified (2026-07-19 foreman, still true 2026-07-28):** `mkdocs build --strict` was **observed passing** locally (exits 0). `ruff check`, `ruff format --check`, and `pytest --cov` still **not re-run** — do not assume they pass without a live run. Test count (798 pass, 1 skip) rests on commit history, not observed-green CI.
- **Version reporting (FIXED, `t_0c0fff25`/`d97ea7c`):** `seal/__init__.py` now resolves `__version__` via `importlib.metadata.version("seal-vpe")` — the correct distribution name (was `version("seal")`, the wrong name, which fell back to the hard-coded `"0.1.0"`). With `seal-vpe` installed in this environment, `version("seal-vpe")` now resolves to `0.1.0` from installed metadata (verified 2026-06-29), not the fallback branch; the `except PackageNotFoundError → "0.1.0"` fallback remains for uninstalled use.

### CLI surface (`seal …`)
`genkey` · `sign` · `verify` · `secrets {add,get,list,delete}` · `audit` · `key {rotate,revoke,disable,list,daemon}` · `rollback` · `hardware` · `fuzz` · `status` · `epd` · `memory {sign,verify}` · `quickstart` · `disable` · `federation {export,import,verify}`

> **`federation {export,import,verify}` — `export`/`import` (P9.5c, `cli.py:889`, verified by read) and `verify` (P9.5e/`t_fd51e037`, `cli.py:956–969`, commit `c07c6cf`).** `seal federation export` writes a signed trust-anchor bundle (calls `export_trust_bundle`); `seal federation import` loads + verifies one (`import_trust_bundle`); `seal federation verify` provides a CLI pathway into `vpe_federated_verify()` with `--did-web`, `--did-str`, `--dns-domain`, `--registry`, and `--issuer-override` flags. The `epd`, `memory`, `quickstart`, and `disable` subcommands were also already wired in `cli.py` but were missing from this list in prior syncs — now reconciled against the actual `sub.add_parser(...)` calls. (Not probed live: `python -m seal --help` is execution-blocked in this sandbox; the surface list is confirmed by reading the subparser registrations, not by running the CLI.)

---

## Security Notes / Known Limitations

- **Private keys encrypted at rest:** `seal/key_manager.py` encrypts private keys with Fernet (`cryptography.fernet.Fernet`) before writing to the SQLite registry at `~/.seal/keys.db`. A Fernet master key is auto-generated at `~/.seal/master.key` on first use. Legacy unencrypted keys are auto-migrated on read with a warning. An optional second factor XORs the Fernet key with machine-id (`/etc/machine-id`).
- **TTL enforcement requires `iat`:** In both `seal/core.py` and `seal/vpe.py`, TTL expiry is only enforced when the `iat`/`issued_at` field is present in the envelope. When `iat` is absent (backward-compat envelopes), TTL is silently skipped. Envelopes produced by `vpe_sign` always include `iat`.
- **Single, encrypted credential store (legacy plaintext store removed — P3.3a, `t_84148f82`):** `seal/credential_store.py` (`seal.credential_store.CredentialStore`) is Fernet-encrypted at rest and is the only credential-store implementation. The legacy plaintext-JSON `CredentialStore` (and `AuditLog`) that previously lived in `seal/secrets_broker.py` and wrote credentials to `~/.hermes/secrets.json` have been **deleted**. `seal/secrets_broker.py` was a 34-line back-compat shim that re-exported `CredentialStore` / `CredentialStoreCorruptedError` from `seal.credential_store`; **deleted in t_7fd8f2ce** since no code imports it anymore. Use `seal.broker`, `seal.credential_store`, and `seal.audit` directly for all new integrations.
- **`DIVISION_BASE_URL` SSRF/exfil vector closed by removal (`t_595b2bcc` → superseded by `t_ab5bd481`):** the original hardening — `_validate_division_url()` at `seal/division_audit.py:70` resolving `DIVISION_BASE_URL` and falling back to `http://localhost:7070` with a `logger.warning` on non-private/public hosts — protected the HTTP transport in the now-deleted `seal/division_audit.py`. That transport is gone: the live `seal/integration/division_vpe_audit.py` reads **no env vars** and does **no URL-driven I/O** (writes go through an injected MCP callable), so the env-var redirect attack surface no longer exists. No replacement hardening needed.
- **`seal/key_manager.py` — L-004 chmod-failure logging (closed t_7d597f41):** the three `chmod` sites that harden filesystem perms — `_ensure_seal_dir()` (`~/.seal` 0700, `:116`), `_load_or_create_master_key()` (`master.key` 0600, `:139`), and `KeyManager.__init__` (db-parent 0700, `:294`) — previously swallowed `OSError` silently, so a failed permission-tighten on a restricted/non-POSIX FS left keys world-readable with no trace. Each now emits a `log.warning(...)` naming the path + error. **L-004 closed.**
- **`seal/integration/division_vpe_audit.py` — L-006 + L-007 hardened + dead code removed (closed t_55865f62, t_373d679c, t_a4423aec):** Three fixes in `DivisionVPEAudit`. (1) **L-006 (canonicalization fallback in `record_from_result`):** A bare `except Exception:` that silently aliased the envelope hash to a nonce fragment was replaced with `except (TypeError, ValueError, KeyError)`, adds a `degraded:` prefix, logs a `logger.warning` naming the issuer + degraded hash, and sets `reason="hash_computation_failed"` when the caller didn't supply one. (2) **L-007 (cross-reference append):** A bare `except: pass` in `record()` when appending the Division episode reference to the local log was replaced with a `logger.warning` that includes the `audit_id` and `episode_id`. (3) **`_extract_episode_id` silent-swallow fixed (closed `t_3f76b1e6`, commit `35e3787`):** the former `except (json.JSONDecodeError, TypeError, AttributeError): pass` at `division_vpe_audit.py:444` now emits a `logger.warning` naming the result type + truncated content instead of silently dropping the parse failure — the last silent `except` in this module is closed.
- **Cross-language ports implemented in-repo, not published (P8.5a):** TypeScript (`vpe-ts/src/index.ts`, 617 LOC), Go (`vpe-go/vpe/`, ~778 LOC), and Rust (`vpe-rust/src/`, ~929 LOC) ports exist and each ships its own test suite (TS 114 cases, Go 39 test funcs, Rust 33 `#[test]`). All three expose API parity with the Python reference: `generateKeyPair`, `vpeSign`/`vpeVerify` (Ed25519), `vpeSignHmac`/`vpeVerifyHmac`, and canonical-JSON serialization. **Not yet published** to npm/crates.io — `npm install seal-vpe` and `cargo add vpe-rust` still 404. **Go module IS published: `go get github.com/rezearcher/seal/vpe-go/vpe` resolves on proxy.golang.org at v0.1.0 (t_d86f3b1c, commit `f6350f0`, tag `vpe-go/v0.1.0`; live-verified this sync — the old `github.com/seal/vpe-go` path 404s). **Shared cross-language test-vector fixture now committed (P8.5a, was previously a gap):** `tests/vectors/vpe_vectors.json` (22 vectors, valid + tampered, Ed25519 + HMAC) is generated from the Python reference by `tests/generate_vectors.py` and consumed by an automated interop test in **all four** languages — `tests/test_interop_vectors.py`, `vpe-ts/tests/interop_vectors.test.ts`, `vpe-go/vpe/interop_vectors_test.go`, `vpe-rust/tests/interop_vectors_test.rs` — each resolving the *same* repo-root fixture path. Byte-for-byte cross-language verification is now exercised by running tests, not just asserted by spec. (Caveat: this doc-sync could **not** re-execute the four test runners — the sandbox blocks `pytest`/`go test`/`jest`/`cargo test`; "passing" rests on commit history, where `t_253e5d8a`/`e50ce42`/`f575146` specifically fixed 4 TTL-expiry failures by bumping vector TTLs to 31536000s, not on a re-run during this sync.) See the Phase 8 section below.
- **VPE consolidation — SHIPPED 2026-07-10 (t_8154eafe, commits `c93ae6d` + `8c9b42a`; supersedes the earlier no-op `t_719f3958`).** Verified in code: `seal/_base.py` (145 LOC) now exists as the single source of truth for protocol constants, canonical serialization (`_canonical_json`), field-stripping, nonce generation, and cryptography-backed key helpers. **Both `seal/core.py` and `seal/vpe.py` import from `seal._base`** (`from seal._base import (…)` at `core.py:12` and `vpe.py:16`) instead of each carrying divergent copies — this is what eliminated the earlier canonical-JSON/field-set drift that `t_03ea2d3a` had been patching field-by-field. The two files **still exist as separate modules** (this was an extract-shared-core refactor, not a full merge): `core.py` keeps the low-level sign/verify + key-management + multi-sig/cert/hardware surface; `vpe.py` keeps the envelope dataclasses + multi-backend NaCl/cryptography dispatch. Net LOC dropped 1229→730 (core) and 589→414 (vpe). Reviewed under **t_9ea25f3e**, which surfaced the S-001 nonce-ordering bug fixed in `t_75f3f059` (see Security Notes). *(Note: the prior sync's "zero code evidence / do not treat as shipped" verdict applied to `t_719f3958`, which genuinely left no code — the consolidation actually landed later under `t_8154eafe`.)*


---

## Phase 5 — Performance & Production Hardening ✅ Implemented

> Persistent SQLite stores (`store.py`), key lifecycle + rotation (`key_manager.py`/`rotator.py`), HMAC path (`core.vpe_*_hmac`), and benchmarks all landed and tested.

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

> Middleware, graceful degradation, Division audit trail (`division_vpe_audit.py`), and rollback (`rollback.py`) are built and tested. Live production wiring into a running Hermes/Division instance is deployment-dependent, not a code gap.

**Goal:** VPE middleware running in production, protecting real Hermes tool calls.

### Subtasks

| ID | Task | Acceptance Criteria |
|----|------|--------------------|
| P6.1 | Wire VPE into Hermes config | VPE middleware registered as optional plugin in Hermes `config.yaml`. Enabled/disabled via config toggle. No Hermes core modifications needed — MCP middleware layer only. |
| P6.2 | End-to-end test with real tools | Full chain: prompt → VPE sign → Hermes receives → VPE verify → scope check → EPD scan → tool call → response → VPE sign response. Test with `read_file`, `terminal`, `web_search`. |
| P6.3 | Graceful degradation | Unsigned prompts still work: logged as "unverified" with warning. Expired envelopes: logged, prompt still executed (configurable strict/lenient mode). Invalid signatures: rejected with clear error. |
| P6.4 | Division audit trail | Every VPE verification result stored in Division memory as episode: envelope hash, issuer, result (valid/invalid/expired), timestamp. Queryable: "show me all rejected prompts in the last hour." Hardened (L-010, `t_3035a8b3`): audit hashing no longer swallows all exceptions — canonicalization failure now logs a warning, marks the record `hash_computation_failed`, and emits a `degraded:`-prefixed identifier instead of a hash silently aliased to the nonce. The degraded fallback is retained-and-flagged, not removed; its failure branch is now covered by `test_record_from_result_degraded_hash` + `test_record_from_result_degraded_hash_keeps_reason` (t_0915b83c, commit `579247e`). Further hardened in `division_vpe_audit.py` (L-006/L-007, `t_55865f62`/`t_373d679c`): canonicalization fallback in `record_from_result` logs warning + prefixed degraded hash; cross-reference append logs warning instead of bare `except:pass`. |
| P6.5 | Rollback procedure | Disable VPE middleware with single config toggle. Script to roll back all VPE-related changes to Hermes config. No data loss on rollback — audit trail preserved. Hardened (L-006, `t_9da24d09`): `~/.seal` and `~/.hermes` paths are resolved lazily at call time (`_resolve_seal_home()`/`_resolve_hermes_home()`) instead of hardcoded `Path.home()` constants at import time, with `SEAL_HOME`/`HERMES_HOME` env overrides for testability and non-default homes. Further hardened (t_226c651b): the audit-log line count in `_archive_audit` and the status report now runs inside a `with open(...)` block (closes the descriptor even on error) and logs a warning with `exc_info=True` on read failure instead of silently swallowing it (`count = 0` fallback). |

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

> Mutation fuzzer (`epd/fuzzer.py`, `seal fuzz`), cryptographic-bypass + scope-escalation suites (`test_crypto_bypass.py`, 54 tests), and the P7.4 LLM-bypass finding (→ `llm_scan_all`) are done. The **T11 Unicode-smuggling** defense is the latest adversarial hardening (see [Threat Model](docs/threat-model.md)). The fuzzer's mutation-strategy and composite-mutation loops were also de-silenced (t_ed914b66 / t_0b226fe3): a strategy that raises now emits a `logger.warning` naming the strategy + template before continuing, rather than discarding the failure — so a broken strategy is visible instead of quietly shrinking the corpus.

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

> Proposals drafted (`proposals/`: OWASP, MCP extension, SEP), docs site + CI + PyPI packaging **config** in place (`pyproject.toml` + `publish.yml`), CFP drafts written (`seal-community/`). **Shipped since (P8.5a):** cross-language ports — TS/Go/Rust — implemented in-repo with per-port test suites, **plus a shared cross-language test-vector fixture** (`tests/vectors/vpe_vectors.json`, 22 vectors) with an automated interop test in all four languages (commit `f7c2af4`; TTL fix `e50ce42`/`f575146`). **Shipped since (P8.3b, `t_a40992b1`):** the open-source repo is **pushed to GitHub** at `github.com/rezearcher/seal`. **Attempted-and-failed (P8.3b-2, verified live 2026-07-01):** a GitHub Release `v0.1.0` was published 2026-06-28 and **did** trigger `publish.yml`, but the run **failed at the PyPI upload step** — `seal-vpe` is **still 404 on PyPI**. **External-dependent / NOT done:** a *successful* PyPI publish of `seal-vpe` (a 2026-07-05 board task claims this is done, but it is **unverified** — no local evidence, live registry check was permission-blocked this sync; see header note), registry publishing of the ports, and actual OWASP/MCP acceptance.

**Goal:** VPE becomes an industry reference — not just a local tool.

### Subtasks

| ID | Task | Acceptance Criteria |
|----|------|--------------------|
| P8.1 | Submit OWASP proposal | PR or submission to OWASP Agentic Security Top 10 repository. New control category: "Prompt Authentication & Cryptographic Verification" with VPE as reference implementation. |
| P8.2 | Draft MCP spec extension | Formal MCP spec extension proposal. Define: `vpe` field in MCP messages, key exchange mechanism, verification error codes. Submit as PR to MCP spec repo or IETF draft. |
| P8.3 (🟡 GitHub DONE / PyPI FAILED — P8.3b + P8.3b-2, `t_a40992b1`) | Open source release | Clean GitHub repo: README, LICENSE, CONTRIBUTING, issue templates, CI pipeline (GitHub Actions for tests + benchmarks). PyPI package: `pip install seal-vpe`. **Status (verified live 2026-07-01 — network reachable):** repo is **live on GitHub** (`github.com/rezearcher/seal`) with README/LICENSE/CONTRIBUTING/CI all present. **PyPI publish ATTEMPTED and FAILED, `seal-vpe` still 404.** The `P8.3b-2` publish task did the trigger side: a **GitHub Release `v0.1.0` was published 2026-06-28** (target `master`), which fired `publish.yml` run `28317759671`. That run **failed** — `Build package` ✅ but `Publish to PyPI` upload ❌ (most-likely PyPI trusted-publishing / pending-publisher not configured; unconfirmed). `https://pypi.org/pypi/seal-vpe/json` → **404 (live 2026-07-01)**; `pip install seal-vpe` fails today. **Publish-prep config landed** (`t_0c0fff25`/`d97ea7c`, reviewed `t_dd8f649c`; authors fix `a475697`/`t_d3c9664e`): repo URLs, dist name, and authors fixed. **Gap to close:** configure the PyPI trusted publisher (pending-publisher) for `seal-vpe`, then re-run the failed `publish.yml` (re-publish the Release or `gh workflow run`) — or a manual `uv build && uv publish` — and re-verify PyPI returns 200. **2026-07-05 UPDATE:** a board task titled "Publish seal-vpe to PyPI (complete what `t_0c0fff25` left undone)" was marked complete, but this doc-sync could **not verify it** — no local-code change since the last sync (`dist/` and `publish.yml` untouched, version still `0.1.0`) and the live PyPI check was permission-blocked this session. Treat as an **unverified-gap**: the closing step (live PyPI 200) is still unconfirmed. |
| P8.4 | Documentation site | Hosted docs (GitHub Pages or similar): protocol spec, API reference, integration guide, CLI reference, threat model. Quickstart: "Add VPE to your agent in 5 minutes." |
| P8.5 | Reference implementations (**🟡 IMPLEMENTED IN-REPO + INTEROP-WIRED, NOT PUBLISHED** — P8.5a) | TS/Go/Rust ports built and committed (`vpe-ts/`, `vpe-go/`, `vpe-rust/`) with API parity (`vpeSign`/`vpeVerify` Ed25519, `vpeSignHmac`/`vpeVerifyHmac`, canonical JSON) and per-port test suites (TS 114, Go 39, Rust 33). Python remains the canonical spec. **Now met:** the "same test vector suite (cross-language verification)" acceptance criterion — `tests/vectors/vpe_vectors.json` (22 vectors generated from the Python reference via `tests/generate_vectors.py`) is consumed by an automated interop test in all four languages, each resolving the same repo-root fixture (verified by path inspection this sync). **Still open:** npm/crates.io packages unpublished — `npm install seal-vpe` and `cargo add vpe-rust` still 404. **Go module now published (t_d86f3b1c, commit `f6350f0`):** `go get github.com/rezearcher/seal/vpe-go/vpe` resolves at v0.1.0 on proxy.golang.org (tag `vpe-go/v0.1.0`; live-verified 2026-08-17). Interop/per-port pass-counts were **not independently re-run** during this doc sync (sandbox blocks pytest/go/jest/cargo); pass-status rests on commit history, including `t_253e5d8a` which fixed 4 TTL-expiry interop failures. |
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

> Hierarchical issuer chains (`core.verify_cert_chain`, P9.1), key expiry/rotation (P9.2), multi-signature envelopes (`core.vpe_sign_multi`, P9.3), hardware signing (`hardware.py`, P9.4), and federation (`federation.py`, P9.5) are all built and tested. Trust-anchor discovery via DNS/DID is now implemented — Python-native DNS resolver (`resolve_via_dns`), DID document resolution via HTTPS (`resolve_via_did_document`), and a trust anchor exchange protocol (`export_trust_bundle`/`import_trust_bundle`) are all present and integration-tested. See P9.5a-d below.
>
> **Dispatcher now wires all four sources (was a gap through 2026-07-12; closed `t_f5641b1f`, commit `8357442`):** the central `resolve_trust_anchor()` (`federation.py:1223`) chains **registry → DNS → did:key → did:web/did:ion**. The P9.5b HTTPS DID-document path, `resolve_via_did_document()` (`did:web:`/`did:ion:`), is now invoked as dispatch step 4 via the new `did_web` parameter (`federation.py:1269–1273`), returning `source="did_web"` on a hit and falling through to `source="none"` when it resolves to `None`. It is still *also* a standalone public API (exported in `seal/__init__.py`, unit-tested) for callers who want to resolve-and-register directly. The prior two syncs' "not called by `resolve_trust_anchor`" gap note no longer holds.
>
> **CLOSED (2026-07-14, `t_fd51e037`, commit `c07c6cf`) — the above dispatcher-only gap is now fully closed.** `vpe_federated_verify()` gained `did_web` (`federation.py:965`), the CLI gained `seal federation verify --did-web` (`cli.py:956–969`), and `test_verify_with_did_web_forwarded` exercises the full plumbing. See the 2026-07-14 header entry for the closure record.

**Goal:** Extend VPE beyond the reference implementation into a full prompt security framework.

### Subtasks

| ID | Task | Acceptance Criteria |
|----|------|--------------------|
| P9.1 | Hierarchical keys (issuer chains) | Key hierarchy: root CA → intermediate → signing key. Envelope includes cert chain. Verification walks the chain. Enables: team signing, delegation, revocation without re-keying all agents. |
| P9.2 | Time-based key expiry | Keys have `not_before` and `not_after` timestamps. Automatic rotation daemon. Integration with P5.5 key lifecycle. |
| P9.3 | Multi-signature envelopes | Requires N-of-M signatures before execution. Use case: "two of three team leads must approve this prompt." `vpe_sign` adds signature to existing envelope. `vpe_verify` checks threshold. |
| P9.4 | Hardware key support | YubiKey (PIV/OpenPGP), TPM, or macOS Secure Enclave for private key storage. Signing operation moves to hardware. Private key never leaves the device. |
| P9.5 | VPE federation (cross-agent trust) | ✅ Implemented. Agent A can sign a prompt for Agent B via shared trust anchor. Sub-tasks shipped: P9.5a Python-native DNS resolver (`resolve_via_dns`, raw UDP DNS TXT queries), P9.5b DID document resolution (`resolve_via_did` for `did:key:`, `resolve_via_did_document` for `did:web:` and `did:ion:`), P9.5c trust anchor exchange protocol (`export_trust_bundle`/`import_trust_bundle` for JSON bundle export/import), P9.5d integration tests for DNS-discovered trust anchors (`tests/test_federation.py`, 2240 lines). 38 ruff lint errors from P9.5 federation work fixed (t_4613ff8f). **Dispatcher wiring (t_f5641b1f, `8357442`):** `resolve_trust_anchor()` now chains registry → DNS → did:key → did:web/did:ion via the `did_web` kwarg. **Open gap:** `vpe_federated_verify()` still has no `did_web` parameter and never forwards one to the dispatcher, so did:web/did:ion anchors are not reachable from the federated verify flow (nor from the CLI) — see the Phase 9 note above. |

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
- **Cross-framework**: TypeScript/Go/Rust ports exist with API parity to the Python reference (P8.5a), and interoperability is now exercised by a shared canonical test-vector fixture (`tests/vectors/vpe_vectors.json`, 22 vectors) with an automated interop test in all four languages. *Caveat: the test runners could not be re-executed during the latest doc sync (sandboxed); pass-status rests on commit history — see Known Limitations.*

### When to Stop
Seal is "done" when:
- VPE is referenced in OWASP Agentic Security Top 10 or MCP spec, OR
- It's been running in production for 6 months with zero VPE bypasses, OR
- You decide prompt-level crypto isn't the right approach and pivot

### Shutdown states
- **Paused:** Middleware disabled, CLI tools still work, audit data preserved
- **Archived:** Integrations removed, spec and proposals remain as reference
- **Open-sourced:** Project transferred to community ownership
