# Kanban Tasks for Seal Project

> **ADJUDICATED 2026-08-28** — All four tasks below were re-minted from stale scanner
> findings (Beautifier / Lie Detector / Gap Analyzer) and have been verified against
> shipped code. Each is closed with a dated disposition; **do not re-file any of them.**

---

## ADJUDICATED 2026-08-28 — stale-findings doc sync (t_da70723c)

### Task 1 (Beautifier — duplicate function in vpe.py) — **SHIPPED (already consolidated)**
**DISPOSITION: SHIPPED.** The duplicate-VPE implementations this finding flagged were
consolidated in prior commits: `b841c3c` `ref(t_719f3958): consolidate duplicate VPE
implementations (core.py + vpe.py)`, `c93ae6d` `ref(t_8154eafe): consolidate duplicate
VPE implementations into seal/_base.py`, and `3bab27a` `ref(t_d4fe5eb5): consolidate
SIGNED_FIELDS and field-list constants`. Current `seal/vpe.py` (410 LOC) contains 17
unique top-level defs (vpe_sign, vpe_verify, generate_keypair, load/save/load_or_generate
_keypair, 7 `_check_*` validators, 3 `_sign/_verify/_canonical/_ensure_nacl` helpers) with
**zero duplicate names** — verified 2026-08-28 via `grep -oE "^def [a-z_]+" seal/vpe.py |
uniq -c` (every count = 1). No refactor remains to do.

### Task 2 (Beautifier — error handling in seal/hardware.py) — **SHIPPED (stale premise)**
**DISPOSITION: SHIPPED.** `seal/hardware.py` (899 LOC) already ships 20 `raise HsmError`
sites in structured `except → raise` chains (`raise HsmError(...) from exc` after
`logger.error`, lines 246–692: YubiKey PIV 246/249/311/314, TPM 382/385/408/411/423/426/
438/441/457/460/521/524, Secure Enclave 625/628/689/692) with **zero bare excepts**
(verified 2026-08-28). The reliability/maintainability goal of the finding is already met
by `b3800d0` (missing-key handling), `b9c4735` (timeout/error wrap), `2487af0` (tightened
crypto exception handling).

### Task 3 (Lie Detector — error handling for missing keys in seal/hardware.py) — **SHIPPED**
**DISPOSITION: SHIPPED.** The missing-keys handling this finding requested was implemented
by commit `b3800d0` ("Implement error handling for missing keys in seal/hardware.py").
Key-extraction/derivation paths raise `HsmError` with logged context (e.g. YubiKey PIV
generation lines 240–249, signing lines 307–314; Secure Enclave lines 621–628) — failures
surface as typed `HsmError` with the underlying stderr chained via `from exc`, never as
silent crashes. Logging is in place on every failure path (no silent exception handling).

### Task 4 (Gap Analyzer — ARCHITECTURE.md coverage gaps) — **DEAD (closed)**
**DISPOSITION: DEAD.** `ARCHITECTURE.md` is actively synced with dated entries through
2026-08-28 (today's two entries: ruff-format fix + origin-push of the port-CI wiring
[t_e8e5ccc3, t_f0f42d99], and the Lint workflow observed green [foreman verification]).
The doc's header records Phases 1–9.5 implemented and tested; the only remaining items
are **external adoption** (P8 port publishing, P10 production-bake) and the **human-gated
G01** PyPI trusted-publisher gap — both already tracked in the "Remaining" section and in
the board as blocked/tracked items. No unaddressed documented feature exists to implement
or validate; re-filing this card would mint a vacuous task.
