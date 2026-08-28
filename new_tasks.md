## New Tasks for Seal Board

> **ADJUDICATED 2026-08-28** — All three items below were re-minted from stale findings
> docs and have been verified against shipped code. Each is closed with a dated
> disposition; **do not re-file any of them.** Any future supply pass that sees this
> header must treat these as dead entries.

---

## ADJUDICATED 2026-08-28 — stale-findings doc sync (t_da70723c)

### 1. ~~error handling in `seal/hardware.py`~~ — **SHIPPED (stale premise, closed)**
**WHAT:** The previous entry re-proposed an error-handling pass on `seal/hardware.py`.
**DISPOSITION: SHIPPED.** `seal/hardware.py` (899 LOC) already ships **22 `HsmError`
references: class definition at line 65, docstring annotation at line 140, and 20 raise
sites (lines 246–692)** — every raise sits inside a structured `except → raise` chain
(`raise HsmError(...) from exc` after `logger.error`, e.g. lines 240–249, 307–314,
378–385, 621–628) with **zero bare excepts**. The prior premise ("20 `HsmError` raises
suggests the need for improved error management") is stale on both counts: the count is
now 22 references and the handling is already structured. Shipped by `b3800d0`
(missing-key handling), `b9c4735` (subprocess timeout/error wrap), `2487af0` (tightened
crypto exception handling). Verified 2026-08-28: `grep -c HsmError seal/hardware.py` = 22;
`grep -nE "except:"` = 0 matches.

### 2. ~~Coverage for gaps identified in ARCHITECTURE.md~~ — **DEAD (closed)**
**DISPOSITION: DEAD.** `ARCHITECTURE.md` is actively maintained via dated sync entries
through 2026-08-28 (two entries today: ruff-format fix + origin-push of the CI wiring,
and the Lint workflow observed green). Its header states Phases 1–9.5 core capabilities
implemented and tested; the only remaining items are **external adoption** (P8 port
publishing, P10 production-bake) and the **human-gated G01** PyPI trusted-publisher item —
all already tracked in the doc's "Remaining" section. No unaddressed internal coverage
gap exists for a worker to implement; re-filing this card would mint a vacuous task.

### 3. ~~Investigate blocked tasks under 'review-required'~~ — **DEAD (closed)**
**DISPOSITION: DEAD.** The seal board's only blocked card is **G01 ("Register PyPI
trusted publisher for seal — human gate")**, which is human-gated, already open and
tracked, and explicitly out of scope for automated workers (no G01 work per board
policy). There are no 'review-required' blocked cards on the board. Nothing to
investigate; the premise of the item does not hold against current board state.
