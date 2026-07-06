# Raise the Bar — Next Milestone

**Task:** t_207bea35
**Date:** 2026-07-06
**Decision:** Candidate A — Federation Hardening (P9.5+)

## Decision Rationale

v1 is fully shipped (83/83 subtasks, 688 tests pass). The project is in
raise-the-bar mode. Three candidates were evaluated:

### Eliminated: Candidate B — Hardware-Token Coverage (P9.4+)
**Why out:** The AC requires "end-to-end hardware signing works on at least one
real device" (YubiKey/TPM). As an automated agent without physical hardware
access, this AC is unreachable. The hardware abstraction layer (706 LOC in
`seal/hardware.py`, 27 tests) is already well-structured — its weaknesses are
hardware-gated, not code-gated.

### Eliminated: Candidate C — First External Adopter
**Why out:** PyPI publish is credential-gated (PyPI trusted-publisher config is
a Rez human action). The architecture log records this gate has cycled through
multiple closed-as-unverified task attempts. Publishing the cross-language ports
(npm/crates.io/Go) has the same dependency. No agent-code path can close this.

### Selected: Candidate A — Federation Hardening (P9.5+)
**Why in:** Pure code work, no hardware or credentials required. The architecture
doc explicitly identifies trust-anchor discovery via DNS/DID as "the thinnest
area" of an otherwise-shipped P9.5 module (699 LOC, 32 tests). Strengthens
Seal's core moat (axis 2 — provenance) where the product's weakest link is.

## Current State Audit

`seal/federation.py` (697 LOC) ships:

| Capability | Status | Weakness |
|---|---|---|
| File-based trust anchor registry | ✅ Complete | No sync/sharing protocol |
| DNS discovery (TXT records) | 🟡 Present | Subprocess (`dig`/`host`), no Python-native DNS resolver |
| DID key parsing (`did:key`) | ✅ Complete | No DID document fetch/parse from HTTPS |
| Cross-agent audit trail | ✅ Complete | Solid — append-only JSONL via `seal.audit` |
| Resolution chain | 🟡 Present | Hardcoded registry→DNS→DID, no pluggability |
| 32 unit tests | ✅ Passing | Cover registry CRUD, DID key parsing, resolution chain |

## Work Plan

### P9.5a — Python-native DNS resolver integration

Replace the fragile `subprocess.run(['dig', ...])` / `subprocess.run(['host', ...])`
with a stdlib-only DNS resolver using `socket.getaddrinfo` + manual UDP DNS query
construction, or add a lightweight dep like `dnspython` for proper SRV/TXT resolution.

**Files:** `seal/federation.py`, `tests/test_federation.py`
**AC:** `resolve_via_dns('example.com')` returns a 32-byte key from a well-known
TXT record without shelling out to `dig`/`host`.

### P9.5b — DID document resolution via HTTPS

Add `resolve_via_did_document(did: str) -> bytes | None` that fetches a DID
document from an HTTPS endpoint (e.g. `did:web:domain.com/path`), parses the
JSON-LD document, and extracts the Ed25519 verification method.

**Files:** `seal/federation.py`, `tests/test_federation.py`
**AC:** `resolve_via_did_document('did:web:example.com:agent')` fetches the
document, parses the `verificationMethod` array, and extracts the Ed25519 key.

### P9.5c — Trust anchor exchange protocol

Add a lightweight protocol for agents to exchange trust anchors out-of-band:
- `export_trust_bundle()` — serialise all trusted anchors as a signed JSON bundle
- `import_trust_bundle(bundle)` — verify bundle signature and import anchors
- CLI integration: `seal federation export`, `seal federation import`

**Files:** `seal/federation.py`, `seal/cli.py`, `tests/test_federation.py`
**AC:** Agent A exports a trust bundle → Agent B imports it → cross-agent
sign/verify works without pre-shared file access.

### P9.5d — Integration tests for DNS-discovered trust anchors

End-to-end test using a controlled DNS stub (or mock `socket`) to simulate TXT
record responses. Verifies the full chain: discover → verify → reject-tampered.

**Files:** `tests/test_federation.py`
**AC:** 15+ new integration tests covering DNS discovery, DID document resolution,
trust bundle exchange, and the full discover→sign→verify chain.

## Test Strategy

- All new code covered by unit tests (target: +50 test cases)
- Existing 32 federation tests must continue passing
- Full suite (688 tests) must pass before merge
- Mock DNS server for deterministic testing (no network dependency in CI)

## Success Criteria

1. `resolve_via_dns()` uses Python-native DNS (no `dig`/`host` subprocess)
2. `resolve_via_did_document()` fetches + parses real DID documents
3. Trust anchors can be exported and imported between agents
4. 50+ new federation tests, all passing
5. Full suite 688+ tests pass
