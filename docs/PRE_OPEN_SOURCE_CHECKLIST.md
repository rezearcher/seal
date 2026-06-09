# Pre-Open-Source / Pre-Paper Hardening Checklist

> **Status: NOT ready to open-source.** Seal is the one project we're considering
> making public (it's close to useful and a paper is planned), but it must survive
> adversarial testing and real integration first. Publishing a *security* tool that
> is trivially bypassable or doesn't hold up on edge cases is worse than not
> publishing — the community will red-team it on day one (see T11: we already found
> an invisible-Unicode smuggling bypass that shipped "clean"). Harden, then open.

## Why we wait

- A prompt-security / cryptographic-provenance tool invites adversarial scrutiny.
  Reputation downside of a broken release > upside of an early release.
- The VPE concept is genuinely novel and paper-worthy — but the paper's credibility
  rests on the implementation surviving attack, not just on the idea.

## Gate to public + paper (all must pass)

### 1. Test it like an attacker would
- [ ] Red-team the **EPD scanner** bypass surface beyond T11: nested/mixed encodings,
      base64/hex/rot payloads, prompt-splitting across turns, language mixing,
      markdown/HTML/comment smuggling, RTL/bidi overrides, confusable scripts,
      adversarial whitespace, token-boundary tricks. Treat the 91% regex figure as a
      ceiling to attack, not a guarantee.
- [ ] Red-team the **VPE crypto layer**: signature stripping, downgrade to HMAC,
      canonicalization ambiguity, replay across audiences, TTL/clock-skew abuse,
      multi-sig threshold bypass, cert-chain confusion, hardware-path spoofing.
- [ ] Fuzz at scale (extend `seal/epd/fuzzer.py`) and measure catch-rate honestly,
      including novel-mutation catch rate, not just known-pattern.
- [ ] Adversarial LLM generation loop: have a model actively try to defeat EPD +
      VPE and feed misses back into the test corpus.

### 2. Integrate into our tools (shake out real-world bugs)
- [ ] Wire `seal.integration` middleware into a live Hermes tool-call path and run
      real workloads; confirm graceful degradation behaves under real traffic.
- [ ] Wire Division episode signing / audit (`division_vpe_*`) against a real
      Division instance; confirm the audit trail is queryable and correct.
- [ ] Dogfood for a sustained period; log every false positive / false negative.

### 3. Edge cases + "does it even work"
- [ ] End-to-end happy path on every CLI command against real keys/files.
- [ ] Cross-platform key handling (paths, permissions, hardware backends absent).
- [ ] Large-input behavior, empty/null/malformed envelopes, concurrent verifies,
      persistent-store corruption recovery (already started: CredentialStore).
- [ ] Confirm no silent-success / count=0 paths (our standing discipline).

### 4. Release hygiene (before flipping public)
- [ ] License chosen and headers present.
- [ ] No secrets/placeholders that look real in docs (audit found only `ghp_xxx`
      placeholders — keep it that way).
- [ ] Threat model documents known residual risk honestly (T11 section is the model).
- [ ] SECURITY.md responsible-disclosure path is real.
- [ ] Reproducible test suite green in CI on a clean checkout.

## Until then
Repo stays **private** (`rezearcher/seal`). Revisit this checklist before any
public flip or paper submission.
