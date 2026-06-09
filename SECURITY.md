# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Seal (VPE), please report it privately.

**Do not** open a public GitHub issue for security vulnerabilities.

### How to Report

- Email us at: **security@nousresearch.com**
- Or use the **Report a vulnerability** link on the GitHub Security tab:
  https://github.com/nousresearch/seal/security/advisories/new

### What to Include

- Description of the vulnerability
- Steps to reproduce (PoC preferred)
- Affected versions and configurations
- Any proposed mitigation (if known)

### Response Timeline

| Timeframe | Expected Action |
|-----------|-----------------|
| Within 48h | Acknowledgment of receipt |
| Within 7d | Initial triage and severity assessment |
| Within 30d | Fix or mitigation plan communicated |
| Upon fix | Coordinated disclosure and advisory publication |

## Scope

The following are in scope for security reports:

- Cryptographic weaknesses in VPE (Ed25519 or HMAC-SHA256 paths)
- Signature forgery, replay, or malleability
- Nonce/counter bypass
- Scope escalation attacks
- Secrets Broker credential leakage
- EPD scanner bypass (injection detection evasion)

## Out of Scope

- Linguistic prompt injection (content-based attacks without cryptographic bypass)
- Social engineering of project maintainers
- Attacks requiring physical access to the signing machine
- Refusal-to-serve or availability attacks on the Secrets Broker

## Hall of Fame

We will credit researchers who report valid vulnerabilities (with your permission).

Thank you for helping keep AI agent security cryptographic.
