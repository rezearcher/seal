# Integration Guide

## Add VPE to Your Agent in 5 Minutes

This guide walks through integrating VPE into any AI agent framework.

### 1. Install Seal

> **Note (2026-06-27):** `seal-vpe` is **not yet on PyPI** (returns 404), so `pip install seal-vpe` fails today. Until the PyPI publish lands (P8.3b), install from source: `pip install git+https://github.com/rezearcher/seal.git` or build a wheel locally (`uv build` → `pip install dist/seal_vpe-0.1.0-py3-none-any.whl`).

```bash
pip install seal-vpe   # NOT yet available — see note above
```

### 2. Generate Keys

```bash
seal genkey
```

Distribute the public key to your agents. Keep the private key secure.

### 3. Add Signing Middleware

Wrap outgoing prompts with VPE signing:

```python
from seal.vpe import vpe_sign

class VPESigningMiddleware:
    def __init__(self, private_key: bytes, issuer: str = "agent:my-agent"):
        self.private_key = private_key
        self.issuer = issuer
        self._counter = 0

    def wrap_prompt(self, prompt: str, audience: str,
                    scope: dict | None = None) -> dict:
        """Wrap a prompt in a signed VPE envelope."""
        self._counter += 1
        return vpe_sign(
            prompt=prompt,
            issuer=self.issuer,
            audience=audience,
            private_key=self.private_key,
            scope=scope or {"allowed_tools": ["*"], "max_tokens": 4096,
                            "max_cost": 0.10, "allowed_domains": ["*"]},
            ttl_seconds=300,
            counter=self._counter,
        )
```

### 4. Add Verification Middleware

Verify incoming envelopes before execution:

```python
from seal.vpe import vpe_verify
from seal.store import NonceStore, CounterStore

class VPEVerificationMiddleware:
    def __init__(self, public_key: bytes, agent_id: str = "agent:my-agent"):
        self.public_key = public_key
        self.agent_id = agent_id
        self.nonces = NonceStore()
        self.counters = CounterStore()

    def verify(self, envelope: dict) -> dict:
        """Verify an incoming envelope. Returns {'valid': bool, 'reason': str}."""
        result = vpe_verify(envelope, public_key=self.public_key)

        if not result["valid"]:
            return result

        # Nonce replay check
        if not self.nonces.add(envelope.get("nonce", "")):
            return {"valid": False, "reason": "NONCE_REPLAY"}

        # Counter monotonic check
        issuer = envelope.get("issuer", "")
        audience = envelope.get("audience", "")
        counter = envelope.get("counter", 0)
        last = self.counters.get(issuer, audience)
        if last is not None and counter <= last:
            return {"valid": False, "reason": "COUNTER_NON_MONOTONIC"}
        self.counters.set(issuer, audience, counter)

        # Audience check
        expected_audience = envelope.get("audience", "")
        if expected_audience != self.agent_id and expected_audience != "agent:*":
            return {"valid": False, "reason": "WRONG_AUDIENCE"}

        return {"valid": True, "reason": "ok"}
```

### 5. Integrate with MCP

For MCP-compatible agents, add the VPE layer as middleware:

```python
from integration.hermes_vpe_middleware import VPEMiddleware

# In your MCP server config:
middleware = VPEMiddleware(
    private_key_path="~/.seal/seal_private.key",
    public_key_path="~/.seal/seal_public.key",
    issuer="agent:my-agent",
)

# Now every tool call is automatically signed and verified
response = agent.call_tool("search", {"query": "..."})
```

### 6. Use the Secrets Broker

Keep credentials out of LLM context:

```python
from seal.broker import SecretsBroker
from seal.credential_store import CredentialStore

store = CredentialStore("~/.seal/credentials.yaml.enc")
broker = SecretsBroker(store)

# In your tool call arguments, use {SECRET:label} placeholders:
arguments = {
    "api_key": "{SECRET:github_token}",
    "repo": "nousresearch/seal",
}

# The broker resolves the placeholder at runtime:
safe_args = broker.wrap_tool_call("github_api", arguments)
# -> {"api_key": "ghp_xxxxxxxxx", "repo": "nousresearch/seal"}

# For logging, redact the secret:
redacted = broker.redact(arguments)
# -> {"api_key": "***REDACTED***", "repo": "nousresearch/seal"}
```

### 7. Audit Trail

Every credential access is logged:

```python
from seal.audit import AuditLog

audit = AuditLog("~/.seal/audit.jsonl")
entries = audit.query(limit=20)
for entry in entries:
    print(f"{entry['timestamp']} {entry['action']} {entry['label']} by {entry['caller']}")
```

## Integrating with Division

For Division agents with shared memory:

```python
from integration.division_vpe_signer import DivisionVPESigner

signer = DivisionVPESigner(private_key_path="~/.seal/seal_private.key")

# Sign memory episodes before storage
signed_episode = signer.sign_episode(
    agent="division",
    key="memory:project-plan",
    value={"phase": "P8.4", "status": "done"},
)
```

## Integrating with Hermes

The Hermes integration provides MCP middleware that intercepts tool calls:

```python
from integration.hermes_skills_guard import replace_guard_chain

# Replace the Hermes guard chain with VPE-aware guards
replace_guard_chain(vpe_enabled=True)
```

## Production Checklist

- [ ] **Key rotation** — Set up periodic rotation with `seal.key_manager.KeyStore.rotate_key()`
- [ ] **Nonce store cleanup** — Verify cleanup TTL is configured correctly
- [ ] **Audit monitoring** — Set up log aggregation for audit.jsonl
- [ ] **Fallback mode** — Test behavior with unsigned prompts (should log as "unverified")
- [ ] **Error handling** — Map VPE error codes to appropriate agent responses
- [ ] **Cryptography availability** — Ensure PyNaCl or cryptography is installed in production
