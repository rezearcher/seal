# Quickstart

Add VPE to your agent in 5 minutes.

## Install

```bash
pip install seal-vpe
```

Or from source:

```bash
git clone https://github.com/nousresearch/seal.git
cd seal
uv venv
uv pip install -e .
```

## Generate Keys

```bash
seal genkey
```

This creates two files in `~/.seal/`:

| File | Purpose |
|------|---------|
| `seal_private.key` | Your signing key (keep secret, `0600`) |
| `seal_public.key` | Your verification key (safe to share) |

## Sign a Prompt

```bash
seal sign "search the database for customer X" \
  --scope '{"allowed_tools": ["search"], "max_tokens": 4000}' \
  --issuer "user:rez" \
  --audience "agent:hermes-default"
```

Output: a signed VPE envelope JSON string.

## Verify an Envelope

```bash
echo '<envelope>' | seal verify
```

Returns `{"valid": true, "reason": "ok"}` on success.

## Use as a Library

```python
from seal import generate_key_pair, vpe_sign, vpe_verify

# Generate keys
keys = generate_key_pair()

# Sign a prompt
envelope = vpe_sign(
    prompt="search the database for customer X",
    scope={"allowed_tools": ["search"], "max_tokens": 4000},
    issuer="user:rez",
    audience="agent:hermes-default",
    ttl_seconds=300,
    private_key=keys["private_key"],
)

# Verify
result = vpe_verify(envelope, public_key=keys["public_key"])
assert result["valid"] is True
```

## Integrate with Hermes

```python
from seal.vpe import vpe_sign, vpe_verify

# In your MCP middleware:
def before_tool_call(tool_name: str, arguments: dict, context: dict):
    """Sign every outgoing prompt."""
    envelope = vpe_sign(
        prompt=arguments.get("prompt", ""),
        issuer=context.get("agent_id", "hermes:default"),
        audience="agent:target",
        private_key=load_key(),
    )
    arguments["_vpe"] = envelope
    return arguments

def after_tool_call(response: dict, context: dict):
    """Verify incoming envelopes."""
    envelope = response.get("_vpe")
    if envelope:
        result = vpe_verify(envelope, public_key=lookup_key(response["issuer"]))
        if not result["valid"]:
            raise PermissionError(f"Invalid prompt: {result['reason']}")
    return response
```

## Store Secrets

```bash
# Store an API key
seal secrets add github_token "ghp_xxxxxxxxxxxx"

# Use in tool calls with {SECRET:label} placeholders
seal sign "fetch issues from GitHub" \
  --scope '{"allowed_tools": ["github_api"]}'
```

The Secrets Broker resolves `{SECRET:github_token}` at runtime without exposing the value to the LLM.

## Check Status

```bash
seal status
```

Shows VPE integration status, key information, and configuration health.

## Next Steps

- Read the full [Protocol Specification](spec.md)
- Browse the [API Reference](api/index.md)
- Follow the [Integration Guide](integration.md) for production deployments
- Review the [Threat Model](threat-model.md)
- See all [CLI Commands](cli.md)
