# CLI Reference

## Usage

```
seal <command> [options]
```

Installation via `pip install seal-vpe` registers the `seal` CLI entry point. Run `seal --help` for available commands.

## Global Options

| Option | Description | Default |
|--------|-------------|---------|
| `--store PATH` | Path to the encrypted credential store | `~/.seal/credentials.yaml.enc` |
| `--audit PATH` | Path to the audit log | `~/.seal/audit.jsonl` |

## Commands

### `seal genkey`

Generate an Ed25519 key pair.

```bash
seal genkey
```

Creates two files in `~/.seal/`:

| File | Permissions | Content |
|------|-------------|---------|
| `seal_private.key` | `0600` | 32-byte Ed25519 private key (raw bytes) |
| `seal_public.key` | `0644` | 32-byte Ed25519 public key (raw bytes) |

### `seal sign`

Sign a prompt and output a VPE envelope JSON string.

```bash
seal sign <prompt...> [options]
seal sign --stdin      # read prompt from stdin
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--private-key PATH` | Path to private key file | `~/.seal/seal_private.key` |
| `--scope JSON` | Scope JSON object (allowed_tools, max_tokens, etc.) | `{}` |
| `--issuer TEXT` | Issuer identity | `cli:default` |
| `--audience TEXT` | Audience agent | `agent:seal` |
| `--doc-sha256 HEX` | SHA-256 of bound document | none |
| `--ttl SECONDS` | TTL in seconds | `300` |
| `--nonce TEXT` | Explicit nonce (auto-generated if omitted) | random |
| `--counter INT` | Monotonic counter value | auto |

**Examples:**

```bash
# Simple signing
seal sign "list all files in /tmp"

# Full scope control
seal sign "search database" \
  --scope '{"allowed_tools": ["search"], "max_tokens": 2000}' \
  --issuer "user:rez" \
  --audience "agent:hermes-default" \
  --ttl 60

# Pipe prompt from stdin
echo "process orders" | seal sign --stdin
```

### `seal verify`

Verify a VPE envelope from stdin.

```bash
echo '<envelope>' | seal verify [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--public-key PATH` | Path to public key file | `~/.seal/seal_public.key` |

**Output:**

```json
{"valid": true, "reason": "ok"}
```

On failure, returns `{"valid": false, "reason": "<error_code>"}` and exits with code 1.

### `seal secrets`

Manage stored credentials (Fernet-encrypted key-value store).

#### `seal secrets add <label> <value>`

Store a credential. Label must match `^[a-zA-Z0-9_-]+$`.

```bash
seal secrets add github_token "ghp_xxxxxxxxxxxx"
```

#### `seal secrets get <label>`

Retrieve a credential. Outputs to stdout; use with caution in shell history.

```bash
seal secrets get github_token
```

#### `seal secrets list`

List stored credential labels (never exposes values).

```bash
seal secrets list
```

#### `seal secrets delete <label>`

Remove a stored credential.

```bash
seal secrets delete github_token
```

### `seal audit`

Show the last 20 audit log entries.

```bash
seal audit
```

Output format:
```
2026-06-06T20:00:00Z  granted  set      github_token              cli:rez
2026-06-06T20:01:00Z  granted  get      github_token              cli:rez
2026-06-06T20:02:00Z  denied   get      aws_secret                cli:bot  (label_not_found)
```

### `seal status`

Show current VPE integration status.

```bash
seal status
```

Displays:
- VPE middleware enabled/disabled
- Key availability and fingerprints
- Credential store health
- Nonce/counter store status
- Audit log configuration

### `seal disable`

Disable VPE middleware with a single config toggle. Preserves all config and key files.

```bash
seal disable
```

### `seal rollback`

Full removal of all VPE-related entries from Hermes config, with audit trail archival.

```bash
seal rollback [--clean-keys]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--clean-keys` | Also remove VPE key files (archived before removal) |

On rollback:
- Audit trail is copied to `~/.seal/archive/` (never deleted in-place)
- VPE keys are left in place (opt-in removal with `--clean-keys`)
- Credential store is left untouched
- Division memory episodes are preserved (read-only)
