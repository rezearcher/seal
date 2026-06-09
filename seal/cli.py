"""Command-line interface for Seal.

Commands:
    seal genkey                        Generate Ed25519 key pair
    seal sign <prompt>...              Sign a prompt (VPE envelope)
    seal sign --multi ...              Create/update multi-signature VPE envelope
    seal sign --hardware <provider>    Sign using hardware-backed key
    seal verify <stdin                 Verify a VPE envelope
    seal key list                      List managed keys
    seal key rotate                    Rotate the active signing key
    seal key revoke <kid>              Revoke a key by ID
    seal hardware list                 List available HSM providers
    seal secrets add/get/list/delete   Secrets Broker operations
    seal audit                         Show audit log
    seal disable                       Disable VPE middleware (single toggle)
    seal rollback                      Full VPE rollback from Hermes config
    seal status                        Show VPE integration status
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

from seal.audit import AuditLog
from seal.core import (
    VPE_VERSION,
    SIG_ALG_ED25519,
    SIG_ALG_ECDSA_P256,
    generate_key_pair,
    vpe_sign,
    vpe_sign_hardware,
    vpe_sign_multi,
    vpe_verify,
    vpe_verify_hardware,
    vpe_verify_multi,
)
from seal.credential_store import CredentialStore
from seal.hardware import HsmManager
from seal.key_manager import KeyManager, STATUS_ACTIVE, STATUS_EXPIRING, STATUS_RETIRED, STATUS_REVOKED
from seal.rollback import cmd_disable, cmd_rollback, cmd_status, RollbackReport

SEAL_DIR = Path.home() / ".seal"
DEFAULT_STORE_PATH = SEAL_DIR / "credentials.yaml.enc"
DEFAULT_AUDIT_PATH = SEAL_DIR / "audit.jsonl"

LABEL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
GET_WARNING = "# WARNING: printing secret to terminal \u2014 may be in shell history"


def _ensure_seal_dir() -> None:
    SEAL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        SEAL_DIR.chmod(0o700)
    except OSError:
        pass


def _valid_label(label: str) -> bool:
    return bool(LABEL_RE.match(label))


# ---------------------------------------------------------------------------
# Hardware support CLI commands
# ---------------------------------------------------------------------------


def cmd_hardware_list(args) -> int:
    """List available hardware security providers."""
    mgr = HsmManager()
    providers = mgr.available_providers()

    if not providers:
        print("(no hardware providers detected)")
        return 0

    print(f"{'PROVIDER':<18} {'ALGORITHM':<16} {'PLATFORMS':<24} {'ACTIVE'}")
    print("-" * 70)
    for p in providers:
        platforms = ", ".join(p["platforms"])
        active = "yes" if p["active"] else "no"
        print(f"{p['name']:<18} {p['algorithm']:<16} {platforms:<24} {active}")
    return 0


# ---------------------------------------------------------------------------
# VPE CLI commands (genkey / sign / verify)
# ---------------------------------------------------------------------------


def cmd_genkey(args) -> int:
    """Generate Ed25519 key pair registered with the key manager."""
    km = KeyManager()
    key = km.generate_key()
    print(f"generated key: {key['kid']}")
    print(f"  fingerprint: {key['fingerprint']}")
    print(f"  status:      {key['status']}")
    print(f"  expires:     {key['not_after']}")
    return 0


def _resolve_prompt(args) -> str:
    """Resolve prompt text from args or stdin."""
    if hasattr(args, "prompt_file") or not isinstance(getattr(args, "prompt", ""), list):
        return getattr(args, "prompt", "")
    if args.prompt:
        return " ".join(args.prompt)
    return sys.stdin.read().strip()


def cmd_sign(args) -> int:
    """Sign a prompt and print the VPE envelope JSON."""
    prompt = _resolve_prompt(args)

    if not prompt:
        print("error: no prompt provided (provide as argument or pipe via stdin)", file=sys.stderr)
        return 1

    # Parse scope from optional --scope JSON argument
    scope = {}
    if hasattr(args, "scope") and args.scope:
        try:
            scope = json.loads(args.scope)
        except json.JSONDecodeError as e:
            print(f"error: invalid scope JSON: {e}", file=sys.stderr)
            return 1

    # Hardware-backed signing
    hardware = getattr(args, "hardware", None)
    if hardware:
        try:
            envelope = vpe_sign_hardware(
                prompt=prompt,
                scope=scope,
                issuer=getattr(args, "issuer", "cli:default"),
                audience=getattr(args, "audience", "agent:seal"),
                doc_sha256=getattr(args, "doc_sha256", ""),
                ttl_seconds=getattr(args, "ttl", 300),
                nonce=getattr(args, "nonce", None),
                counter=getattr(args, "counter", None),
                provider_name=hardware,
            )
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

        output_path = getattr(args, "output", None)
        if output_path:
            Path(output_path).write_text(envelope)
        else:
            print(envelope)
        return 0

    # Determine key path (software mode)
    key_path = Path(getattr(args, "private_key", str(SEAL_DIR / "seal_private.key")))
    if not key_path.exists():
        print(f"error: private key not found at {key_path} (run 'seal genkey' first)", file=sys.stderr)
        return 1

    private_key = key_path.read_bytes()

    # Check if multi-signature mode
    is_multi = getattr(args, "multi", False)
    threshold = getattr(args, "threshold", None)
    key_id = getattr(args, "key_id", "default")
    additional_sig = getattr(args, "additional_sig", None)

    if is_multi:
        existing = None
        if additional_sig:
            sig_path = Path(additional_sig)
            if not sig_path.exists():
                print(f"error: additional-sig envelope not found at {additional_sig}", file=sys.stderr)
                return 1
            existing = sig_path.read_text().strip()
            envelope = vpe_sign_multi(
                prompt=prompt or "",
                scope=scope,
                issuer=getattr(args, "issuer", "cli:default"),
                audience=getattr(args, "audience", "agent:seal"),
                doc_sha256=getattr(args, "doc_sha256", ""),
                ttl_seconds=getattr(args, "ttl", 300),
                nonce=getattr(args, "nonce", None),
                counter=getattr(args, "counter", None),
                threshold=threshold or 1,
                private_key=private_key,
                key_id=key_id,
                existing_envelope=existing,
            )
        else:
            envelope = vpe_sign_multi(
                prompt=prompt,
                scope=scope,
                issuer=getattr(args, "issuer", "cli:default"),
                audience=getattr(args, "audience", "agent:seal"),
                doc_sha256=getattr(args, "doc_sha256", ""),
                ttl_seconds=getattr(args, "ttl", 300),
                nonce=getattr(args, "nonce", None),
                counter=getattr(args, "counter", None),
                threshold=threshold or 1,
                private_key=private_key,
                key_id=key_id,
            )
    else:
        envelope = vpe_sign(
            prompt=prompt,
            scope=scope,
            issuer=getattr(args, "issuer", "cli:default"),
            audience=getattr(args, "audience", "agent:seal"),
            doc_sha256=getattr(args, "doc_sha256", ""),
            ttl_seconds=getattr(args, "ttl", 300),
            nonce=getattr(args, "nonce", None),
            counter=getattr(args, "counter", None),
            private_key=private_key,
        )

    output_path = getattr(args, "output", None)
    if output_path:
        Path(output_path).write_text(envelope)
    else:
        print(envelope)
    return 0


def cmd_verify(args) -> int:
    """Read a VPE envelope and verify it."""
    envelope_str = getattr(args, "envelope_file", None)
    if envelope_str:
        envelope_str = Path(envelope_str).read_text().strip()
    else:
        envelope_str = sys.stdin.read().strip()

    if not envelope_str:
        print("error: no envelope provided", file=sys.stderr)
        return 1

    is_multi = getattr(args, "multi", False)

    if is_multi:
        public_keys_path = getattr(args, "public_keys", None)
        if not public_keys_path:
            print("error: --public-keys is required in multi-sig mode", file=sys.stderr)
            return 1

        pk_path = Path(public_keys_path)
        if not pk_path.exists():
            print(f"error: public keys file not found at {public_keys_path}", file=sys.stderr)
            return 1

        try:
            keys_raw = json.loads(pk_path.read_text())
        except json.JSONDecodeError as e:
            print(f"error: invalid public keys JSON: {e}", file=sys.stderr)
            return 1

        public_keys = {}
        for kid, hex_val in keys_raw.items():
            try:
                public_keys[kid] = bytes.fromhex(hex_val)
            except ValueError:
                print(f"error: invalid hex for key_id {kid!r}", file=sys.stderr)
                return 1

        result = vpe_verify_multi(envelope_str, public_keys=public_keys)
    else:
        key_path = Path(getattr(args, "public_key", str(SEAL_DIR / "seal_public.key")))
        if not key_path.exists():
            print(f"error: public key not found at {key_path}", file=sys.stderr)
            return 1

        public_key = key_path.read_bytes()
        sig_algorithm = getattr(args, "sig_algorithm", SIG_ALG_ED25519)
        if sig_algorithm == SIG_ALG_ED25519:
            result = vpe_verify(envelope_str, public_key=public_key)
        else:
            result = vpe_verify_hardware(envelope_str, public_key=public_key,
                                         sig_algorithm=sig_algorithm)

    json_output = getattr(args, "json_output", True)
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print("valid" if result.get("valid") else "invalid")

    return 0 if result.get("valid") else 1


# ---------------------------------------------------------------------------
# Key lifecycle CLI commands
# ---------------------------------------------------------------------------


def _status_label(status: str) -> str:
    labels = {
        STATUS_ACTIVE: "active",
        STATUS_EXPIRING: "expiring",
        STATUS_RETIRED: "retired",
        STATUS_REVOKED: "revoked",
    }
    return labels.get(status, status)


def cmd_key_list(args) -> int:
    km = KeyManager()
    status_filter = getattr(args, "status", None)
    keys = km.list_keys(status=status_filter)

    if not keys:
        print("(no keys registered)")
        return 0

    active_kid = km.get_active_key()
    active_kid = active_kid["kid"] if active_kid else None

    print(f"{'KID':<36} {'FINGERPRINT':<14} {'STATUS':<10} {'EXPIRES':<14} {'ROTATED':<14}")
    print("-" * 88)
    for k in keys:
        kid = k["kid"]
        fp = k["fingerprint"]
        status = _status_label(k["status"])
        marker = " <-- active" if kid == active_kid else ""
        expires = time.strftime("%Y-%m-%d", time.gmtime(k["not_after"])) if k["not_after"] else "never"
        rotated = time.strftime("%Y-%m-%d", time.gmtime(k["rotated_at"])) if k["rotated_at"] else "-"
        revoked = ""
        if k["status"] == STATUS_REVOKED and k["revoke_reason"]:
            revoked = f"  ({k['revoke_reason']})"
        print(f"{kid:<36} {fp:<14} {status:<10} {expires:<14} {rotated:<14}{marker}{revoked}")
    return 0


def cmd_key_rotate(args) -> int:
    km = KeyManager()
    old_key = km.get_active_key()
    new_key = km.rotate_key()
    if old_key:
        old_kid = old_key["kid"]
        print(f"retired:  {old_kid} ({old_key['fingerprint']})")
    print(f"active:   {new_key['kid']} ({new_key['fingerprint']})")
    print(f"expires:  {time.strftime('%Y-%m-%d', time.gmtime(new_key['not_after']))}")
    return 0


def cmd_key_revoke(args) -> int:
    kid = args.kid
    reason = getattr(args, "reason", "")
    km = KeyManager()
    key = km.get_key(kid)
    if key is None:
        print(f"error: no key found with id {kid!r}", file=sys.stderr)
        return 1
    if key["status"] == STATUS_REVOKED:
        print(f"key {kid} is already revoked")
        return 0
    result = km.revoke_key(kid, reason=reason)
    if result["ok"]:
        print(f"revoked:  {kid} ({key['fingerprint']})")
        if reason:
            print(f"reason:   {reason}")
        if result["rotated"]:
            new_key = km.get_key(result["new_kid"])
            print(f"active:   {result['new_kid']} ({new_key['fingerprint']})")
            print("note:     revoked key was active — auto-rotated a replacement")
        return 0
    print(f"error: failed to revoke key {kid!r}", file=sys.stderr)
    return 1


def cmd_key_daemon(args) -> int:
    try:
        KeyManager.run_rotation_daemon(
            db_path=getattr(args, "db", None),
            days_before=args.days_before,
            interval_seconds=args.interval,
            once=args.once,
        )
    except KeyboardInterrupt:
        print("\n[seal-rotator] stopped by signal")
    return 0


# ---------------------------------------------------------------------------
# Secrets Broker CLI commands
# ---------------------------------------------------------------------------


def _open_store(args) -> CredentialStore:
    return CredentialStore(args.store)


def _open_audit(args) -> AuditLog:
    return AuditLog(args.audit)


def _cmd_secrets(args) -> int:
    cmd = args.secrets_command
    if cmd in {"add", "get", "delete"} and not _valid_label(args.label):
        print(f"error: invalid label {args.label!r}", file=sys.stderr)
        return 2
    store = _open_store(args)
    audit = _open_audit(args)
    caller = f"cli:{os.environ.get('USER', 'unknown')}"
    if cmd == "add":
        store.set(args.label, args.value)
        audit.log_access(args.label, caller, action="set")
        print(f"stored credential {args.label!r}")
        return 0
    if cmd == "get":
        value = store.get(args.label)
        if value is None:
            audit.log_denial(args.label, caller)
            print(f"error: no credential named {args.label!r}", file=sys.stderr)
            return 1
        audit.log_access(args.label, caller, action="get")
        print(GET_WARNING, file=sys.stderr)
        print(value)
        return 0
    if cmd == "list":
        labels = store.list_labels()
        for label in labels:
            print(label)
        if not labels:
            print("(no credentials stored)", file=sys.stderr)
        return 0
    if cmd == "delete":
        removed = store.delete(args.label)
        audit.log_access(args.label, caller, action="delete")
        if removed:
            print(f"deleted credential {args.label!r}")
            return 0
        print(f"error: no credential named {args.label!r}", file=sys.stderr)
        return 1
    return 2


def _cmd_audit(args) -> int:
    audit = _open_audit(args)
    entries = audit.query(status=args.status, since=args.since, limit=args.tail)
    if not entries:
        print("(no audit entries)", file=sys.stderr)
        return 0
    for entry in entries:
        ts = entry.get("timestamp", "?")
        result = entry.get("result", "?")
        reason = entry.get("reason")
        if entry.get("type") == "vpe_verification":
            digest = entry.get("envelope_hash", "?")
            if len(digest) > 16:
                digest = digest[:16] + "..."
            issuer = entry.get("issuer", "?")
            audience = entry.get("audience", "?")
            line = f"{ts}  {result:<8} {digest:<19} {issuer:<18} -> {audience}"
        else:
            action = entry.get("action", "?")
            label = entry.get("label", "?")
            caller = entry.get("caller", "?")
            line = f"{ts}  {result:<8} {action:<7} {label:<24} {caller}"
        if reason:
            line += f"  ({reason})"
        print(line)
    return 0


# ---------------------------------------------------------------------------
# Parser builder
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seal",
        description="Seal \u2014 Verified Prompt Envelope Protocol & AI Agent Security.",
    )
    parser.add_argument(
        "--store", default=str(DEFAULT_STORE_PATH),
        help=f"path to the encrypted credential store (default: {DEFAULT_STORE_PATH})",
    )
    parser.add_argument(
        "--audit", default=str(DEFAULT_AUDIT_PATH),
        help=f"path to the audit log (default: {DEFAULT_AUDIT_PATH})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- genkey ---
    sub.add_parser("genkey", help="generate Ed25519 key pair")

    # --- sign ---
    p_sign = sub.add_parser("sign", help="sign a prompt and output a VPE envelope")
    p_sign.add_argument("prompt", nargs="*", help="prompt text (omit to read from stdin)")
    p_sign.add_argument("--stdin", action="store_true", help="read prompt from stdin")
    p_sign.add_argument("--private-key", help="path to private key file")
    p_sign.add_argument("--scope", help="scope JSON object")
    p_sign.add_argument("--issuer", help="issuer identity (default: cli:default)")
    p_sign.add_argument("--audience", help="audience agent (default: agent:seal)")
    p_sign.add_argument("--doc-sha256", help="SHA-256 of bound document")
    p_sign.add_argument("--ttl", type=int, default=300, help="TTL in seconds (default: 300)")
    p_sign.add_argument("--nonce", help="explicit nonce")
    p_sign.add_argument("--counter", type=int, help="monotonic counter value")
    p_sign.add_argument("--hardware", choices=["yubikey", "tpm", "enclave"],
                        help="use hardware-backed key")
    p_sign.add_argument("--multi", action="store_true", help="use multi-signature envelope")
    p_sign.add_argument("--threshold", type=int, default=None,
                        help="N-of-M threshold for multi-sig (default: 1)")
    p_sign.add_argument("--key-id", default="default",
                        help="signer key identifier")
    p_sign.add_argument("--additional-sig",
                        help="path to existing multi-sig envelope to append signature to")

    # --- verify ---
    p_verify = sub.add_parser("verify", help="verify a VPE envelope from stdin")
    p_verify.add_argument("--public-key", help="path to public key file")
    p_verify.add_argument("--sig-algorithm", default=SIG_ALG_ED25519,
                          choices=[SIG_ALG_ED25519, SIG_ALG_ECDSA_P256],
                          help="signature algorithm (default: ed25519)")
    p_verify.add_argument("--multi", action="store_true", help="use multi-sig verification")
    p_verify.add_argument("--public-keys",
                          help="path to JSON file mapping key_id->hex_public_key")

    # --- key ---
    p_key = sub.add_parser("key", help="manage signing keys")
    key_sub = p_key.add_subparsers(dest="key_command", required=True)
    p_key_list = key_sub.add_parser("list", help="list all managed keys")
    p_key_list.add_argument("--status", choices=["active", "retired", "revoked"],
                            help="filter by key status")
    key_sub.add_parser("rotate", help="rotate the active signing key")
    p_key_revoke = key_sub.add_parser("revoke", help="revoke a key by ID")
    p_key_revoke.add_argument("kid", help="key ID to revoke")
    p_key_revoke.add_argument("--reason", help="optional revocation reason")
    p_key_daemon = key_sub.add_parser("daemon", help="run the key rotation daemon")
    p_key_daemon.add_argument("--once", action="store_true", help="check once and exit")
    p_key_daemon.add_argument("--days-before", type=int, default=30)
    p_key_daemon.add_argument("--interval", type=int, default=3600)
    p_key_daemon.add_argument("--db", help="path to key database")

    # --- hardware ---
    p_hw = sub.add_parser("hardware", help="manage hardware security providers")
    hw_sub = p_hw.add_subparsers(dest="hardware_command", required=True)
    hw_sub.add_parser("list", help="list available HSM providers")

    # --- secrets ---
    secrets = sub.add_parser("secrets", help="manage stored credentials")
    secrets_sub = secrets.add_subparsers(dest="secrets_command", required=True)
    p_add = secrets_sub.add_parser("add", help="store a credential")
    p_add.add_argument("label")
    p_add.add_argument("value")
    p_get = secrets_sub.add_parser("get", help="print a credential to stdout")
    p_get.add_argument("label")
    secrets_sub.add_parser("list", help="list credential labels")
    p_del = secrets_sub.add_parser("delete", help="remove a credential")
    p_del.add_argument("label")

    # --- audit ---
    p_audit = sub.add_parser("audit", help="query the verification audit log")
    p_audit.add_argument("--tail", type=int, default=20,
                         help="number of recent entries (default: 20)")
    p_audit.add_argument("--since",
                         help="ISO timestamp filter (e.g. '2026-06-08T09:00:00')")
    p_audit.add_argument("--status", choices=["valid", "invalid", "expired"],
                         help="filter by verification result")
    # --- disable ---
    sub.add_parser("disable", help="disable VPE middleware")
    # --- rollback ---
    p_rollback = sub.add_parser("rollback", help="remove VPE traces from Hermes config")
    p_rollback.add_argument("--clean-keys", action="store_true",
                            help="also remove VPE key files")
    # --- status ---
    sub.add_parser("status", help="show current VPE integration status")

    # --- fuzz ---
    p_fuzz = sub.add_parser("fuzz", help="run EPD pattern mutation fuzzer benchmark")
    p_fuzz.add_argument("--count", type=int, default=1000,
                        help="minimum mutations to generate (default: 1000)")
    p_fuzz.add_argument("--seed", type=int, default=42,
                        help="random seed (default: 42)")
    p_fuzz.add_argument("--evasions", type=int, default=20,
                        help="evasion examples to show (default: 20)")
    p_fuzz.add_argument("--json", action="store_true",
                        help="output raw JSON")

    return parser


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    _ensure_seal_dir()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "genkey":
        return cmd_genkey(args)
    elif args.command == "sign":
        return cmd_sign(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "key":
        if args.key_command == "list":
            return cmd_key_list(args)
        elif args.key_command == "rotate":
            return cmd_key_rotate(args)
        elif args.key_command == "revoke":
            return cmd_key_revoke(args)
        elif args.key_command == "daemon":
            return cmd_key_daemon(args)
        return 2
    elif args.command == "hardware":
        if args.hardware_command == "list":
            return cmd_hardware_list(args)
        return 2
    elif args.command == "secrets":
        return _cmd_secrets(args)
    elif args.command == "audit":
        return _cmd_audit(args)
    elif args.command == "disable":
        report = cmd_disable()
        report.print_report("VPE Disable \u2014 Results")
        return 0 if report.ok() else 1
    elif args.command == "rollback":
        report = cmd_rollback(clean_keys=args.clean_keys)
        report.print_report("VPE Rollback \u2014 Results")
        return 0 if report.ok() else 1
    elif args.command == "status":
        report = cmd_status()
        report.print_report("VPE Integration Status")
        return 0
    elif args.command == "fuzz":
        from seal.epd.fuzzer import main as fuzz_main
        fuzz_argv = [
            "--count", str(args.count),
            "--seed", str(args.seed),
            "--evasions", str(args.evasions),
        ]
        if args.json:
            fuzz_argv.append("--json")
        return fuzz_main(fuzz_argv)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
