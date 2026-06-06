"""Command-line interface for the Seal Secrets Broker.

    seal secrets add <label> <value>
    seal secrets get <label>
    seal secrets list
    seal secrets delete <label>
    seal audit
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from seal.audit import AuditLog
from seal.credential_store import CredentialStore

SEAL_DIR = Path.home() / ".seal"
DEFAULT_STORE_PATH = SEAL_DIR / "credentials.yaml.enc"
DEFAULT_AUDIT_PATH = SEAL_DIR / "audit.jsonl"

LABEL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

GET_WARNING = "# WARNING: printing secret to terminal — may be in shell history"


def _ensure_seal_dir() -> None:
    SEAL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        SEAL_DIR.chmod(0o700)
    except OSError:  # pragma: no cover
        pass


def _valid_label(label: str) -> bool:
    return bool(LABEL_RE.match(label))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seal",
        description="Seal Secrets Broker — keep credentials out of model context.",
    )
    parser.add_argument(
        "--store",
        default=str(DEFAULT_STORE_PATH),
        help=f"path to the encrypted credential store (default: {DEFAULT_STORE_PATH})",
    )
    parser.add_argument(
        "--audit",
        default=str(DEFAULT_AUDIT_PATH),
        help=f"path to the audit log (default: {DEFAULT_AUDIT_PATH})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    secrets = sub.add_parser("secrets", help="manage stored credentials")
    secrets_sub = secrets.add_subparsers(dest="secrets_command", required=True)

    p_add = secrets_sub.add_parser("add", help="store a credential")
    p_add.add_argument("label")
    p_add.add_argument("value")

    p_get = secrets_sub.add_parser("get", help="print a credential to stdout")
    p_get.add_argument("label")

    secrets_sub.add_parser("list", help="list credential labels (not values)")

    p_del = secrets_sub.add_parser("delete", help="remove a credential")
    p_del.add_argument("label")

    sub.add_parser("audit", help="show the last 20 audit entries")

    return parser


def _open_store(args) -> CredentialStore:
    return CredentialStore(args.store)


def _open_audit(args) -> AuditLog:
    return AuditLog(args.audit)


def _cmd_secrets(args) -> int:
    cmd = args.secrets_command

    if cmd in {"add", "get", "delete"} and not _valid_label(args.label):
        print(
            f"error: invalid label {args.label!r}: must match {LABEL_RE.pattern}",
            file=sys.stderr,
        )
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

    return 2  # pragma: no cover - argparse guards this


def _cmd_audit(args) -> int:
    audit = _open_audit(args)
    entries = audit.query(limit=20)
    if not entries:
        print("(no audit entries)", file=sys.stderr)
        return 0
    for entry in entries:
        ts = entry.get("timestamp", "?")
        result = entry.get("result", "?")
        action = entry.get("action", "?")
        label = entry.get("label", "?")
        caller = entry.get("caller", "?")
        line = f"{ts}  {result:<8} {action:<7} {label:<24} {caller}"
        reason = entry.get("reason")
        if reason:
            line += f"  ({reason})"
        print(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    _ensure_seal_dir()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "secrets":
        return _cmd_secrets(args)
    if args.command == "audit":
        return _cmd_audit(args)
    parser.error("unknown command")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
