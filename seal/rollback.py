"""Rollback procedure for VPE/Hermes integration.

Supports two operations:
  - disable:  Single config toggle to disable VPE middleware (preserves config)
  - rollback: Full removal of all VPE-related entries from Hermes config
              with audit trail archival.

On rollback:
  - Audit trail is copied to ~/.seal/archive/ (never deleted in-place)
  - VPE keys are left in place (opt-in removal with --clean-keys)
  - Credential store is left untouched
  - Division memory episodes are preserved (read-only)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy path resolvers — resolved at call time, not import time.
# Supports SEAL_HOME and HERMES_HOME env var overrides.
# ---------------------------------------------------------------------------


def _resolve_seal_home() -> Path:
    """Resolve ~/.seal, with optional SEAL_HOME env override."""
    override = os.environ.get("SEAL_HOME")
    return Path(override) if override else Path.home() / ".seal"


def _resolve_hermes_home() -> Path:
    """Resolve ~/.hermes, with optional HERMES_HOME env override."""
    override = os.environ.get("HERMES_HOME")
    return Path(override) if override else Path.home() / ".hermes"


def _hermes_config() -> Path:
    return _resolve_hermes_home() / "config.yaml"


def _seal_dir() -> Path:
    return _resolve_seal_home()


def _seal_audit() -> Path:
    return _seal_dir() / "audit.jsonl"


def _seal_archive() -> Path:
    return _seal_dir() / "archive"


def _vpe_keys_hermes() -> Path:
    return _resolve_hermes_home() / "vpe-keys"


def _seal_backup_config() -> Path:
    return _hermes_config().with_name("config.yaml.vpe-backup")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict:
    """Load a YAML file, returning empty dict on missing/empty."""
    if not path.exists() or path.stat().st_size == 0:
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _dump_yaml(path: Path, data: dict) -> None:
    """Write a YAML file with safe_dump (no flow style, block mode)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Status Report
# ---------------------------------------------------------------------------


class RollbackReport:
    """Structured report of what the rollback / disable operation did."""

    def __init__(self) -> None:
        self.operations: list[str] = []
        self.preserved: list[str] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def op(self, msg: str) -> None:
        self.operations.append(msg)

    def keep(self, msg: str) -> None:
        self.preserved.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def err(self, msg: str) -> None:
        self.errors.append(msg)

    def ok(self) -> bool:
        return len(self.errors) == 0

    def print_report(self, title: str) -> None:
        """Print a formatted report."""
        sep = "─" * 60
        print()
        print(sep)
        print(f"  {title}")
        print(sep)
        if self.operations:
            print()
            print("  Operations:")
            for op in self.operations:
                print(f"    ✓ {op}")
        if self.preserved:
            print()
            print("  Preserved (no data loss):")
            for p in self.preserved:
                print(f"    • {p}")
        if self.warnings:
            print()
            print("  Warnings:")
            for w in self.warnings:
                print(f"    ⚠ {w}")
        if self.errors:
            print()
            print("  Errors:")
            for e in self.errors:
                print(f"    ✗ {e}")
        print(sep)
        print()


def _report_to_dict(report: RollbackReport) -> dict:
    return {
        "operations": report.operations,
        "preserved": report.preserved,
        "warnings": report.warnings,
        "errors": report.errors,
        "ok": report.ok(),
    }


# ---------------------------------------------------------------------------
# Disable — single config toggle
# ---------------------------------------------------------------------------


def cmd_disable() -> RollbackReport:
    """Set security.vpe.vpe_enabled: false in Hermes config.

    This is the single-config-toggle to deactivate VPE middleware
    without removing any configuration or data.
    """
    report = RollbackReport()

    if not _hermes_config().exists():
        report.err(f"Hermes config not found at {_hermes_config()}")
        return report

    try:
        config = _load_yaml(_hermes_config())
    except Exception as e:
        report.err(f"Failed to load {_hermes_config()}: {e}")
        return report

    # Navigate/create security → vpe
    security = config.setdefault("security", {})
    vpe = security.setdefault("vpe", {})

    before = vpe.get("vpe_enabled", None)
    vpe["vpe_enabled"] = False
    vpe["vpe_mode"] = vpe.get("vpe_mode", "audit")

    # Backup original config before writing
    try:
        _backup_config(report)
    except Exception as e:
        report.err(f"Config backup failed: {e}")
        # Don't return — still try to write the toggle

    try:
        _dump_yaml(_hermes_config(), config)
        if before is False:
            report.op("VPE was already disabled (vpe_enabled: false)")
        elif before is None:
            report.op("Created security.vpe section with vpe_enabled: false")
        else:
            report.op(f"Toggled VPE from enabled={before} to vpe_enabled: false")
    except Exception as e:
        report.err(f"Failed to write {_hermes_config()}: {e}")

    report.keep("Audit log untouched — still at " + str(_seal_audit()))
    report.keep("VPE keys untouched — still at " + str(_vpe_keys_hermes()))
    report.keep("Credential store untouched — still at " + str(_seal_dir()))

    return report


# ---------------------------------------------------------------------------
# Rollback — full removal of VPE from Hermes config
# ---------------------------------------------------------------------------


def _backup_config(report: RollbackReport) -> None:
    """Create a timestamped backup of Hermes config before modifying."""
    ts = _utcnow()
    backup = _hermes_config().with_name(f"config.yaml.vpe-{ts}")
    shutil.copy2(str(_hermes_config()), str(backup))
    report.op(f"Config backed up to {backup}")


def _archive_audit(report: RollbackReport) -> None:
    """Archive the audit log if it exists and has entries."""
    if not _seal_audit().exists():
        report.keep("No audit log found at " + str(_seal_audit()))
        return

    try:
        with open(_seal_audit()) as f:
            count = sum(1 for _ in f if _.strip())
    except Exception:
        logger.warning("Failed to read audit log", exc_info=True)
        count = 0

    if count == 0:
        report.keep("Audit log exists but is empty — nothing to archive")
        return

    ts = _utcnow()
    _seal_archive().mkdir(parents=True, exist_ok=True)
    archive_path = _seal_archive() / f"audit-{ts}.jsonl"
    shutil.copy2(str(_seal_audit()), str(archive_path))
    report.op(f"Audit log archived to {archive_path} ({count} entries)")
    report.keep("Original audit log at " + str(_seal_audit()) + " — preserved in place")


def _remove_vpe_from_config(report: RollbackReport) -> bool:
    """Remove the security.vpe section from Hermes config.yaml.

    Returns True if the section was found and removed.
    """
    if not _hermes_config().exists():
        report.err(f"Hermes config not found at {_hermes_config()}")
        return False

    try:
        config = _load_yaml(_hermes_config())
    except Exception as e:
        report.err(f"Failed to load {_hermes_config()}: {e}")
        return False

    # Navigate to security → vpe
    security = config.get("security")
    if not security or not isinstance(security, dict):
        report.op("No security section in Hermes config — nothing to remove")
        return False

    vpe = security.get("vpe")
    if vpe is None:
        report.op("No security.vpe section in Hermes config — nothing to remove")
        return False

    # Record what's being removed
    removed_keys = list(vpe.keys()) if isinstance(vpe, dict) else ["(whole section)"]
    del security["vpe"]

    # Clean up empty security section
    if not security:
        del config["security"]

    _dump_yaml(_hermes_config(), config)
    report.op(f"Removed security.vpe section ({', '.join(removed_keys)}) from {_hermes_config()}")
    return True


def _remove_vpe_hooks(report: RollbackReport) -> None:
    """Remove any VPE middleware hooks from Hermes hooks config.

    The hooks are in config.yaml under hooks.pre_tool_call.
    """
    if not _hermes_config().exists():
        return

    try:
        config = _load_yaml(_hermes_config())
    except Exception as e:
        report.err(f"Failed to load {_hermes_config()} for hook cleanup: {e}")
        return

    hooks = config.get("hooks")
    if not hooks or not isinstance(hooks, dict):
        return

    pre = hooks.get("pre_tool_call", [])
    if not isinstance(pre, list):
        return

    vpe_pattern = re.compile(r"vpe|hermes_vpe_middleware", re.IGNORECASE)
    original_count = len(pre)
    filtered = [h for h in pre if not (isinstance(h, dict) and vpe_pattern.search(str(h.get("command", ""))))]
    filtered = [h for h in filtered if not (isinstance(h, str) and vpe_pattern.search(h))]

    removed_count = original_count - len(filtered)
    if removed_count > 0:
        hooks["pre_tool_call"] = filtered
        _dump_yaml(_hermes_config(), config)
        report.op(f"Removed {removed_count} VPE-related hook(s) from hooks.pre_tool_call")

    # Check steer.sh and kill-switch.sh — these are standard Hermes hooks,
    # not VPE hooks. Don't remove them.


def cmd_rollback(clean_keys: bool = False, yes: bool = False) -> RollbackReport:
    """Full VPE rollback: remove all VPE traces from Hermes config.

    Args:
        clean_keys: If True, also remove VPE key directories.
        yes: If True, skip confirmation prompts.

    Returns:
        RollbackReport with details of what was done.
    """
    report = RollbackReport()

    # --- Phase 1: Backup ---
    print("Phase 1/4: Backing up Hermes config...")
    try:
        _backup_config(report)
    except Exception as e:
        report.err(f"Config backup failed: {e}")

    # --- Phase 2: Archive audit trail ---
    print("Phase 2/4: Archiving audit trail...")
    _archive_audit(report)

    # --- Phase 3: Remove VPE from config ---
    print("Phase 3/4: Removing VPE from Hermes config...")
    _remove_vpe_from_config(report)
    _remove_vpe_hooks(report)

    # --- Phase 4: Archival of VPE keys (preserve unless clean_keys) ---
    print("Phase 4/4: Handling VPE keys and seal directory...")
    if clean_keys:
        _clean_keys(report)
    else:
        _preserve_keys(report)

    # Final preservation summary
    report.keep("Audit log — archived and still present at " + str(_seal_audit()))
    report.keep("Credential store — untouched at " + str(_seal_dir() / "credentials.yaml.enc"))
    report.keep("Division memory episodes — read-only, not affected by rollback")

    return report


def _clean_keys(report: RollbackReport) -> None:
    """Remove VPE key directories."""
    hermes_keys_removed = False
    seal_keys_removed = False

    if _vpe_keys_hermes().exists():
        ts = _utcnow()
        archive = _vpe_keys_hermes().parent / f"vpe-keys-archive-{ts}"
        shutil.copytree(str(_vpe_keys_hermes()), str(archive), dirs_exist_ok=True)
        shutil.rmtree(str(_vpe_keys_hermes()))
        report.op(f"Hermes VPE keys archived to {archive} and removed")
        hermes_keys_removed = True

    if _seal_dir().exists() and list(_seal_dir().glob("seal_*.key")):
        ts = _utcnow()
        key_archive = _seal_dir() / f"keys-archive-{ts}"
        key_archive.mkdir(parents=True, exist_ok=True)
        for k in list(_seal_dir().glob("seal_*.key")):
            shutil.move(str(k), str(key_archive / k.name))
        report.op(f"Seal key files archived to {key_archive} and removed")
        seal_keys_removed = True

    if not hermes_keys_removed and not seal_keys_removed:
        report.op("No VPE key directories found to clean")


def _preserve_keys(report: RollbackReport) -> None:
    """Leave VPE keys in place for potential re-enablement."""
    if _vpe_keys_hermes().exists():
        count = len(list(_vpe_keys_hermes().iterdir()))
        report.keep(f"VPE keys at {_vpe_keys_hermes()} ({count} files) — left in place")
    if _seal_dir().exists():
        keys = list(_seal_dir().glob("seal_*.key"))
        if keys:
            report.keep(f"Seal keys at {_seal_dir()} ({len(keys)} files) — left in place")


# ---------------------------------------------------------------------------
# Status check — report current VPE state
# ---------------------------------------------------------------------------


def cmd_status() -> RollbackReport:
    """Report the current VPE integration status — what's enabled, what's present."""
    report = RollbackReport()

    # Check config
    if not _hermes_config().exists():
        report.err("Hermes config not found")
        return report

    try:
        config = _load_yaml(_hermes_config())
    except Exception as e:
        report.err(f"Failed to load config: {e}")
        return report

    security = config.get("security", {})
    vpe = security.get("vpe", None) if isinstance(security, dict) else None

    if vpe is not None and isinstance(vpe, dict):
        enabled = vpe.get("vpe_enabled", False)
        mode = vpe.get("vpe_mode", "audit")
        status_str = "ENABLED" if enabled else "DISABLED (toggle present)"
        report.op(f"VPE config section: present — {status_str} (mode: {mode})")
        for k, v in vpe.items():
            report.op(f"  {k}: {v}")
    else:
        report.op("VPE config section: not present in Hermes config")
        report.op("VPE middleware will not be loaded (default behaviour)")

    # Check hooks
    hooks = config.get("hooks", {})
    pre = hooks.get("pre_tool_call", []) if isinstance(hooks, dict) else []
    vpe_hooks = [h for h in pre if isinstance(h, dict) and "vpe" in str(h.get("command", "")).lower()]
    if vpe_hooks:
        report.op(f"VPE hooks in pre_tool_call: {len(vpe_hooks)} present")
        for h in vpe_hooks:
            report.op(f"  → {h.get('command', '?')}")
    else:
        report.op("VPE hooks in pre_tool_call: none")

    # Check keys
    hermes_keys = list(_vpe_keys_hermes().iterdir()) if _vpe_keys_hermes().exists() else []
    seal_keys = list(_seal_dir().glob("seal_*.key")) if _seal_dir().exists() else []
    report.op(f"Hermes VPE keys: {len(hermes_keys)} file(s) at {_vpe_keys_hermes()}")
    report.op(f"Seal keys: {len(seal_keys)} file(s) at {_seal_dir()}")

    # Show active signing key from KeyManager
    try:
        from seal.key_manager import KeyManager, STATUS_ACTIVE

        km = KeyManager()
        active = km.get_active_key()
        if active:
            fp = active["fingerprint"]
            expires = (
                time.strftime("%Y-%m-%d", time.gmtime(active["not_after"]))
                if active["not_after"]
                else "never"
            )
            report.op(
                f"Active signing key: {active['kid']}  "
                f"fingerprint={fp}  expires={expires}"
            )
        else:
            report.op("Active signing key: none (run 'seal genkey' to create one)")
    except Exception as e:
        report.op(f"Active signing key: error — {e}")

    # Check audit
    if _seal_audit().exists():
        try:
            with open(_seal_audit()) as f:
                count = sum(1 for _ in f if _.strip())
        except Exception:
            logger.warning("Failed to read audit log for status report", exc_info=True)
            count = 0
        report.op(f"Audit log: {count} entries at {_seal_audit()}")
    else:
        report.op("Audit log: not present")

    # Check archive
    if _seal_archive().exists():
        archives = sorted(_seal_archive().glob("audit-*.jsonl"))
        if archives:
            report.op(f"Archived audit logs: {len(archives)} file(s) in {_seal_archive()}")

    return report
