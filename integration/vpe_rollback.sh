#!/usr/bin/env bash
# VPE Rollback Script — Remove all VPE/Hermes integration traces
#
# Usage:
#   ./vpe_rollback.sh              # Dry-run (show what would happen)
#   ./vpe_rollback.sh --apply      # Execute rollback
#   ./vpe_rollback.sh --apply --clean-keys   # Also remove VPE key files
#
# This script delegates to `seal rollback` for the Python logic and
# provides a quick terminal-friendly wrapper with confirmation prompts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEAL_CLI="${SCRIPT_DIR}/../seal/cli.py"
HERMES_CONFIG="${HOME}/.hermes/config.yaml"
SEAL_AUDIT="${HOME}/.seal/audit.jsonl"
VPE_KEYS="${HOME}/.hermes/vpe-keys"

APPLY=false
CLEAN_KEYS=false

for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=true ;;
    --clean-keys) CLEAN_KEYS=true ;;
    --help|-h)
      echo "Usage: $0 [--apply] [--clean-keys]"
      echo ""
      echo "  (no flag)   Dry-run — show current state and what would be done"
      echo "  --apply     Execute the rollback"
      echo "  --clean-keys  Also archive and remove VPE keys (requires --apply)"
      exit 0
      ;;
  esac
done

echo "═══════════════════════════════════════════════════"
echo "  VPE Rollback Script"
echo "═══════════════════════════════════════════════════"
echo ""

# ── Step 1: Show current state ──
echo "▸ Current VPE status:"
if [ -f "$HERMES_CONFIG" ]; then
  if grep -q "vpe_enabled" "$HERMES_CONFIG" 2>/dev/null; then
    VPE_LINE=$(grep -A1 "vpe:" "$HERMES_CONFIG" | head -3)
    echo "  VPE config section:     PRESENT"
    echo "  $VPE_LINE"
  else
    echo "  VPE config section:     NOT PRESENT"
  fi
else
  echo "  Hermes config:          NOT FOUND at $HERMES_CONFIG"
fi

if [ -f "$SEAL_AUDIT" ]; then
  COUNT=$(wc -l < "$SEAL_AUDIT" 2>/dev/null || echo 0)
  echo "  Audit log entries:      $COUNT"
else
  echo "  Audit log:              NOT PRESENT"
fi

if [ -d "$VPE_KEYS" ]; then
  KEY_COUNT=$(ls -1 "$VPE_KEYS" 2>/dev/null | wc -l)
  echo "  VPE key files:          $KEY_COUNT at $VPE_KEYS"
else
  echo "  VPE key files:          NOT PRESENT"
fi

echo ""

# ── Step 2: What will be done ──
echo "▸ Rollback will:"
echo "  1. Back up Hermes config to config.yaml.vpe-<timestamp>"
echo "  2. Archive audit log to ~/.seal/archive/audit-<timestamp>.jsonl"
echo "  3. Remove security.vpe section from Hermes config.yaml"
echo "  4. Remove VPE-related hooks from hooks.pre_tool_call"
if [ "$CLEAN_KEYS" = true ]; then
  echo "  5. Archive and remove VPE key files"
fi
echo ""

echo "▸ Preserved (no data loss):"
echo "  • Audit log — archived and left in place"
echo "  • Credential store — untouched (~/.seal/credentials*.enc)"
echo "  • Seal directory — left intact (~/.seal/)"
echo "  • Division memory — not affected"
echo ""

# ── Step 3: Execute or dry-run ──
if [ "$APPLY" = true ]; then
  echo "▸ Executing rollback..."
  echo ""

  CLEAN_ARG=""
  if [ "$CLEAN_KEYS" = true ]; then
    CLEAN_ARG=" --clean-keys"
  fi

  cd "$SCRIPT_DIR/.."
  python3 -m seal rollback${CLEAN_ARG}

  echo ""
  echo "✓ Rollback complete. Re-run with --clean-keys to also remove keys."
  echo "  Verify: seal status"
else
  echo "▸ DRY RUN — no changes made."
  echo "  Run with --apply to execute."
  echo ""
  echo "  To verify current state:  python3 -m seal status"
  echo "  To disable (not remove):  python3 -m seal disable"
fi

echo ""
