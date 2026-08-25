#!/usr/bin/env bash
# Fail-fast rootdir guard for seal's canonical test entrypoint.
#
# Running the suite from any cwd other than the repo root (e.g. $HOME) makes
# pytest pick a bogus rootdir and collect nothing meaningful, silently
# producing a vacuous "green". This wrapper refuses to start in that
# situation; all other pytest args pass through unchanged.
#
# Usage:
#   bash scripts/test.sh [pytest args...]   # from the repo root
#   make test-python                        # delegates through this wrapper

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
CWD="$(pwd -P)"

if [ "$CWD" != "$REPO_ROOT" ]; then
    echo "refusing: run from the repo root (cwd=$CWD, repo root=$REPO_ROOT)" >&2
    exit 2
fi

exec python3 -m pytest "$@"
