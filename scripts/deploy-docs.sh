#!/usr/bin/env bash
# Deploy documentation to GitHub Pages
#
# Prerequisites:
#   1. GitHub repo exists at https://github.com/nousresearch/seal
#   2. GitHub Pages enabled in repo Settings > Pages (source: GitHub Actions)
#   3. Git remote configured: git remote add origin git@github.com:nousresearch/seal.git
#
# Usage:
#   ./scripts/deploy-docs.sh         # Build and push (triggers GitHub Actions deploy)
#   ./scripts/deploy-docs.sh --serve  # Preview locally first

set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--serve" ]; then
    echo "→ Previewing docs at http://localhost:8000"
    uv run mkdocs serve
    exit 0
fi

echo "→ Building site..."
uv run mkdocs build --strict

echo "→ Committing build (if needed)..."
git add site/ -f 2>/dev/null || true

echo "→ Pushing to GitHub (triggers GitHub Actions)..."
git push origin master

echo "→ Done! Site will be at https://nousresearch.github.io/seal"
echo "  (check Actions tab for deployment progress)"
