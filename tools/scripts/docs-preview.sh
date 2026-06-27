#!/usr/bin/env bash
#
# Preview the documentation website (gears-rust-web-docs) with the LOCAL
# docs/web-docs content from this gears-rust checkout — including uncommitted edits.
#
# The web docs site lives in a separate repo (TypeScript/Astro). This script
# clones it into a gitignored cache dir, then runs its dev server pointed at the
# local content via GEARS_RUST_PATH. The site's `predev` hook syncs the content.
#
# Usage: make docs-preview   (or: bash tools/scripts/docs-preview.sh)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CACHE_DIR="${GEARS_DOCS_CACHE:-$REPO_ROOT/.web-docs-preview}"
DOCS_REPO="${GEARS_DOCS_REPO:-https://github.com/constructorfabric/gears-rust-web-docs.git}"

# --- Prerequisite: Node >= 22.13 (required by Astro / the docs site) ---
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node not found. Install Node.js >= 22.13 to preview the docs site." >&2
  exit 1
fi

# Try to switch to Node 22 via nvm if current version is too old
node_major="$(node -p 'process.versions.node.split(".")[0]')"
node_minor="$(node -p 'process.versions.node.split(".")[1]')"
if [ "$node_major" -lt 22 ] || { [ "$node_major" -eq 22 ] && [ "$node_minor" -lt 13 ]; }; then
  if command -v nvm >/dev/null 2>&1 || [ -s "$HOME/.nvm/nvm.sh" ]; then
    echo "==> Current Node $(node -v) is too old. Switching to Node 22 via nvm..."
    # shellcheck source=/dev/null
    [ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh"
    nvm use 22 >/dev/null 2>&1 || nvm use 22
    echo "==> Now using Node $(node -v)"
  else
    echo "ERROR: Node $(node -v) is too old (need >= 22.13). Install nvm or upgrade Node.js." >&2
    exit 1
  fi
fi

# --- Clone or update the docs site into the cache dir ---
if [ -d "$CACHE_DIR/.git" ]; then
  echo "==> Updating cached docs site in $CACHE_DIR"
  git -C "$CACHE_DIR" pull --ff-only || echo "WARNING: could not fast-forward cached docs site; using existing checkout." >&2
else
  echo "==> Cloning docs site into $CACHE_DIR"
  git clone --depth 1 "$DOCS_REPO" "$CACHE_DIR"
fi

cd "$CACHE_DIR"

# --- Install deps and run dev against the local content ---
if command -v pnpm >/dev/null 2>&1; then
  pnpm install
  echo "==> Starting docs site at http://localhost:4321 (content from $REPO_ROOT/docs/web-docs)"
  GEARS_RUST_PATH="$REPO_ROOT" BASE=/ pnpm dev
else
  npm install
  echo "==> Starting docs site at http://localhost:4321 (content from $REPO_ROOT/docs/web-docs)"
  GEARS_RUST_PATH="$REPO_ROOT" BASE=/ npm run dev
fi
