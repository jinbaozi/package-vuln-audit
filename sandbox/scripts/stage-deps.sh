#!/usr/bin/env bash
# Stage dependencies into offline-bundle/ before docker build.
# Idempotent: re-runnable; overwrites with fresh copies from host.
#
# What it does:
#   1. Copy static binaries from host's ~/.pvas/bin and ~/.local/bin
#   2. Download python wheels (with transitive deps) for cppcheck, semgrep
#   3. Deduplicate wheels by version (keep newest)
#
# Run on the HOST before docker build.
set -euo pipefail

SKILL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="$SKILL_ROOT/offline-bundle"
mkdir -p "$BUNDLE/binaries" "$BUNDLE/python/wheels"

echo "[stage-deps] skill=$SKILL_ROOT bundle=$BUNDLE"

# ---------------------------------------------------------------------------
# 1. Static binaries from host user-local installs
# ---------------------------------------------------------------------------
for src in \
    "$HOME/.pvas/bin/osv-scanner" \
    "$HOME/.local/bin/rg" \
    "$HOME/.local/bin/cppcheck" \
    "$HOME/.local/bin/semgrep"; do
    if [ -x "$src" ]; then
        name="$(basename "$src")"
        cp -f "$src" "$BUNDLE/binaries/$name"
        chmod 0755 "$BUNDLE/binaries/$name"
        echo "[stage-deps] staged binary: $name ($(stat -c %s "$BUNDLE/binaries/$name") bytes)"
    else
        echo "[stage-deps] SKIP missing: $src"
    fi
done

# ---------------------------------------------------------------------------
# 2. Python wheels with transitive dependencies
# ---------------------------------------------------------------------------
echo "[stage-deps] downloading python wheels..."
if pip3 download --dest "$BUNDLE/python/wheels/" semgrep cppcheck 2>&1 | tail -3; then
    echo "[stage-deps] wheels downloaded"
else
    echo "[stage-deps] WARN: pip download failed; trying --no-deps fallback"
    pip3 download --no-deps --dest "$BUNDLE/python/wheels/" semgrep cppcheck || true
fi

# Ensure importlib_metadata<8.8 is available (semgrep deps need it)
pip3 download --no-deps --dest "$BUNDLE/python/wheels/" "importlib_metadata<8.8" 2>&1 | tail -2 || true

# ---------------------------------------------------------------------------
# 3. Deduplicate wheels
# ---------------------------------------------------------------------------
echo "[stage-deps] deduplicating wheels..."
python3 "$SKILL_ROOT/sandbox/scripts/dedupe-wheels.py" "$BUNDLE/python/wheels"

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
echo ""
echo "[stage-deps] binaries:"
ls -la "$BUNDLE/binaries/" | tail -n +2
echo ""
echo "[stage-deps] wheels count: $(ls "$BUNDLE/python/wheels/" 2>/dev/null | wc -l)"
echo "[stage-deps] done"