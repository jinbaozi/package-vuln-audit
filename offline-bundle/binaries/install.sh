#!/usr/bin/env bash
# Stage host's user-local tools into offline-bundle/binaries/.
#
# This script should be run on the HOST before building the sandbox runtime
# image. It copies pre-installed tools from ~/.pvas/bin and ~/.local/bin,
# then downloads Python wheels for cppcheck/semgrep and their transitive
# dependencies. The build-runtime.sh script later builds the image with
# these artifacts.
#
# Usage:
#     bash offline-bundle/binaries/install.sh [--force]
#
# Options:
#     --force    Re-download wheels and re-copy binaries even if they exist
#
# After running, execute:
#     bash sandbox/scripts/build-runtime.sh

set -euo pipefail

SKILL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="$SKILL_ROOT/offline-bundle"
WHEELS="$BUNDLE/python/wheels"
BINARIES="$BUNDLE/binaries"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

mkdir -p "$BINARIES" "$WHEELS"

echo "[install] skill=$SKILL_ROOT"
echo "[install] bundle=$BUNDLE"
echo "[install] force=$FORCE"

# ---------------------------------------------------------------------------
# 1. Static binaries from host user-local installs
# ---------------------------------------------------------------------------
copy_binary() {
    local src="$1"
    local name="$(basename "$src")"
    local dst="$BINARIES/$name"
    if [ -e "$dst" ] && [ "$FORCE" != "1" ]; then
        echo "[install] SKIP existing: $name"
        return 0
    fi
    if [ ! -x "$src" ]; then
        echo "[install] WARN missing: $src (skipping)"
        return 0
    fi
    cp -f "$src" "$dst"
    chmod 0755 "$dst"
    echo "[install] staged binary: $name ($(stat -c %s "$dst") bytes)"
}

echo "[install] === Stage 1: static binaries ==="
for src in \
    "$HOME/.pvas/bin/osv-scanner" \
    "$HOME/.local/bin/rg" \
    "$HOME/.local/bin/cppcheck" \
    "$HOME/.local/bin/semgrep"; do
    copy_binary "$src"
done

# ---------------------------------------------------------------------------
# 2. Python wheels with transitive deps
# ---------------------------------------------------------------------------
echo "[install] === Stage 2: Python wheels ==="
if [ "$FORCE" = "1" ] || [ -z "$(ls -A "$WHEELS" 2>/dev/null)" ]; then
    pip3 download --dest "$WHEELS/" semgrep cppcheck 2>&1 | tail -3 || \
        pip3 download --no-deps --dest "$WHEELS/" semgrep cppcheck
    pip3 download --no-deps --dest "$WHEELS/" "importlib_metadata<8.8" 2>&1 | tail -2 || true
else
    echo "[install] wheels already present; use --force to re-download"
fi

# ---------------------------------------------------------------------------
# 3. Deduplicate wheels
# ---------------------------------------------------------------------------
echo "[install] === Stage 3: deduplicate wheels ==="
python3 "$SKILL_ROOT/sandbox/scripts/dedupe-wheels.py" "$WHEELS"

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
echo ""
echo "[install] === Summary ==="
echo "binaries: $(ls -1 "$BINARIES" 2>/dev/null | wc -l) files"
ls -la "$BINARIES" | tail -n +2 | awk '{print "  " $NF}'
echo ""
echo "wheels: $(ls -1 "$WHEELS" 2>/dev/null | wc -l) files"
echo ""
echo "[install] Done. Next: bash sandbox/scripts/build-runtime.sh"