#!/usr/bin/env bash
# Single-shot build pipeline for PVAS sandbox runtime image.
#
# Pipeline:
#   1. preflight (audit-image-prereqs.py --strict)
#   2. stage-deps (auto-fill missing wheels/binaries if preflight failed)
#   3. import base image (if missing)
#   4. docker build --no-cache (uses canonical Dockerfile.runtime)
#   5. verify-image (every tool in deps.json must PASS)
#
# If any step fails, exit code 1.

set -euo pipefail

SKILL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKERFILE="$SKILL_ROOT/sandbox/images/Dockerfile.runtime"

if [ ! -f "$DOCKERFILE" ]; then
    echo "[build-runtime] FATAL: $DOCKERFILE not found" >&2
    exit 1
fi

cd "$SKILL_ROOT"

echo "[build-runtime] === preflight ==="
if ! python3 sandbox/scripts/audit-image-prereqs.py --strict; then
    echo "[build-runtime] preflight failed; running stage-deps to recover..."
    bash sandbox/scripts/stage-deps.sh
    python3 sandbox/scripts/audit-image-prereqs.py --strict
fi

echo ""
echo "[build-runtime] === import base if missing ==="
bash sandbox/scripts/pvas-import-image.sh

echo ""
echo "[build-runtime] === staging fresh deps ==="
bash sandbox/scripts/stage-deps.sh

echo ""
echo "[build-runtime] === docker build (no cache) ==="
echo "[build-runtime] Dockerfile: $DOCKERFILE"
docker build --no-cache \
    -f "$DOCKERFILE" \
    --build-arg BASE=pvas-sandbox:v11-2503-imported \
    -t pvas-sandbox:v11-2503-runtime \
    "$SKILL_ROOT" 2>&1 | tail -25

echo ""
echo "[build-runtime] === verify image ==="
python3 sandbox/scripts/audit-image-verify.py