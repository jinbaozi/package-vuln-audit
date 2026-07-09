#!/usr/bin/env bash
# Wrapper that guarantees cleanup on any exit path.
#
# Usage: bash run-with-cleanup.sh <audit-command> [args...]
#
# Behavior:
#   - Exports PVAS_AUDIT_ID (default: default-audit-id)
#   - Sets up trap on EXIT/INT/TERM
#   - Runs the audit command
#   - On exit, calls cleanup-audit.sh regardless of exit code
#
# This guarantees no Docker resources leak even if audit fails or user
# presses Ctrl-C.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PVAS_AUDIT_ID="${PVAS_AUDIT_ID:-default-audit-id}"
export PVAS_LOG_DIR="${PVAS_LOG_DIR:-$(pwd)/audit-output/machine}"
mkdir -p "$PVAS_LOG_DIR"

cleanup_on_exit() {
    local rc=$?
    echo ""
    echo "[run-with-cleanup] audit exited with code $rc; running cleanup-audit.sh..."
    bash "${SCRIPT_DIR}/cleanup-audit.sh" || true
    exit "$rc"
}

trap cleanup_on_exit EXIT INT TERM

echo "[run-with-cleanup] PVAS_AUDIT_ID=$PVAS_AUDIT_ID"
echo "[run-with-cleanup] PVAS_LOG_DIR=$PVAS_LOG_DIR"
echo "[run-with-cleanup] cleanup will run on any exit path"
echo ""

"$@"
RC=$?
echo ""
echo "[run-with-cleanup] audit command exited with code $RC"
exit "$RC"