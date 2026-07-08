#!/usr/bin/env bash
# Shared helpers for profile_*.sh scripts
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_FILES="${PVAS_MAX_FILES:-50000}"
MAX_SOURCE_FILES="${PVAS_MAX_SOURCE_FILES:-10000}"
MAX_FILE_BYTES="${PVAS_MAX_FILE_BYTES:-5242880}"
EXCLUDE_DIRS="${PVAS_EXCLUDE_DIRS:-.git build dist out target node_modules vendor third_party audit-output __pycache__ .venv venv}"

run_context_budget() {
  local out="$1"
  local budget_file="${2:-$out/context-budget.json}"
  python3 "$SCRIPT_DIR/context_budget.py" \
    --profile-dir "$out" \
    --packet-dir "${PVAS_PACKET_DIR:-audit-output/03-candidates/packets}" \
    --out "$budget_file"
}
