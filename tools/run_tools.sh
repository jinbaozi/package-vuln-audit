#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-.}"
OUT="${2:-audit-output/02-tools}"
RAW="$OUT/raw"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.pvas/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"
mkdir -p "$RAW"

ENV_OUT="$(dirname "$OUT")/00-environment"
ENV_PROFILE="${PVAS_ENV_PROFILE:-standard}"
ENV_MODE="${PVAS_TOOL_MODE:-default}"
GATE_ARGS=(--out "$ENV_OUT" --profile "$ENV_PROFILE" --mode "$ENV_MODE")
if [ "${PVAS_ALLOW_DEGRADED:-0}" = "1" ]; then GATE_ARGS+=(--allow-degraded); fi
# Standalone: gate runs by default. Driver sets PVAS_SKIP_ENV_GATE=1 after its own gate.
if [ "${PVAS_SKIP_ENV_GATE:-0}" != "1" ]; then
  if ! python3 "$SCRIPT_DIR/strict_env_gate.py" "${GATE_ARGS[@]}"; then
    exit 2
  fi
fi
PROFILE_DIR="$(dirname "$OUT")/01-profile"
MATRIX="$PROFILE_DIR/required-tools-matrix.json"
if [ ! -f "$MATRIX" ]; then
  python3 "$SCRIPT_DIR/generate_tool_matrix.py" \
    --package-profile "$PROFILE_DIR/package-profile.json" \
    --profile "$ENV_PROFILE" \
    --timeout "${PVAS_TOOL_TIMEOUT:-60s}" \
    --out "$MATRIX"
fi
python3 "$SCRIPT_DIR/run_tool_matrix.py" --matrix "$MATRIX" --source "$SRC" --out "$OUT"
ENV_OUT="$(dirname "$OUT")/00-environment"
python3 "$SCRIPT_DIR/generate_install_plan.py" --tool-summary "$OUT/tool-summary.json" --out "$ENV_OUT" >/dev/null || true
