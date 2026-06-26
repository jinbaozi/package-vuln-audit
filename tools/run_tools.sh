#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-.}"
OUT="${2:-audit-output/02-tools}"
RAW="$OUT/raw"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.pvas/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"
mkdir -p "$RAW"

ENV_OUT="$(dirname "$OUT")/00-environment"
ENV_MODE="${PVAS_TOOL_MODE:-default}"
ENV_PROFILE="${PVAS_ENV_PROFILE:-standard}"
ALLOW_FLAG=()
if [ "${PVAS_ALLOW_DEGRADED:-0}" = "1" ]; then ALLOW_FLAG=(--allow-degraded); fi
if ! python3 "$SCRIPT_DIR/verify_environment.py" --profile "$ENV_PROFILE" --mode "$ENV_MODE" "${ALLOW_FLAG[@]}" --out "$ENV_OUT"; then
  if [ "$ENV_MODE" = "strict" ] && [ "${PVAS_INSTALL_ASSIST:-1}" = "1" ]; then
    missing_tools="$(python3 - "$ENV_OUT/environment-check.json" <<'PYENV'
import json, sys
data=json.load(open(sys.argv[1]))
print(','.join(data.get('blocking_missing_tools') or data.get('missing_tools') or []))
PYENV
)"
    python3 "$SCRIPT_DIR/generate_install_plan.py" --environment-check "$ENV_OUT/environment-check.json" --out "$ENV_OUT" >/dev/null || true
    python3 "$SCRIPT_DIR/install_assistant.py" --tools "$missing_tools" --mode strict --out "$ENV_OUT" ${PVAS_INSTALL_DRY_RUN:+--dry-run} || true
    echo "[PVAS-STRICT-BLOCK] audit paused after controlled install-assistant. Review $ENV_OUT/install-assistant-decision.json or rerun with PVAS_ALLOW_DEGRADED=1." >&2
  fi
  exit 2
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
