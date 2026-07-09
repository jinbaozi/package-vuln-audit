#!/usr/bin/env bash
# Run traditional tools (cppcheck, semgrep, osv-scanner, etc.) for the audit.
#
# In strict mode, this script enforces running all tools inside the
# pvas-sandbox:v11-2503-runtime container via pvas_container.
#
# Usage:
#   bash run_tools.sh [SRC] [OUT]
#
# Env:
#   PVAS_SKIP_ENV_GATE      =1  skip strict_env_gate (only when driver already ran it)
#   PVAS_ALLOW_DEGRADED      =1  allow degraded mode
#   PVAS_RUNTIME_IMAGE       override the runtime image tag
#   PVAS_CPPCHECK_MODE       fast | deep (default: fast)
#   PVAS_TOOL_TIMEOUT        timeout per tool (default: 600s)

set -euo pipefail
SRC="${1:-.}"
OUT="${2:-audit-output/02-tools}"
RAW="$OUT/raw"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Host PATH used only for non-strict-mode fallback and preflight tooling.
export PATH="$HOME/.pvas/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"
mkdir -p "$RAW"

# ------------------------------------------------------------------
# 1. Environment gate (skip if driver already ran it)
# ------------------------------------------------------------------
ENV_OUT="$(dirname "$OUT")/00-environment"
ENV_PROFILE="${PVAS_ENV_PROFILE:-standard}"
ENV_MODE="${PVAS_TOOL_MODE:-strict}"
GATE_ARGS=(--out "$ENV_OUT" --profile "$ENV_PROFILE" --mode "$ENV_MODE")
if [ "${PVAS_ALLOW_DEGRADED:-0}" = "1" ]; then GATE_ARGS+=(--allow-degraded); fi
if [ "${PVAS_SKIP_ENV_GATE:-0}" != "1" ]; then
  if ! python3 "$SCRIPT_DIR/strict_env_gate.py" "${GATE_ARGS[@]}"; then
    exit 2
  fi
fi

# ------------------------------------------------------------------
# 2. Build runtime image if missing (only in strict mode)
# ------------------------------------------------------------------
PROFILE_DIR="$(dirname "$OUT")/01-profile"
MATRIX="$PROFILE_DIR/required-tools-matrix.json"

if [ "$ENV_MODE" = "strict" ] && [ "${PVAS_SKIP_IMAGE_BUILD:-0}" != "1" ]; then
    if ! docker images --format '{{.Repository}}:{{.Tag}}' | grep -qF "pvas-sandbox:v11-2503-runtime"; then
        echo "[run_tools] runtime image missing; running build-runtime.sh"
        bash "$SKILL_ROOT/sandbox/scripts/build-runtime.sh"
    fi
fi

# ------------------------------------------------------------------
# 3. Generate tool matrix if missing
# ------------------------------------------------------------------
CPPCHECK_MODE="${PVAS_CPPCHECK_MODE:-fast}"
CPPCHECK_MODE_SOURCE="${PVAS_CPPCHECK_MODE_SOURCE:-standalone-default-fast}"
if [ -n "${PVAS_CPPCHECK_MODE:-}" ] && [ -z "${PVAS_CPPCHECK_MODE_SOURCE:-}" ]; then
  CPPCHECK_MODE_SOURCE="env-cppcheck-mode"
fi
if [ ! -f "$MATRIX" ]; then
  python3 "$SCRIPT_DIR/generate_tool_matrix.py" \
    --package-profile "$PROFILE_DIR/package-profile.json" \
    --profile "$ENV_PROFILE" \
    --timeout "${PVAS_TOOL_TIMEOUT:-600s}" \
    --cppcheck-mode "$CPPCHECK_MODE" \
    --cppcheck-mode-source "$CPPCHECK_MODE_SOURCE" \
    --out "$MATRIX"
fi

# ------------------------------------------------------------------
# 4. Run tool matrix (sandbox or host per strict mode)
# ------------------------------------------------------------------
if [ "$ENV_MODE" = "strict" ] || [ "${PVAS_FORCE_SANDBOX:-0}" = "1" ]; then
    # Force sandbox execution. run_tool_matrix.py uses pvas_container.
    export PVAS_FORCE_SANDBOX=1
fi

python3 "$SCRIPT_DIR/run_tool_matrix.py" --matrix "$MATRIX" --source "$SRC" --out "$OUT"

# ------------------------------------------------------------------
# 5. Generate install plan (advisory only; we never auto-install)
# ------------------------------------------------------------------
python3 "$SCRIPT_DIR/generate_install_plan.py" --tool-summary "$OUT/tool-summary.json" --out "$ENV_OUT" || true