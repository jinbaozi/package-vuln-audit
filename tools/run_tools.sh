#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-.}"
OUT="${2:-audit-output/02-tools}"
RAW="$OUT/raw"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.pvas/bin:$PATH"
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
run_tool() {
  local name="$1"; shift
  local bin="$1"; shift
  local outfile="$RAW/$name.out"
  if command -v "$bin" >/dev/null 2>&1; then
    (timeout "${PVAS_TOOL_TIMEOUT:-60s}" "$bin" "$@" > "$outfile" 2>&1) && status=completed || status=failed
  else
    echo "not installed" > "$outfile"; status=not-installed
  fi
  printf '%s\t%s\t%s\n' "$name" "$status" "$outfile" >> "$OUT/.tool-status.tsv"
}
: > "$OUT/.tool-status.tsv"
run_tool rg rg -n "strcpy|strcat|sprintf|vsprintf|memcpy|memmove|malloc|calloc|realloc|free|system\(|popen\(|mktemp|tmpnam|open\(|unlink\(" "$SRC"

if [ "${PVAS_SKIP_OPTIONAL:-0}" = "1" ]; then
  echo '{}' > "$RAW/semgrep.json"; printf '%s\t%s\t%s\n' semgrep skipped "$RAW/semgrep.json" >> "$OUT/.tool-status.tsv"
  echo 'skipped' > "$RAW/cppcheck.out"; printf '%s\t%s\t%s\n' cppcheck skipped "$RAW/cppcheck.out" >> "$OUT/.tool-status.tsv"
  echo '{}' > "$RAW/osv.json"; printf '%s\t%s\t%s\n' osv-scanner skipped "$RAW/osv.json" >> "$OUT/.tool-status.tsv"
else
  if command -v semgrep >/dev/null 2>&1; then
    timeout "${PVAS_TOOL_TIMEOUT:-60s}" semgrep scan --config auto --json --output "$RAW/semgrep.json" "$SRC" >/dev/null 2>&1 && semgrep_status=completed || semgrep_status=failed
  else
    echo '{}' > "$RAW/semgrep.json"; semgrep_status=not-installed
  fi
  printf '%s\t%s\t%s\n' semgrep "$semgrep_status" "$RAW/semgrep.json" >> "$OUT/.tool-status.tsv"
  run_tool cppcheck cppcheck --enable=warning,style,performance,portability --template=gcc "$SRC"
  if command -v osv-scanner >/dev/null 2>&1; then
    timeout "${PVAS_TOOL_TIMEOUT:-60s}" osv-scanner scan --format json "$SRC" > "$RAW/osv.json" 2>&1 && osv_status=completed || osv_status=failed
  else
    echo '{}' > "$RAW/osv.json"; osv_status=not-installed
  fi
  printf '%s\t%s\t%s\n' osv-scanner "$osv_status" "$RAW/osv.json" >> "$OUT/.tool-status.tsv"
fi
python3 - "$OUT" <<'PY'
import json, pathlib, sys
out=pathlib.Path(sys.argv[1])
rows=[]
missing=[]
for line in (out/'.tool-status.tsv').read_text().splitlines():
    name,status,of=line.split('\t',2)
    row={'name':name,'status':status,'output':of,'notes':''}
    rows.append(row)
    if status == 'not-installed':
        missing.append(name)
summary='Tool execution completed with missing tools tolerated.'
if missing:
    summary += ' Missing tools: ' + ', '.join(missing) + '. See ../00-environment/tool-install-plan.md for installation guidance.'
(out/'tool-summary.json').write_text(json.dumps({'tools':rows,'raw_outputs':[r['output'] for r in rows],'summary':summary,'normalized_candidate_count':0,'errors':[]}, indent=2))
for name in missing:
    print(f'[PVAS-TOOL-MISSING] {name} not installed; generated candidate coverage may be degraded.', file=sys.stderr)
PY
ENV_OUT="$(dirname "$OUT")/00-environment"
python3 "$SCRIPT_DIR/generate_install_plan.py" --tool-summary "$OUT/tool-summary.json" --out "$ENV_OUT" >/dev/null || true
