#!/usr/bin/env bash
set -euo pipefail
CANDIDATE_ID="${1:?candidate id required}"
shift || true
OUT="${VALIDATION_OUT:-audit-output/04-validation/$CANDIDATE_ID}"
mkdir -p "$OUT"
if [ "$#" -eq 0 ]; then
  echo "No validation command supplied." > "$OUT/result.txt"
  exit 2
fi
printf '%q ' "$@" > "$OUT/command.txt"
set +e
("$@") > "$OUT/stdout.txt" 2> "$OUT/stderr.txt"
code=$?
set -e
status="inconclusive"; [ "$code" -ne 0 ] && status="validated"
python3 - "$CANDIDATE_ID" "$OUT" "$status" "$code" <<'PY'
import json, pathlib, sys
cid,out,status,code=sys.argv[1],pathlib.Path(sys.argv[2]),sys.argv[3],sys.argv[4]
cmd=(out/'command.txt').read_text()
(out/'validation-result.json').write_text(json.dumps({'candidate_id':cid,'status':status,'method':'minimal-testcase','command':cmd,'artifacts':[str(out/'stdout.txt'),str(out/'stderr.txt')],'result_summary':f'Command exited with code {code}. Review logs before final classification.','reproducibility':'once','safety_note':'Authorized local validation/regression testing only.'}, indent=2))
PY
