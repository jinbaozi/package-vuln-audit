#!/usr/bin/env bash
set -euo pipefail

BUILD="${1:-build-asan}"
INPUT="${2:?usage: validate_binutils_input.sh <build-dir> <input-file> [output-dir]}"
OUT="${3:-audit-output/04-validation/binutils}"
mkdir -p "$OUT"

export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"

run_case() {
  local name="$1"; shift
  local log="$OUT/${name}.log"
  if [ ! -x "$1" ]; then
    echo "missing binary: $1" > "$log"
    printf '%s\t%s\t%s\n' "$name" "missing" "$log" >> "$OUT/status.tsv"
    return 0
  fi
  if timeout 10s "$@" > "$log" 2>&1; then
    printf '%s\t%s\t%s\n' "$name" "clean" "$log" >> "$OUT/status.tsv"
  else
    printf '%s\t%s\t%s\n' "$name" "crash-or-timeout" "$log" >> "$OUT/status.tsv"
  fi
}

: > "$OUT/status.tsv"
run_case readelf-a "$BUILD/binutils/readelf" -a "$INPUT"
run_case readelf-r "$BUILD/binutils/readelf" -r "$INPUT"
run_case objdump-D "$BUILD/binutils/objdump" -D "$INPUT"
run_case objdump-x "$BUILD/binutils/objdump" -x "$INPUT"
run_case nm "$BUILD/binutils/nm-new" "$INPUT"
run_case objcopy "$BUILD/binutils/objcopy" "$INPUT" "$OUT/objcopy.out" || true
run_case strip "$BUILD/binutils/strip-new" "$INPUT" -o "$OUT/strip.out" || true

python3 - "$OUT" <<'PY'
import json, pathlib, sys
out=pathlib.Path(sys.argv[1])
rows=[]
for line in (out/'status.tsv').read_text().splitlines():
    name,status,log=line.split('\t',2)
    rows.append({'case':name,'status':status,'log':log})
(out/'validation-summary.json').write_text(json.dumps({'target':'binutils','cases':rows}, indent=2))
PY
