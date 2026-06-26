#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <binutils-source-root> [audit-output]" >&2
  exit 2
fi
SRC="$1"
OUT="${2:-$SRC/audit-output}"
SKILL_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

mkdir -p "$OUT"
"$SKILL_ROOT/tools/profile_project.sh" "$SRC" "$OUT/01-profile"
"$SKILL_ROOT/tools/profile_binutils.sh" "$SRC" "$OUT/01-profile/binutils"
"$SKILL_ROOT/tools/run_tools.sh" "$SRC" "$OUT/02-tools"
python3 "$SKILL_ROOT/tools/normalize_results.py" --tool-dir "$OUT/02-tools" --out "$OUT/03-candidates/raw-candidates.json"
python3 "$SKILL_ROOT/tools/rank_candidates.py" --input "$OUT/03-candidates/raw-candidates.json" --out "$OUT/03-candidates/ranked-candidates.json" --top 20
python3 "$SKILL_ROOT/tools/make_ai_packets.py" --candidates "$OUT/03-candidates/ranked-candidates.json" --source-root "$SRC" --out "$OUT/03-candidates/packets" --context-lines 80 --max-functions 3
python3 "$SKILL_ROOT/tools/summarize_artifacts.py" --audit-output "$OUT" --out "$OUT/summary.json"

echo "Binutils audit artifacts written to $OUT"
echo "Next: review $OUT/03-candidates/packets/*.md with the candidate-reviewer subagent."
