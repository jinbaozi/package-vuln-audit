#!/usr/bin/env bash
set -euo pipefail
SKILL_ROOT="${SKILL_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$SRC/audit-output}"
rm -rf "$OUT"
mkdir -p "$OUT"
"$SKILL_ROOT/tools/profile_project.sh" "$SRC" "$OUT/01-profile"
PVAS_SKIP_OPTIONAL=1 "$SKILL_ROOT/tools/run_tools.sh" "$SRC" "$OUT/02-tools"
python3 "$SKILL_ROOT/tools/normalize_results.py" --tools-dir "$OUT/02-tools/raw" --out "$OUT/03-candidates/raw-candidates.json"
python3 "$SKILL_ROOT/tools/rank_candidates.py" --input "$OUT/03-candidates/raw-candidates.json" --out "$OUT/03-candidates/ranked-candidates.json" --top 10
python3 "$SKILL_ROOT/tools/make_ai_packets.py" --candidates "$OUT/03-candidates/ranked-candidates.json" --source-root "$SRC" --out "$OUT/03-candidates/packets" --context-lines 30 --max-lines 120
python3 "$SKILL_ROOT/tools/summarize_artifacts.py" --audit-output "$OUT" --out "$OUT/summary.json"
echo "demo audit artifacts written to $OUT"
