#!/usr/bin/env bash
set -euo pipefail
SKILL_ROOT="${SKILL_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$SRC/audit-output}"
rm -rf "$OUT"
mkdir -p "$OUT"
"$SKILL_ROOT/tools/profile_project.sh" "$SRC" "$OUT/01-profile"
mkdir -p "$OUT/02-tools/raw"
python3 - "$SRC" "$OUT/02-tools" <<'PY'
import json
import pathlib
import re
import sys

src = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
raw = out / "raw"
patterns = re.compile(r"strcpy|strcat|sprintf|vsprintf|memcpy|memmove|malloc|calloc|realloc|free|system\(|popen\(|mktemp|tmpnam|open\(|unlink\(")
lines = []
for path in sorted((src / "src").glob("**/*")):
    if not path.is_file():
        continue
    for lineno, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
        if patterns.search(line):
            lines.append(f"{path}:{lineno}:{line}")
(raw / "rg.out").write_text("\n".join(lines) + ("\n" if lines else ""))
(out / "tool-summary.json").write_text(json.dumps({
    "tools": [{
        "name": "rg",
        "status": "completed-with-findings" if lines else "completed",
        "output": str(raw / "rg.out"),
        "reason": "",
        "strict_decision": "continue",
        "coverage_impact": "",
        "watchdog_events": [],
        "network_used": False
    }],
    "raw_outputs": [str(raw / "rg.out")],
    "summary": "Toy fixture local pattern scan completed.",
    "normalized_candidate_count": 0,
    "errors": [],
    "strict_decision": "continue",
    "blocked_tools": [],
    "coverage_impact": [],
    "incomplete_tools": []
}, indent=2))
PY
python3 "$SKILL_ROOT/tools/normalize_results.py" --tools-dir "$OUT/02-tools/raw" --out "$OUT/03-candidates/raw-candidates.json"
python3 "$SKILL_ROOT/tools/rank_candidates.py" --input "$OUT/03-candidates/raw-candidates.json" --out "$OUT/03-candidates/ranked-candidates.json" --top 10
python3 "$SKILL_ROOT/tools/make_ai_packets.py" --candidates "$OUT/03-candidates/ranked-candidates.json" --source-root "$SRC" --out "$OUT/03-candidates/packets" --context-lines 30 --max-lines 120
python3 "$SKILL_ROOT/tools/summarize_artifacts.py" --audit-output "$OUT" --out "$OUT/summary.json"
echo "demo audit artifacts written to $OUT"
