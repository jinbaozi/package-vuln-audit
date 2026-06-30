#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-.}"
OUT="${2:-audit-output/01-profile}"
mkdir -p "$OUT"
SRC="$(cd "$SRC" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=profile_common.sh
source "$SCRIPT_DIR/profile_common.sh"

FIND_CMD=(find "$SRC" '(' )
first=1
for d in $EXCLUDE_DIRS; do
  if [[ "$first" -eq 0 ]]; then FIND_CMD+=('-o'); fi
  FIND_CMD+=('-path' "$SRC/$d")
  first=0
done
FIND_CMD+=(')' '-prune' '-o' '-type' 'f' '-print')

set +o pipefail
"${FIND_CMD[@]}" | head -n "$MAX_FILES" > "$OUT/all-files.txt"
set -o pipefail

python3 "$SCRIPT_DIR/profile_manifest.py" from-all-files "$SRC" "$OUT" \
  --max-source "$MAX_SOURCE_FILES" --max-bytes "$MAX_FILE_BYTES" --exclude-dirs "$EXCLUDE_DIRS"

if git -C "$SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$SRC" log --oneline -n 200 > "$OUT/git-log.txt" || true
else
  : > "$OUT/git-log.txt"
fi
run_context_budget "$OUT"
