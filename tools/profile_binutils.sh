#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-.}"
OUT="${2:-audit-output/01-profile/binutils}"
mkdir -p "$OUT"
SRC="$(cd "$SRC" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=profile_common.sh
source "$SCRIPT_DIR/profile_common.sh"

: > "$OUT/binutils-source-files.txt"
for d in binutils bfd opcodes gas ld gold gprof libctf libsframe; do
  if [ -d "$SRC/$d" ]; then
    find "$SRC/$d" \( -path '*/.git' -o -path '*/build' -o -path '*/dist' -o -path '*/audit-output' \) -prune -o -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cxx' -o -name '*.inc' \) -print >> "$OUT/binutils-source-files.txt"
  fi
done
sort -u "$OUT/binutils-source-files.txt" | head -n "$MAX_SOURCE_FILES" > "$OUT/binutils-source-files.tmp"
mv "$OUT/binutils-source-files.tmp" "$OUT/binutils-source-files.txt"

python3 "$SCRIPT_DIR/profile_manifest.py" binutils-manifest "$SRC" "$OUT" \
  --max-source "$MAX_SOURCE_FILES" --max-bytes "$MAX_FILE_BYTES" --exclude-dirs "$EXCLUDE_DIRS"

timeout "${PVAS_TOOL_TIMEOUT:-20s}" rg -n "readelf|objdump|bfd_|asection|Elf_Internal|reloc|symtab|strtab|dwarf|debug_|archive|opcodes|disassemble" \
  "$SRC/binutils" "$SRC/bfd" "$SRC/opcodes" 2>/dev/null > "$OUT/binutils-keywords.txt" || true

timeout "${PVAS_TOOL_TIMEOUT:-20s}" rg -n "sh_offset|sh_size|sh_entsize|e_shnum|e_phnum|e_shoff|e_phoff|symcount|reloc|strtab|debug_info|debug_abbrev|debug_line|archive" \
  "$SRC/binutils" "$SRC/bfd" "$SRC/opcodes" 2>/dev/null > "$OUT/binutils-format-fields.txt" || true

timeout "${PVAS_TOOL_TIMEOUT:-20s}" rg -n "goto fail|goto error|cleanup|free\(|bfd_release|bfd_alloc|bfd_malloc|xmalloc|xcalloc|partial|out:|fail:" \
  "$SRC/binutils" "$SRC/bfd" "$SRC/opcodes" 2>/dev/null > "$OUT/binutils-cleanup-ownership.txt" || true

python3 "$SCRIPT_DIR/profile_manifest.py" binutils-profile "$SRC" "$OUT"
run_context_budget "$OUT" "$OUT/context-budget.binutils.json"
