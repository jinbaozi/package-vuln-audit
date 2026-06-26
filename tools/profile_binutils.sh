#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-.}"
OUT="${2:-audit-output/01-profile/binutils}"
mkdir -p "$OUT"
SRC="$(cd "$SRC" && pwd)"
MAX_SOURCE_FILES="${PVAS_MAX_SOURCE_FILES:-10000}"
MAX_FILE_BYTES="${PVAS_MAX_FILE_BYTES:-5242880}"
EXCLUDE_DIRS="${PVAS_EXCLUDE_DIRS:-.git build dist out target node_modules vendor third_party audit-output __pycache__ .venv venv}"
: > "$OUT/binutils-source-files.txt"
for d in binutils bfd opcodes gas ld gold gprof libctf libsframe; do
  if [ -d "$SRC/$d" ]; then
    find "$SRC/$d" \( -path '*/.git' -o -path '*/build' -o -path '*/dist' -o -path '*/audit-output' \) -prune -o -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cxx' -o -name '*.inc' \) -print >> "$OUT/binutils-source-files.txt"
  fi
done
sort -u "$OUT/binutils-source-files.txt" | head -n "$MAX_SOURCE_FILES" > "$OUT/binutils-source-files.tmp"
mv "$OUT/binutils-source-files.tmp" "$OUT/binutils-source-files.txt"
python3 - "$SRC" "$OUT" "$MAX_SOURCE_FILES" "$MAX_FILE_BYTES" "$EXCLUDE_DIRS" <<'PYMANIFEST'
import json, pathlib, sys
src=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); max_source=int(sys.argv[3]); max_bytes=int(sys.argv[4]); excluded=sys.argv[5].split()
files=(out/'binutils-source-files.txt').read_text(errors='ignore').splitlines() if (out/'binutils-source-files.txt').exists() else []
large=0; kept=[]
for f in files:
    try: size=pathlib.Path(f).stat().st_size
    except Exception: size=0
    if size > max_bytes:
        large += 1
    else:
        kept.append(f)
(out/'binutils-source-files.txt').write_text('\n'.join(kept)+'\n' if kept else '')
(out/'traversal-manifest.binutils.json').write_text(json.dumps({'source_root':str(src),'excluded_dirs':excluded,'all_files_count':len(files),'source_files_count':len(kept),'large_files_skipped':large,'truncated':len(files) >= max_source,'limits':{'max_source_files':max_source,'max_file_bytes':max_bytes}}, indent=2))
PYMANIFEST

timeout "${PVAS_TOOL_TIMEOUT:-20s}" rg -n "readelf|objdump|bfd_|asection|Elf_Internal|reloc|symtab|strtab|dwarf|debug_|archive|opcodes|disassemble" \
  "$SRC/binutils" "$SRC/bfd" "$SRC/opcodes" 2>/dev/null > "$OUT/binutils-keywords.txt" || true

timeout "${PVAS_TOOL_TIMEOUT:-20s}" rg -n "sh_offset|sh_size|sh_entsize|e_shnum|e_phnum|e_shoff|e_phoff|symcount|reloc|strtab|debug_info|debug_abbrev|debug_line|archive" \
  "$SRC/binutils" "$SRC/bfd" "$SRC/opcodes" 2>/dev/null > "$OUT/binutils-format-fields.txt" || true

timeout "${PVAS_TOOL_TIMEOUT:-20s}" rg -n "goto fail|goto error|cleanup|free\(|bfd_release|bfd_alloc|bfd_malloc|xmalloc|xcalloc|partial|out:|fail:" \
  "$SRC/binutils" "$SRC/bfd" "$SRC/opcodes" 2>/dev/null > "$OUT/binutils-cleanup-ownership.txt" || true

python3 - "$SRC" "$OUT" <<'PY'
import json, pathlib, sys
src=pathlib.Path(sys.argv[1])
out=pathlib.Path(sys.argv[2])
files=(out/'binutils-source-files.txt').read_text(errors='ignore').splitlines() if (out/'binutils-source-files.txt').exists() else []
focus=[
  'binutils/readelf.c', 'binutils/objdump.c', 'binutils/nm.c', 'binutils/objcopy.c',
  'bfd/elf.c', 'bfd/archive.c', 'bfd/compress.c', 'binutils/dwarf.c', 'opcodes/'
]
existing=[p for p in focus if (src/p).exists()]
profile={
  'package_name': 'binutils' if (src/'bfd').exists() or (src/'binutils').exists() else src.resolve().name,
  'source_root': str(src),
  'primary_language': ['C'],
  'profiles': ['binary-parser','compiler-toolchain','cli-tool'],
  'build_system': ['autotools','make'] if (src/'configure').exists() else ['unknown'],
  'input_surfaces': ['ELF object files','archives','DWARF/debug sections','relocations','symbol/string tables','command-line options'],
  'high_risk_modules': existing + [f for f in files if any(x in f for x in ['bfd/elf','bfd/archive','opcodes/'])][:20],
  'selected_recipes': ['recipes/binary-parser.md','recipes/compiler-toolchain.md','recipes/cli-tool.md'],
  'recommended_tools': ['rg','semgrep','cppcheck','codeql','asan','ubsan','afl++','libFuzzer'],
  'validation_binaries': ['readelf','objdump','nm-new','objcopy','strip-new'],
  'audit_focus': ['offset+size overflow','section/symbol/relocation/string table consistency','DWARF bounds','archive member bounds','BFD ownership and cleanup','opcodes disassembly buffer assumptions'],
  'confidence': 'high' if existing else 'medium'
}
(out/'package-profile.binutils.json').write_text(json.dumps(profile, indent=2))
(out/'package-profile.binutils.md').write_text('# Binutils Package Profile\n\n```json\n'+json.dumps(profile, indent=2)+'\n```\n')
PY
python3 "$(dirname "$0")/context_budget.py" --profile-dir "$OUT" --packet-dir "${PVAS_PACKET_DIR:-audit-output/03-candidates/packets}" --out "$OUT/context-budget.binutils.json" >/dev/null || true
