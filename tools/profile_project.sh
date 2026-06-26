#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-.}"
OUT="${2:-audit-output/01-profile}"
mkdir -p "$OUT"
SRC="$(cd "$SRC" && pwd)"
MAX_FILES="${PVAS_MAX_FILES:-50000}"
MAX_SOURCE_FILES="${PVAS_MAX_SOURCE_FILES:-10000}"
MAX_FILE_BYTES="${PVAS_MAX_FILE_BYTES:-5242880}"
EXCLUDE_DIRS="${PVAS_EXCLUDE_DIRS:-.git build dist out target node_modules vendor third_party audit-output __pycache__ .venv venv}"

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

python3 - "$SRC" "$OUT" "$MAX_SOURCE_FILES" "$MAX_FILE_BYTES" "$EXCLUDE_DIRS" <<'PYSEL'
import pathlib, sys, os, json
src=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); max_source=int(sys.argv[3]); max_bytes=int(sys.argv[4]); excluded=sys.argv[5].split()
all_files=(out/'all-files.txt').read_text(errors='ignore').splitlines()
source_names={'.c','.h','.cc','.cpp','.cxx','.hpp','.rs','.go','.py','.sh'}
special={'Makefile','CMakeLists.txt'}
build_names={'configure','configure.ac','Makefile','CMakeLists.txt','meson.build','Cargo.toml','go.mod','package.json','requirements.txt','pyproject.toml'}
source=[]; build=[]; large=0
for f in all_files:
    p=pathlib.Path(f); name=p.name; suff=p.suffix.lower()
    try: size=p.stat().st_size
    except Exception: size=0
    if size > max_bytes:
        large += 1
        continue
    if suff in source_names or name in special:
        if len(source) < max_source:
            source.append(f)
    if name in build_names:
        build.append(f)
(out/'source-files.txt').write_text('\n'.join(source)+'\n' if source else '')
(out/'build-and-dependency-files.txt').write_text('\n'.join(build)+'\n' if build else '')
manifest={
  'source_root': str(src),
  'excluded_dirs': excluded,
  'all_files_count': len(all_files),
  'source_files_count': len(source),
  'large_files_skipped': large,
  'truncated': len(all_files) >= int(os.environ.get('PVAS_MAX_FILES','50000')) or len(source) >= max_source,
  'limits': {'max_files': int(os.environ.get('PVAS_MAX_FILES','50000')), 'max_source_files': max_source, 'max_file_bytes': max_bytes}
}
(out/'traversal-manifest.json').write_text(json.dumps(manifest, indent=2))
PYSEL

if git -C "$SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$SRC" log --oneline -n 200 > "$OUT/git-log.txt" || true
else
  : > "$OUT/git-log.txt"
fi
python3 - "$SRC" "$OUT" <<'PY'
import json, pathlib, collections, sys
src=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2])
files=(out/'source-files.txt').read_text(errors='ignore').splitlines()
build=(out/'build-and-dependency-files.txt').read_text(errors='ignore').splitlines()
exts=collections.Counter(pathlib.Path(f).suffix.lower() or pathlib.Path(f).name for f in files)
text='\n'.join(files + build).lower()
profiles=[]
if any(x in text for x in ['.c', '.h', '.cpp', '.cc', '.cxx']): profiles.append('cli-tool')
if any(x in text for x in ['parse', 'parser', 'read', 'decode', 'archive', 'elf', 'dwarf', 'record']): profiles.append('binary-parser')
if any(x in text for x in ['makefile', 'cmakelists.txt', 'configure', 'meson.build']): profiles.append('build-system')
if not profiles: profiles.append('unknown-conservative')
langs=[]
if any(k in exts for k in ['.c','.h','.cc','.cpp','.cxx','.hpp']): langs.append('C/C++')
if any(k in exts for k in ['.py']): langs.append('Python')
if any(k in exts for k in ['.sh']): langs.append('Shell')
build_system=[]
for b in build:
    name=pathlib.Path(b).name.lower()
    if name == 'makefile': build_system.append('make')
    elif name == 'cmakelists.txt': build_system.append('cmake')
    elif name in ('configure','configure.ac'): build_system.append('autotools')
    elif name == 'meson.build': build_system.append('meson')
profile={
  'package_name': src.resolve().name,
  'source_root': str(src),
  'primary_language': langs or ['unknown'],
  'profiles': sorted(set(profiles)),
  'build_system': sorted(set(build_system)) or ['unknown'],
  'source_file_count': len(files),
  'extension_counts': dict(exts.most_common(30)),
  'input_surfaces': ['files','command-line arguments'] if 'binary-parser' in profiles else ['unknown'],
  'high_risk_modules': [f for f in files if any(k in f.lower() for k in ['parse','read','decode','main.c'])][:20],
  'selected_recipes': [f'recipes/{p}.md' for p in sorted(set(profiles))],
  'confidence': 'medium'
}
(out/'package-profile-hints.json').write_text(json.dumps({'source_file_count':len(files),'extension_counts':dict(exts.most_common(30))}, indent=2))
(out/'package-profile.json').write_text(json.dumps(profile, indent=2))
(out/'package-profile.md').write_text('# Package Profile\n\n```json\n'+json.dumps(profile, indent=2)+'\n```\n')
PY
python3 "$(dirname "$0")/context_budget.py" --profile-dir "$OUT" --packet-dir "${PVAS_PACKET_DIR:-audit-output/03-candidates/packets}" --out "$OUT/context-budget.json" >/dev/null || true
