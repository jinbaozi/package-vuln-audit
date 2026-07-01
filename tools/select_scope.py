#!/usr/bin/env python3
"""Select deterministic audit scope and recipes from a package profile."""
from __future__ import annotations

import argparse
import pathlib
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json

RECIPE_MAP = {
    'binary-parser': ['recipes/binary-parser.md'],
    'cli-tool': ['recipes/cli-tool.md'],
    'build-system': ['recipes/build-system.md'],
    'library': ['recipes/library.md'],
    'network-service': ['recipes/network-service.md'],
}

SCOPE_HINTS = {
    'binary-parser': ['parsers', 'file format readers', 'bounds-sensitive decoding paths'],
    'cli-tool': ['command-line input handling', 'file argument processing', 'diagnostic output paths'],
    'build-system': ['build scripts', 'configure-time code execution surfaces', 'generated file handling'],
    'library': ['public APIs', 'callers crossing trust boundaries', 'memory ownership boundaries'],
    'network-service': ['request parsing', 'authentication boundaries', 'network-facing sinks'],
}


def _profile_names(profile: dict) -> list[str]:
    names = profile.get('profiles') or profile.get('profile') or []
    if isinstance(names, str):
        names = [names]
    if not names:
        langs = ' '.join(profile.get('primary_language') or []).lower()
        if 'c' in langs:
            names = ['cli-tool']
    return [str(x) for x in names]


def select_scope(profile: dict, source: str = '.') -> dict:
    profiles = _profile_names(profile)
    recipes: list[str] = []
    focus: list[str] = []
    for p in profiles:
        recipes.extend(RECIPE_MAP.get(p, []))
        focus.extend(SCOPE_HINTS.get(p, []))
    if not recipes:
        recipes = ['recipes/generic-source-audit.md']
    return {
        'package_name': profile.get('package_name') or profile.get('name') or pathlib.Path(source).name,
        'source': source,
        'profiles': profiles,
        'selected_recipes': sorted(dict.fromkeys(recipes)),
        'focus_areas': sorted(dict.fromkeys(focus)) or ['source-code security review'],
        'candidate_limit': 20,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', required=True)
    ap.add_argument('--source', default='.')
    ap.add_argument('--out-dir', required=True)
    args = ap.parse_args()

    profile = load_json(args.profile, default={}, required=True)
    if not isinstance(profile, dict):
        raise SystemExit('package profile must be a JSON object')
    selected = select_scope(profile, args.source)
    out_dir = pathlib.Path(args.out_dir)
    write_json(out_dir / 'selected-scope.json', selected)
    lines = ['# Selected Scope', '']
    lines.append(f"- Package: `{selected['package_name']}`")
    lines.append(f"- Profiles: {', '.join(selected['profiles']) if selected['profiles'] else 'generic'}")
    lines.append('')
    lines.append('## Recipes')
    for recipe in selected['selected_recipes']:
        lines.append(f'- `{recipe}`')
    lines.append('')
    lines.append('## Focus Areas')
    for area in selected['focus_areas']:
        lines.append(f'- {area}')
    (out_dir / 'selected-recipes.md').write_text('\n'.join(lines) + '\n')
    print(out_dir / 'selected-scope.json')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
