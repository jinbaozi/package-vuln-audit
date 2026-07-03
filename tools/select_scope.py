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
    'build-system': ['recipes/build-system.md'],
    'cli-tool': ['recipes/cli-tool.md'],
    'compiler-toolchain': ['recipes/compiler-toolchain.md'],
    'crypto-auth': ['recipes/crypto-auth.md'],
    'library-parser': ['recipes/library-parser.md'],
    'mixed-project': ['recipes/mixed-project.md'],
    'network-service': ['recipes/network-service.md'],
    'package-manager': ['recipes/package-manager.md'],
    'privileged-tool': ['recipes/privileged-tool.md'],
    'unknown-conservative': ['recipes/unknown-conservative.md'],
}

SCOPE_HINTS = {
    'binary-parser': ['parsers', 'file format readers', 'bounds-sensitive decoding paths'],
    'cli-tool': ['command-line input handling', 'file argument processing', 'diagnostic output paths'],
    'compiler-toolchain': ['compiler frontends', 'linker inputs', 'generated code boundaries'],
    'build-system': ['build scripts', 'configure-time code execution surfaces', 'generated file handling'],
    'crypto-auth': ['authentication flows', 'cryptographic boundary checks', 'secret handling'],
    'library-parser': ['public parser APIs', 'callers crossing trust boundaries', 'memory ownership boundaries'],
    'mixed-project': ['cross-language boundaries', 'generated artifacts', 'shared parsing surfaces'],
    'network-service': ['request parsing', 'authentication boundaries', 'network-facing sinks'],
    'package-manager': ['manifest parsing', 'dependency resolution', 'archive extraction'],
    'privileged-tool': ['privilege boundary checks', 'filesystem mutation', 'environment handling'],
    'unknown-conservative': ['source-code security review', 'input parsing', 'dangerous sink review'],
}
ROOT = pathlib.Path(__file__).resolve().parents[1]


def _profile_names(profile: dict) -> list[str]:
    names = profile.get('profiles') or profile.get('profile') or []
    if isinstance(names, str):
        names = [names]
    if not names:
        langs = ' '.join(profile.get('primary_language') or []).lower()
        if 'c' in langs:
            names = ['cli-tool']
    return [str(x) for x in names]


def _selected_recipes(profile: dict) -> list[str]:
    values = profile.get('selected_recipes') or []
    if isinstance(values, str):
        values = [values]
    recipes = []
    iterable = values if isinstance(values, list) else []
    for value in iterable:
        recipe = str(value)
        if recipe and not recipe.startswith('recipes/'):
            recipe = f'recipes/{recipe}'
        if recipe and not recipe.endswith('.md'):
            recipe = f'{recipe}.md'
        if recipe:
            recipes.append(recipe)
    return recipes


def _existing_recipes(recipes: list[str]) -> list[str]:
    return [recipe for recipe in recipes if (ROOT / recipe).is_file()]


def select_scope(profile: dict, source: str = '.') -> dict:
    profiles = _profile_names(profile)
    explicit_recipes = _selected_recipes(profile)
    missing_explicit = [recipe for recipe in explicit_recipes if not (ROOT / recipe).is_file()]
    if missing_explicit:
        raise ValueError(f"selected recipe does not exist: {', '.join(missing_explicit)}")
    recipes: list[str] = explicit_recipes
    focus: list[str] = []
    if not recipes:
        for p in profiles:
            recipes.extend(RECIPE_MAP.get(p, []))
            focus.extend(SCOPE_HINTS.get(p, []))
    else:
        for p in profiles:
            focus.extend(SCOPE_HINTS.get(p, []))
    recipes = _existing_recipes(sorted(dict.fromkeys(recipes)))
    if not recipes:
        recipes = ['recipes/unknown-conservative.md']
        if 'unknown-conservative' not in profiles:
            profiles = profiles + ['unknown-conservative']
        focus.extend(SCOPE_HINTS['unknown-conservative'])
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
