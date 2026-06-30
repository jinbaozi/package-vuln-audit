#!/usr/bin/env python3
"""Build L1 guides/index.json from core/manifest.yaml stages and workflow titles."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

import manifest_io

HEADING_RE = re.compile(r'^#\s+(.+?)\s*$')
DEFAULT_LOAD_TIER = 'L2'


def scan_workflow_titles(workflows_dir: pathlib.Path) -> dict[str, str]:
    titles: dict[str, str] = {}
    if not workflows_dir.is_dir():
        return titles
    for path in sorted(workflows_dir.glob('*.md')):
        rel = f'workflows/{path.name}'
        for line in path.read_text(encoding='utf-8').splitlines():
            match = HEADING_RE.match(line)
            if match:
                titles[rel] = match.group(1)
                break
    return titles


def title_from_step_id(step_id: str) -> str:
    return ' '.join(part.capitalize() for part in step_id.split('-'))


def build_index(root: pathlib.Path) -> dict:
    manifest = manifest_io.load_manifest(manifest_io.manifest_path(root))
    titles = scan_workflow_titles(root / 'workflows')

    stages: list[dict] = []
    for stage in manifest.get('stages') or []:
        if not isinstance(stage, dict):
            continue
        step_id = stage.get('step_id')
        if not step_id:
            continue
        workflow_doc = stage.get('workflow_doc')
        if workflow_doc:
            title = titles.get(str(workflow_doc), title_from_step_id(str(step_id)))
        else:
            title = title_from_step_id(str(step_id))
        stages.append(
            {
                'step_id': step_id,
                'workflow_doc': workflow_doc,
                'title': title,
                'load_tier': DEFAULT_LOAD_TIER,
            }
        )

    return {
        'generated_from': 'workflows/',
        'manifest': 'core/manifest.yaml',
        'stages': stages,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description='Generate L1 guides/index.json from workflows')
    ap.add_argument('--root', default='.')
    ap.add_argument('--out', default='guides/index.json')
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    try:
        index = build_index(root)
    except (OSError, ValueError) as exc:
        print(f'generate_guides_index failed: {exc}', file=sys.stderr)
        return 1

    out = pathlib.Path(args.out)
    if not out.is_absolute():
        out = root / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(index, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'ok', 'stages': len(index['stages']), 'out': str(out)}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
