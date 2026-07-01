#!/usr/bin/env python3
"""Prepare the AI-hypothesis work packet without fabricating hypotheses."""
from __future__ import annotations

import argparse
import pathlib
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--ranked-candidates', required=True)
    ap.add_argument('--selected-scope', required=True)
    ap.add_argument('--out-dir', required=True)
    ap.add_argument('--max-candidates', default='20')
    args = ap.parse_args()

    ranked = load_json(args.ranked_candidates, default={}, required=True)
    scope = load_json(args.selected_scope, default={}, required=True)
    candidates = ranked.get('candidates', []) if isinstance(ranked, dict) else []
    try:
        limit = int(args.max_candidates)
    except ValueError:
        limit = 20
    selected = candidates[:limit]
    out_dir = pathlib.Path(args.out_dir)
    task = {
        'task': 'generate-ai-hypotheses',
        'required_output': str(out_dir / 'ai-hypotheses.json'),
        'schema': 'schemas/hypothesis.schema.json or {"hypotheses": [hypothesis]}',
        'selected_scope': scope,
        'candidate_count': len(selected),
        'candidate_ids': [c.get('id') for c in selected if isinstance(c, dict) and c.get('id')],
        'instructions': [
            'Use actual source slices and selected recipes only.',
            'Do not present hypotheses as vulnerabilities.',
            'Write non-empty hypotheses only when grounded in package behavior.',
        ],
    }
    write_json(out_dir / 'ai-hypothesis-task.json', task)
    md = ['# AI Hypothesis Task', '', f"Required output: `{task['required_output']}`", '', '## Candidate IDs']
    md.extend(f"- `{cid}`" for cid in task['candidate_ids'])
    (out_dir / 'ai-hypothesis-task.md').write_text('\n'.join(md) + '\n')
    print(out_dir / 'ai-hypothesis-task.json')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
