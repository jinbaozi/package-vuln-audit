#!/usr/bin/env python3
"""Validate that Top-N candidate review packets cover ranked candidates."""
from __future__ import annotations

import argparse
import pathlib
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json


def _candidate_ids(path: pathlib.Path, limit: int) -> list[str]:
    data = load_json(path, default={}, required=True)
    candidates = data.get('candidates', []) if isinstance(data, dict) else []
    ids = []
    for c in candidates[:limit]:
        if isinstance(c, dict) and c.get('id'):
            ids.append(str(c['id']))
    return ids


def _reviewed_ids(review_dir: pathlib.Path) -> set[str]:
    ids: set[str] = set()
    if not review_dir.is_dir():
        return ids
    for path in sorted(review_dir.glob('*.json')):
        data = load_json(path, default={})
        if not isinstance(data, dict):
            continue
        rid = data.get('candidate_id') or data.get('id')
        if not rid and isinstance(data.get('candidate'), dict):
            rid = data['candidate'].get('id')
        if rid:
            ids.add(str(rid))
    return ids


def validate(ranked: pathlib.Path, review_dir: pathlib.Path, limit: int) -> tuple[bool, list[str], dict]:
    required = _candidate_ids(ranked, limit)
    reviewed = _reviewed_ids(review_dir)
    if not required:
        return True, [], {'required_candidate_ids': [], 'reviewed_candidate_ids': sorted(reviewed), 'not_applicable': True}
    missing = [cid for cid in required if cid not in reviewed]
    errors = [f'missing candidate review for {cid}' for cid in missing]
    return not errors, errors, {'required_candidate_ids': required, 'reviewed_candidate_ids': sorted(reviewed), 'not_applicable': False}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--ranked-candidates', required=True)
    ap.add_argument('--review-dir', required=True)
    ap.add_argument('--max-candidates', type=int, default=20)
    ap.add_argument('--out')
    args = ap.parse_args()
    ok, errors, detail = validate(pathlib.Path(args.ranked_candidates), pathlib.Path(args.review_dir), args.max_candidates)
    result = {'passed': ok, 'errors': errors, **detail}
    if args.out:
        write_json(args.out, result)
    if not ok:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('candidate review coverage valid')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
