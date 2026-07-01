#!/usr/bin/env python3
"""Validate required AI hypothesis artifacts."""
from __future__ import annotations

import argparse
import pathlib
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json

REQUIRED = {
    'id', 'profile', 'component', 'assumption', 'attacker_controlled_input',
    'possible_gap', 'possible_sink', 'validation_method', 'confidence'
}
CONFIDENCE = {'low', 'medium', 'high'}


def _hypotheses(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get('hypotheses', [])
    return []


def validate(path: pathlib.Path) -> tuple[bool, list[str], int]:
    errors: list[str] = []
    data = load_json(path, default=None)
    if data is None:
        return False, [f'missing AI hypotheses artifact: {path}'], 0
    hyps = _hypotheses(data)
    if not isinstance(hyps, list) or not hyps:
        return False, ['ai-hypotheses.json must contain a non-empty hypotheses list'], 0
    seen: set[str] = set()
    for i, hyp in enumerate(hyps):
        if not isinstance(hyp, dict):
            errors.append(f'hypotheses[{i}] must be an object')
            continue
        missing = sorted(REQUIRED - set(hyp))
        if missing:
            errors.append(f"hypotheses[{i}] missing required fields: {', '.join(missing)}")
        hid = hyp.get('id')
        if not hid:
            errors.append(f'hypotheses[{i}] missing id')
        elif hid in seen:
            errors.append(f'duplicate hypothesis id: {hid}')
        else:
            seen.add(str(hid))
        if hyp.get('confidence') not in CONFIDENCE:
            errors.append(f"hypotheses[{i}] confidence must be one of {sorted(CONFIDENCE)}")
    return not errors, errors, len(hyps)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--hypotheses', required=True)
    ap.add_argument('--out')
    args = ap.parse_args()
    ok, errors, count = validate(pathlib.Path(args.hypotheses))
    result = {'passed': ok, 'errors': errors, 'hypothesis_count': count}
    if args.out:
        write_json(args.out, result)
    if not ok:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'validated {count} AI hypotheses')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
