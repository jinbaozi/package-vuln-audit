#!/usr/bin/env python3
"""Preflight gate for audit intake artifacts."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from pvas_io import load_json


def validate_intake_dir(intake_dir: pathlib.Path) -> list[str]:
    errors: list[str] = []
    scope = intake_dir / 'scope.md'
    intake = intake_dir / 'intake.json'
    if not scope.is_file() or not scope.read_text(errors='ignore').strip():
        errors.append('missing or empty scope.md')
    data = load_json(intake, required=False)
    if not isinstance(data, dict):
        errors.append('missing or invalid intake.json')
        return errors
    for key in ('authorization', 'scope_summary', 'source_path', 'network_policy'):
        val = data.get(key)
        if not val or (isinstance(val, str) and not val.strip()):
            errors.append(f'intake.json missing or empty: {key}')
    auth = (data.get('authorization') or '').lower()
    if auth in {'', 'tbd', 'unknown', 'pending'}:
        errors.append('authorization not confirmed')
    try:
        import jsonschema

        schema = json.loads((ROOT / 'schemas' / 'intake.schema.json').read_text())
        jsonschema.validate(data, schema)
    except ImportError:
        pass
    except Exception as e:
        errors.append(f'intake schema validation failed: {e}')
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--intake-dir', required=True)
    ap.add_argument('--out')
    args = ap.parse_args()
    errors = validate_intake_dir(pathlib.Path(args.intake_dir))
    result = {'status': 'passed' if not errors else 'blocked', 'errors': errors}
    if args.out:
        out = pathlib.Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2))
    if errors:
        for e in errors:
            print(f'[PVAS-INTAKE-BLOCKED] {e}', file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
