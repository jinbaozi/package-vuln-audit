#!/usr/bin/env python3
"""Preflight gate for audit intake artifacts."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from pvas_io import load_json, write_json, emit_gate_result

NETWORK_POLICY_VALUES = ("offline", "restricted", "online-approved")
NETWORK_POLICY_ALIASES = {
    "offline": "offline",
    "off-line": "offline",
    "no network": "offline",
    "no-network": "offline",
    "airgap": "offline",
    "air-gapped": "offline",
    "air gapped": "offline",
    "restricted": "restricted",
    "limited": "restricted",
    "default": "restricted",
    "internal": "restricted",
    "intranet": "restricted",
    "approved only": "restricted",
    "online-approved": "online-approved",
    "online approved": "online-approved",
    "approved-online": "online-approved",
    "network approved": "online-approved",
    "internet approved": "online-approved",
    "online": "online-approved",
}


def normalize_network_policy(value: object) -> tuple[str | None, str | None]:
    """Map common legacy/free-text network policies to the schema enum."""
    if not isinstance(value, str):
        return None, "network_policy must be a string"
    raw = " ".join(value.strip().lower().replace("_", "-").split())
    raw = raw.replace(" - ", "-")
    if raw in NETWORK_POLICY_ALIASES:
        return NETWORK_POLICY_ALIASES[raw], None
    compact = raw.replace("-", " ")
    if compact in NETWORK_POLICY_ALIASES:
        return NETWORK_POLICY_ALIASES[compact], None
    return None, (
        f"network_policy unsupported value {value!r}; "
        f"allowed values: {', '.join(NETWORK_POLICY_VALUES)}"
    )


def validate_intake_dir(intake_dir: pathlib.Path, *, require_present: bool = False) -> list[str]:
    errors: list[str] = []
    scope = intake_dir / 'scope.md'
    intake = intake_dir / 'intake.json'
    scope_exists = scope.is_file()
    intake_exists = intake.is_file()
    if not scope_exists and not intake_exists:
        if require_present:
            errors.append('missing scope.md and intake.json')
        return errors
    if not scope_exists or not scope.read_text(errors='ignore').strip():
        errors.append('missing or empty scope.md')
    data = load_json(intake, required=False)
    if not isinstance(data, dict):
        errors.append('missing or invalid intake.json')
        return errors
    normalized_policy, policy_error = normalize_network_policy(data.get('network_policy'))
    if policy_error:
        errors.append(policy_error)
    elif normalized_policy and normalized_policy != data.get('network_policy'):
        data['network_policy'] = normalized_policy
        write_json(intake, data)
    for key in ('authorization', 'scope_summary', 'source_path', 'network_policy'):
        val = data.get(key)
        if not val or (isinstance(val, str) and not val.strip()):
            errors.append(f'intake.json missing or empty: {key}')
    auth = (data.get('authorization') or '').lower()
    if auth in {'', 'tbd', 'unknown', 'pending'}:
        errors.append('authorization not confirmed')
    try:
        import jsonschema

        schema = load_json(ROOT / 'schemas' / 'intake.schema.json', required=True)
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
    ap.add_argument('--require-present', action='store_true',
                    help='Require scope.md and intake.json (complete-audit path)')
    args = ap.parse_args()
    errors = validate_intake_dir(pathlib.Path(args.intake_dir), require_present=args.require_present)
    result = {'status': 'passed' if not errors else 'blocked', 'errors': errors}
    if args.out:
        emit_gate_result(args.out, result)
    if errors:
        for e in errors:
            print(f'[PVAS-INTAKE-BLOCKED] {e}', file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
