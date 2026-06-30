#!/usr/bin/env python3
"""CVSS v3.1 Base Score calculator (stdlib only). Aligned with FIRST spec / cvssjs."""
from __future__ import annotations
import argparse
import json
import math
import pathlib
import sys

METRICS = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},
    'PR_S': {'N': 0.85, 'L': 0.68, 'H': 0.50},
    'UI': {'N': 0.85, 'R': 0.62},
    'S': {'U': False, 'C': True},
    'C': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'I': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'A': {'H': 0.56, 'L': 0.22, 'N': 0.0},
}


def parse_vector(vector: str) -> dict[str, str]:
    if not vector.startswith('CVSS:3.1/'):
        raise ValueError('expected CVSS:3.1/ prefix')
    parts: dict[str, str] = {}
    for seg in vector.split('/')[1:]:
        if ':' not in seg:
            continue
        k, v = seg.split(':', 1)
        parts[k] = v
    for k in ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'):
        if k not in parts:
            raise ValueError(f'missing metric {k}')
        if k == 'AV' and parts[k] not in METRICS['AV']:
            raise ValueError(f'invalid AV: {parts[k]}')
        if k == 'AC' and parts[k] not in METRICS['AC']:
            raise ValueError(f'invalid AC: {parts[k]}')
        if k == 'PR' and parts[k] not in METRICS['PR']:
            raise ValueError(f'invalid PR: {parts[k]}')
        if k == 'UI' and parts[k] not in METRICS['UI']:
            raise ValueError(f'invalid UI: {parts[k]}')
        if k == 'S' and parts[k] not in METRICS['S']:
            raise ValueError(f'invalid S: {parts[k]}')
        if k in ('C', 'I', 'A') and parts[k] not in METRICS['C']:
            raise ValueError(f'invalid {k}: {parts[k]}')
    return parts


def roundup(n: float) -> float:
    return math.ceil(n * 10) / 10.0


def severity(score: float) -> str:
    if score <= 0:
        return 'None'
    if score < 4.0:
        return 'Low'
    if score < 7.0:
        return 'Medium'
    if score < 9.0:
        return 'High'
    return 'Critical'


def base_score(m: dict[str, str]) -> float:
    scope_changed = METRICS['S'][m['S']]
    pr_map = METRICS['PR_S'] if scope_changed else METRICS['PR']
    iss = 1 - (1 - METRICS['C'][m['C']]) * (1 - METRICS['I'][m['I']]) * (1 - METRICS['A'][m['A']])
    if iss <= 0:
        return 0.0
    if scope_changed:
        isc = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        if isc <= 0:
            return 0.0
    else:
        isc = 6.42 * iss
    exploit = 8.22 * METRICS['AV'][m['AV']] * METRICS['AC'][m['AC']] * pr_map[m['PR']] * METRICS['UI'][m['UI']]
    if scope_changed:
        score = min(1.08 * (isc + exploit), 10)
    else:
        score = min(isc + exploit, 10)
    return roundup(score)


def compute(vector: str) -> dict:
    m = parse_vector(vector)
    score = base_score(m)
    return {'version': '3.1', 'vector': vector, 'base_score': score, 'severity': severity(score)}


def validate_artifact(data: dict) -> list[str]:
    errors: list[str] = []
    cvss = data.get('cvss', data)
    vector = cvss.get('vector', '')
    if not vector.startswith('CVSS:3.1/'):
        return [f'not a 3.1 vector: {vector}']
    calc = compute(vector)
    if abs(float(cvss.get('base_score', -1)) - calc['base_score']) > 0.11:
        errors.append(f'base_score mismatch: {cvss.get("base_score")} vs {calc["base_score"]}')
    if cvss.get('severity') and cvss['severity'] != calc['severity']:
        errors.append(f'severity mismatch: {cvss.get("severity")} vs {calc["severity"]}')
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--vector')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--in', dest='inp')
    args = ap.parse_args()
    if args.validate:
        if not args.inp:
            print('error: --in required with --validate', file=sys.stderr)
            return 2
        data = json.loads(pathlib.Path(args.inp).read_text())
        errs = validate_artifact(data)
        if errs:
            print(json.dumps({'valid': False, 'errors': errs}, indent=2))
            return 1
        print(json.dumps({'valid': True}, indent=2))
        return 0
    if not args.vector:
        ap.error('--vector or --validate --in required')
    try:
        print(json.dumps(compute(args.vector), indent=2))
    except ValueError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
