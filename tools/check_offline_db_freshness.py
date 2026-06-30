#!/usr/bin/env python3
"""Check offline public vulnerability database freshness manifests."""
from __future__ import annotations
import argparse, datetime as dt, json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from pvas_io import load_json, write_json

SOURCES = ['nvd', 'osv', 'ghsa', 'cisa-kev']
DEFAULT_EXTRA_MANIFESTS = ['openeuler/manifest.json']


def parse_time(s: str | None):
    if not s: return None
    try:
        return dt.datetime.fromisoformat(s.replace('Z', '+00:00'))
    except Exception:
        return None


def check_manifest_file(manifest_path: pathlib.Path, source: str, max_age_days: int) -> dict:
    if not manifest_path.exists():
        return {'source': source, 'manifest': str(manifest_path), 'freshness': 'missing', 'blocking': False, 'limitations': ['manifest missing']}
    try:
        data = load_json(manifest_path, required=True)
    except Exception as exc:
        return {'source': source, 'manifest': str(manifest_path), 'freshness': 'corrupt', 'blocking': True, 'limitations': [f'cannot parse manifest: {exc}']}
    last = data.get('last_updated') or data.get('updated_at') or data.get('retrieved_at') or data.get('data_cutoff')
    ts = parse_time(last)
    if not ts:
        return {'source': source, 'manifest': str(manifest_path), 'last_updated': last or '', 'max_age_days': max_age_days, 'freshness': 'unknown', 'blocking': False, 'limitations': ['last_updated missing or invalid']}
    now = dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    age_days = max(0, (now - ts).days)
    fresh = 'fresh' if age_days <= max_age_days else 'stale'
    return {'source': source, 'manifest': str(manifest_path), 'last_updated': ts.isoformat(), 'age_days': age_days, 'max_age_days': max_age_days, 'freshness': fresh, 'blocking': False, 'limitations': [] if fresh == 'fresh' else ['offline DB is stale; report must include limitation']}


def check_source(root: pathlib.Path, source: str, max_age_days: int) -> dict:
    return check_manifest_file(root / source / 'manifest.json', source.upper(), max_age_days)


def source_label_for_manifest(manifest_path: pathlib.Path) -> str:
    name = manifest_path.parent.name.upper()
    if name == 'OPENEULER':
        return 'OPENEULER-REGISTRY'
    return name or manifest_path.stem.upper()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--db-root', default='offline-bundle/vuln-db')
    ap.add_argument('--max-age-days', type=int, default=7)
    ap.add_argument('--out', default='audit-output/machine/correlation/offline-db-freshness.json')
    ap.add_argument(
        '--extra-manifest',
        action='append',
        default=[],
        help='Additional manifest.json paths to check (repeatable)',
    )
    args = ap.parse_args()
    root = pathlib.Path(args.db_root)
    checks = [check_source(root, s, args.max_age_days) for s in SOURCES]

    seen_manifests: set[str] = set()
    for rel in DEFAULT_EXTRA_MANIFESTS:
        p = root / rel
        key = str(p.resolve()) if p.exists() else str(p)
        if key not in seen_manifests and p.is_file():
            seen_manifests.add(key)
            checks.append(check_manifest_file(p, source_label_for_manifest(p), args.max_age_days))

    for manifest_arg in args.extra_manifest:
        p = pathlib.Path(manifest_arg)
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen_manifests:
            continue
        seen_manifests.add(key)
        checks.append(check_manifest_file(p, source_label_for_manifest(p), args.max_age_days))

    result = {'status': 'blocked' if any(c.get('blocking') for c in checks) else 'ok', 'sources': checks}
    write_json(args.out, result)
    print(json.dumps({'status': result['status'], 'freshness': {c['source']: c['freshness'] for c in checks}}, indent=2))
    return 2 if result['status'] == 'blocked' else 0

if __name__ == '__main__':
    raise SystemExit(main())
