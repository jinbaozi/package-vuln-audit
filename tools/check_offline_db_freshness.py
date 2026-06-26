#!/usr/bin/env python3
"""Check offline public vulnerability database freshness manifests."""
from __future__ import annotations
import argparse, datetime as dt, json, pathlib, sys

SOURCES = ['nvd', 'osv', 'ghsa', 'cisa-kev']


def parse_time(s: str | None):
    if not s: return None
    try:
        return dt.datetime.fromisoformat(s.replace('Z', '+00:00'))
    except Exception:
        return None


def check_source(root: pathlib.Path, source: str, max_age_days: int) -> dict:
    p = root / source / 'manifest.json'
    if not p.exists():
        return {'source': source.upper(), 'manifest': str(p), 'freshness': 'missing', 'blocking': False, 'limitations': ['manifest missing']}
    try:
        data = json.loads(p.read_text())
    except Exception as exc:
        return {'source': source.upper(), 'manifest': str(p), 'freshness': 'corrupt', 'blocking': True, 'limitations': [f'cannot parse manifest: {exc}']}
    last = data.get('last_updated') or data.get('updated_at') or data.get('retrieved_at')
    ts = parse_time(last)
    if not ts:
        return {'source': source.upper(), 'manifest': str(p), 'last_updated': last or '', 'max_age_days': max_age_days, 'freshness': 'unknown', 'blocking': False, 'limitations': ['last_updated missing or invalid']}
    now = dt.datetime.now(dt.timezone.utc)
    age_days = max(0, (now - ts).days)
    fresh = 'fresh' if age_days <= max_age_days else 'stale'
    return {'source': source.upper(), 'manifest': str(p), 'last_updated': ts.isoformat(), 'age_days': age_days, 'max_age_days': max_age_days, 'freshness': fresh, 'blocking': False, 'limitations': [] if fresh == 'fresh' else ['offline DB is stale; report must include limitation']}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--db-root', default='offline-bundle/vuln-db')
    ap.add_argument('--max-age-days', type=int, default=7)
    ap.add_argument('--out', default='audit-output/machine/correlation/offline-db-freshness.json')
    args = ap.parse_args()
    root = pathlib.Path(args.db_root)
    checks = [check_source(root, s, args.max_age_days) for s in SOURCES]
    result = {'status': 'blocked' if any(c.get('blocking') for c in checks) else 'ok', 'sources': checks}
    out = pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(result, indent=2))
    print(json.dumps({'status': result['status'], 'freshness': {c['source']: c['freshness'] for c in checks}}, indent=2))
    return 2 if result['status'] == 'blocked' else 0

if __name__ == '__main__':
    raise SystemExit(main())
