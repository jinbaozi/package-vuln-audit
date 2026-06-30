#!/usr/bin/env python3
"""Apply public-vuln correlation results to Validated findings (disclosure_status only)."""
from __future__ import annotations

import argparse
import json
import pathlib

from pvas_io import corr_map, load_findings, load_json, write_json


def ref_key(ref: dict) -> tuple[str, str]:
    return (str(ref.get('source', '')), str(ref.get('id', '')))


def correlation_ref(record: dict) -> dict:
    ref: dict = {
        'source': record.get('source', ''),
        'id': record.get('id', ''),
    }
    if record.get('url'):
        ref['url'] = record['url']
    if record.get('match_level'):
        ref['match_level'] = record['match_level']
    return ref


def merge_refs(existing: list[dict], incoming: list[dict]) -> list[dict]:
    merged: dict[tuple[str, str], dict] = {}
    for ref in existing or []:
        if isinstance(ref, dict) and ref.get('id'):
            merged[ref_key(ref)] = dict(ref)
    for ref in incoming:
        key = ref_key(ref)
        if key in merged:
            cur = merged[key]
            for field in ('url', 'match_level'):
                if not cur.get(field) and ref.get(field):
                    cur[field] = ref[field]
        else:
            merged[key] = dict(ref)
    return list(merged.values())


def apply_correlation(findings: list[dict], correlations: dict[str, dict]) -> dict:
    updated: list[str] = []
    skipped_non_validated: list[str] = []
    disclosure_levels_before: dict[str, str] = {}

    for f in findings:
        fid = f.get('id', '')
        if f.get('status') != 'Validated':
            skipped_non_validated.append(fid)
            continue
        corr = correlations.get(fid)
        if not corr:
            continue

        disclosure_levels_before[fid] = f.get('disclosure_level', '')
        f['disclosure_status'] = corr.get('status', f.get('disclosure_status', 'unknown'))

        if corr.get('status') == 'publicly_disclosed':
            incoming = [
                correlation_ref(r)
                for r in corr.get('matched_records') or []
                if isinstance(r, dict) and r.get('id')
            ]
            f['public_vulnerability_references'] = merge_refs(
                f.get('public_vulnerability_references') or [],
                incoming,
            )

        updated.append(fid)

    unchanged = all(
        f.get('disclosure_level', '') == disclosure_levels_before.get(f.get('id', ''), '')
        for f in findings
        if f.get('id') in disclosure_levels_before
    )

    return {
        'updated_findings': updated,
        'skipped_non_validated': skipped_non_validated,
        'applied_count': len(updated),
        'unchanged_disclosure_level': unchanged,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--findings', required=True)
    ap.add_argument('--correlation', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument(
        '--summary-out',
        default='',
        help='default: same dir as correlation → apply-correlation-result.json',
    )
    args = ap.parse_args()

    findings_path = pathlib.Path(args.findings)
    corr_path = pathlib.Path(args.correlation)
    out_path = pathlib.Path(args.out)

    raw = load_json(findings_path, required=True)
    wrapper = isinstance(raw, dict) and 'findings' in raw
    findings = load_findings(findings_path)
    correlations = corr_map(load_json(corr_path, required=True))

    summary = apply_correlation(findings, correlations)

    if wrapper:
        raw['findings'] = findings
        write_json(out_path, raw)
    else:
        write_json(out_path, {'findings': findings})

    summary_out = pathlib.Path(args.summary_out) if args.summary_out else (
        corr_path.parent / 'apply-correlation-result.json'
    )
    write_json(summary_out, summary)
    print(f'[PVAS-APPLY-CORRELATION] updated {summary["applied_count"]} findings → {out_path}')
    print(f'[PVAS-APPLY-CORRELATION] summary → {summary_out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
