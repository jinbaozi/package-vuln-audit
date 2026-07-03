#!/usr/bin/env python3
"""Create the authoritative finding-index.json from validation output."""
from __future__ import annotations

import argparse
import pathlib
import sys
from datetime import datetime, timezone

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import findings_list, load_json, write_json

REPORTABLE = {'Validated', 'Needs Manual Review'}


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--validation-findings', required=True)
    ap.add_argument('--validation-targets')
    ap.add_argument('--candidate-summary-ref', required=True)
    ap.add_argument('--validation-summary-ref', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    findings = findings_list(load_json(args.validation_findings, {'findings': []}))
    targets = load_json(args.validation_targets, {}) if args.validation_targets else {}
    rejected_summary = []
    if isinstance(targets, dict):
        rejected_summary.extend(x for x in targets.get('rejected_summary') or [] if isinstance(x, dict))
    reportable = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        status = finding.get('status')
        if status in REPORTABLE:
            reportable.append(finding)
        elif status == 'Rejected':
            rejected_summary.append({
                'id': finding.get('id', '?'),
                'status': 'Rejected',
                'reason': finding.get('false_positive_exclusion') or finding.get('manual_review_reason') or '',
            })
    payload = {
        'schema_version': '1.0',
        'generated_at': _iso_now(),
        'findings': reportable,
        'rejected_summary': rejected_summary,
        'candidate_summary_ref': args.candidate_summary_ref,
        'validation_summary_ref': args.validation_summary_ref,
        'reportable_statuses': sorted(REPORTABLE),
    }
    write_json(args.out, payload)
    print(f"[PVAS-FINDINGS] wrote {args.out} ({len(reportable)} reportable finding(s))")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
