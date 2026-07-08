#!/usr/bin/env python3
"""Generate final report and explicitly attach report-status metadata.

This command is an explicit replacement for relying on the `sitecustomize.py`
post-processing hook when producing final reports. It intentionally preserves the
same CLI contract as `generate_final_report.py` and then invokes
`report_status.postprocess_final_report()` with the resolved arguments.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import generate_final_report
import report_status


def parse_known_report_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--audit-root', default='audit-output')
    parser.add_argument('--findings')
    parser.add_argument('--correlation')
    parser.add_argument('--out', default='audit-output/06-report')
    args, _unknown = parser.parse_known_args(argv)
    return args


def main() -> int:
    args = parse_known_report_args(sys.argv[1:])
    rc = generate_final_report.main()
    if rc != 0:
        return rc
    status = report_status.postprocess_final_report(
        audit_root=pathlib.Path(args.audit_root),
        out_root=pathlib.Path(args.out),
        findings_path=pathlib.Path(args.findings) if args.findings else None,
        correlation_path=pathlib.Path(args.correlation) if args.correlation else None,
    )
    print(
        '[PVAS-REPORT-STATUS] '
        f"type={status.get('report_type')} "
        f"negative_conclusion_allowed={status.get('negative_conclusion_allowed')}"
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
