#!/usr/bin/env python3
"""Tool-level Python startup hooks.

This file is imported automatically by Python when scripts are executed from the
`tools/` directory. Keep the hook intentionally narrow: only final-report
processes are post-processed, and all failures are reported as warnings instead
of changing the underlying report generation exit code.
"""
from __future__ import annotations

import atexit
import pathlib
import sys


def _arg_value(argv: list[str], name: str, default: str | None = None) -> str | None:
    if name not in argv:
        return default
    idx = argv.index(name)
    if idx + 1 >= len(argv):
        return default
    return argv[idx + 1]


def _register_final_report_postprocess() -> None:
    script = pathlib.Path(sys.argv[0]).name
    if script != 'generate_final_report.py':
        return

    argv = list(sys.argv[1:])
    audit_root = pathlib.Path(_arg_value(argv, '--audit-root', 'audit-output') or 'audit-output')
    out_root = pathlib.Path(_arg_value(argv, '--out', 'audit-output/06-report') or 'audit-output/06-report')
    findings_arg = _arg_value(argv, '--findings')
    correlation_arg = _arg_value(argv, '--correlation')
    findings = pathlib.Path(findings_arg) if findings_arg else None
    correlation = pathlib.Path(correlation_arg) if correlation_arg else None

    def _postprocess() -> None:
        try:
            from report_status import postprocess_final_report
            status = postprocess_final_report(
                audit_root=audit_root,
                out_root=out_root,
                findings_path=findings,
                correlation_path=correlation,
            )
            print(
                '[PVAS-REPORT-STATUS] '
                f"type={status.get('report_type')} "
                f"negative_conclusion_allowed={status.get('negative_conclusion_allowed')}"
            )
        except Exception as exc:  # pragma: no cover - defensive startup hook
            print(f'[PVAS-REPORT-STATUS-WARN] postprocess failed: {exc}', file=sys.stderr)

    atexit.register(_postprocess)


_register_final_report_postprocess()
