#!/usr/bin/env python3
"""Soft-fail handling for missing public vulnerability correlation sources.

Complete internal audits may run in restricted/offline environments where public
vulnerability records are not configured. A Validated finding still needs an
explicit disclosure-correlation state, but the workflow should be able to produce
an internal degraded report instead of stopping before report generation.
"""
from __future__ import annotations

import os
import pathlib
import sys
from typing import Any

PUBLIC_CORRELATION_REQUIRED_ISSUE = 'Validated findings require configured public vulnerability correlation sources'
CORRELATION_NOT_CONFIGURED_STATUS = 'correlation_not_configured'
CORRELATION_NOT_CONFIGURED_REASON = 'public vulnerability records not configured; public disclosure status is unknown'
CORRELATION_NOT_CONFIGURED_LIMITATION = 'public vulnerability correlation was not configured; internal degraded report generated'


def env_truthy(name: str) -> bool:
    return str(os.environ.get(name, '')).strip().lower() in {'1', 'true', 'yes', 'on'}


def hard_correlation_required() -> bool:
    """Return True when strict deployments still require public records to proceed."""
    return env_truthy('PVAS_REQUIRE_PUBLIC_CORRELATION_FOR_VALIDATED')


def issue_matches(issues: list[str] | tuple[str, ...] | None) -> bool:
    return PUBLIC_CORRELATION_REQUIRED_ISSUE in [str(issue) for issue in (issues or [])]


def build_not_configured_correlation(validated: list[dict]) -> dict:
    correlations = []
    for finding in validated:
        fid = str(finding.get('id') or '').strip()
        if not fid:
            continue
        correlations.append({
            'finding_id': fid,
            'status': CORRELATION_NOT_CONFIGURED_STATUS,
            'match_level': 'M0',
            'matched_records': [],
            'checked_sources': [],
            'limitations': [CORRELATION_NOT_CONFIGURED_LIMITATION],
        })
    return {
        'schema_version': '1.0',
        'status': CORRELATION_NOT_CONFIGURED_STATUS,
        'reason': CORRELATION_NOT_CONFIGURED_REASON,
        'checked_sources': [],
        'negative_public_disclosure_conclusion_allowed': False,
        'correlations': correlations,
        'limitations': [CORRELATION_NOT_CONFIGURED_LIMITATION],
    }


def _require_callable(value: Any, name: str):
    if not callable(value):
        raise RuntimeError(f'{name} is not callable in enforced driver frame')
    return value


def recover_missing_public_records_from_driver_frame(frame) -> dict:
    """Generate internal degraded report artifacts from the driver's exec_report frame.

    The caller frame is expected to be the nested `exec_report()` frame from
    `enforced_audit_driver.py` at the point where it would otherwise return a
    hard failure for missing public records.
    """
    loc = frame.f_locals
    glob = frame.f_globals
    out = pathlib.Path(loc['out'])
    corr = pathlib.Path(loc['corr'])
    finding_index_path = pathlib.Path(loc['finding_index_path'])
    validated = [f for f in (loc.get('validated') or []) if isinstance(f, dict)]

    run = _require_callable(glob.get('run'), 'run')
    write_json = _require_callable(glob.get('write_json'), 'write_json')

    payload = build_not_configured_correlation(validated)
    write_json(corr, payload)

    # Apply the synthetic correlation so findings no longer carry an ambiguous
    # disclosure_status=unknown. This remains a degraded/unknown public status,
    # not a claim that the issue is unpublished.
    run([
        sys.executable,
        'tools/apply_correlation_to_findings.py',
        '--findings', str(finding_index_path),
        '--correlation', str(corr),
        '--out', str(finding_index_path),
    ], allow_fail=False)

    run([
        sys.executable,
        'tools/publish_bilingual_reports.py',
        '--findings', str(finding_index_path),
        '--correlation', str(corr),
        '--poc-root', str(out / '04-validation/poc-tests'),
        '--out', str(out),
        '--skip-final-report',
    ], allow_fail=False)

    run([
        sys.executable,
        'tools/generate_final_report.py',
        '--audit-root', str(out),
        '--findings', str(finding_index_path),
        '--out', str(out / '06-report'),
        '--correlation', str(corr),
    ], allow_fail=False)

    completeness_path = out / 'machine/report-completeness-pre-disclosure.json'
    completeness_cmd = [
        sys.executable,
        'tools/validate_report_completeness.py',
        '--findings', str(finding_index_path),
        '--correlation', str(corr),
        '--report-root', str(out),
        '--manual-root', str(out / '04-validation/manual-review'),
        '--poc-root', str(out / '04-validation/poc-tests'),
        '--out', str(completeness_path),
    ]
    rc, tool_out = run(completeness_cmd, allow_fail=True)
    if rc != 0:
        raise RuntimeError(tool_out[-1000:] or 'report completeness failed during public-correlation soft-fail recovery')

    return {
        'outputs': [
            str(out / '06-report/machine'),
            str(out / '06-report/zh-CN'),
            str(out / '06-report/en-US'),
            str(completeness_path),
            str(corr),
        ],
        'limitations': [CORRELATION_NOT_CONFIGURED_LIMITATION],
        'details': {
            'public_correlation_status': CORRELATION_NOT_CONFIGURED_STATUS,
            'negative_public_disclosure_conclusion_allowed': False,
            'correlation': str(corr),
        },
    }


def maybe_recover_missing_public_records(frame, issues: list[str] | tuple[str, ...] | None) -> dict | None:
    if hard_correlation_required() or not issue_matches(issues):
        return None
    return recover_missing_public_records_from_driver_frame(frame)
