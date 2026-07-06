#!/usr/bin/env python3
"""Aggregate stage exceptions into audit-output/machine/exception-index.json."""
from __future__ import annotations

import argparse
import pathlib
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from pvas_io import load_json, write_json

STEP_AUDIT_DIRS = {
    '00-intake': '00-intake',
    '00-environment': '00-environment',
    '01-package-profile': '01-profile',
    '02-scope-selection': '01-profile',
    '03-tool-scan': '02-tools',
    '04-ai-hypothesis': '03-candidates',
    '05-candidate-review': '03-candidates',
    '06-validation': '04-validation',
    '07-cvss-scoring': '05-findings',
    '08-report': '06-report',
    '09-progressive-disclosure': '07-disclosure',
    '00-workflow-contract': 'machine',
    '00-manifest-validation': 'machine',
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _empty_index() -> dict:
    return {
        'generated_at': _iso_now(),
        'pipeline_decision': 'continue',
        'summary': {
            'failed_after_retries_count': 0,
            'recovered_count': 0,
            'not_applicable_count': 0,
            'manual_review_count': 0,
        },
        'events': [],
        'halted_stages': [],
        'partial_stages': [],
    }


def _event_key(event: dict) -> str:
    return str(event.get('id', ''))


def _merge_events(existing: list[dict], new_events: list[dict]) -> list[dict]:
    by_id: dict[str, dict] = {}
    for event in existing:
        key = _event_key(event)
        if key:
            by_id[key] = event
    for event in new_events:
        key = _event_key(event)
        if key:
            by_id[key] = event
    return list(by_id.values())


def _count_manual_review(audit_output: pathlib.Path) -> int:
    manual_root = audit_output / '04-validation' / 'manual-review'
    if not manual_root.is_dir():
        return 0
    return sum(1 for p in manual_root.iterdir() if p.is_dir())


def _scan_workflow_steps(audit_output: pathlib.Path) -> tuple[list[dict], list[str], list[str]]:
    events: list[dict] = []
    halted_stages: list[str] = []
    partial_stages: list[str] = []
    steps_dir = audit_output / 'machine' / 'workflow-steps'
    if not steps_dir.is_dir():
        return events, halted_stages, partial_stages

    for step_path in sorted(steps_dir.glob('*.json')):
        step = load_json(step_path, default={})
        if not isinstance(step, dict):
            continue
        step_id = step.get('step_id') or step_path.stem
        status = step.get('status', '')
        limitations = step.get('limitations') or []
        issues = step.get('blocking_issues') or []
        if status == 'failed-after-retries':
            if step_id not in halted_stages:
                halted_stages.append(step_id)
            message = '; '.join(str(i) for i in issues) if issues else step.get('last_error_summary') or f'{step_id} failed after retries'
            events.append({
                'id': f'EX-{step_id}-failed-after-retries',
                'step_id': step_id,
                'audit_output_dir': STEP_AUDIT_DIRS.get(step_id, ''),
                'class': 'failed-after-retries',
                'code': f'{step_id}.failed-after-retries',
                'message': message,
                'final_decision': 'failed',
                'attempt_count': step.get('attempt_count', 0),
                'last_error_summary': step.get('last_error_summary', ''),
                'recovery_actions': step.get('recovery_actions') or [],
                'artifact_refs': step.get('artifact_refs') or step.get('outputs_written') or [],
            })
            continue
        if status == 'completed-with-recovery':
            events.append({
                'id': f'EX-{step_id}-recovered',
                'step_id': step_id,
                'audit_output_dir': STEP_AUDIT_DIRS.get(step_id, ''),
                'class': 'recovered',
                'code': f'{step_id}.completed-with-recovery',
                'message': step.get('last_error_summary') or f'{step_id} recovered after retry',
                'final_decision': 'continue',
                'attempt_count': step.get('attempt_count', 0),
                'last_error_summary': step.get('last_error_summary', ''),
                'recovery_actions': step.get('recovery_actions') or [],
                'artifact_refs': step.get('artifact_refs') or step.get('outputs_written') or [],
            })
            continue
        if status == 'not-applicable':
            if step_id not in partial_stages:
                partial_stages.append(step_id)
            events.append({
                'id': f'EX-{step_id}-not-applicable',
                'step_id': step_id,
                'audit_output_dir': STEP_AUDIT_DIRS.get(step_id, ''),
                'class': 'not-applicable',
                'code': f'{step_id}.not-applicable',
                'message': '; '.join(str(x) for x in limitations) if limitations else 'stage executed and determined not applicable',
                'final_decision': 'continue',
                'attempt_count': step.get('attempt_count', 0),
                'last_error_summary': step.get('last_error_summary', ''),
                'recovery_actions': step.get('recovery_actions') or [],
                'artifact_refs': step.get('artifact_refs') or step.get('outputs_written') or [],
            })
    return events, halted_stages, partial_stages


def _schema_validation_events(audit_output: pathlib.Path) -> list[dict]:
    result = load_json(audit_output / 'machine' / 'schema-validation-result.json', default=None)
    if not isinstance(result, dict) or result.get('passed') is not False:
        return []
    errors = result.get('errors') or []
    return [{
        'id': 'EX-SCH-002',
        'step_id': '06-validation',
        'audit_output_dir': 'machine',
        'class': 'failed-after-retries',
        'code': 'EX-SCH-002',
        'message': '; '.join(str(e) for e in errors) if errors else 'schema validation failed',
        'final_decision': 'failed',
        'attempt_count': 0,
        'last_error_summary': '; '.join(str(e) for e in errors),
        'recovery_actions': ['regenerate upstream finding JSON and rerun schema validation'],
        'artifact_refs': ['audit-output/machine/schema-validation-result.json'],
    }]


def _tool_summary_events(audit_output: pathlib.Path) -> list[dict]:
    summary = load_json(audit_output / '02-tools' / 'tool-summary.json', default=None)
    if not isinstance(summary, dict):
        return []
    events: list[dict] = []
    for tool in summary.get('tools') or []:
        if not isinstance(tool, dict):
            continue
        name = tool.get('name') or 'unknown'
        reason = tool.get('reason') or tool.get('notes') or tool.get('status') or 'unknown'
        if tool.get('status') == 'not-applicable':
            events.append({
                'id': f'EX-03-tool-scan-{name}-na',
                'step_id': '03-tool-scan',
                'audit_output_dir': '02-tools',
                'class': 'not-applicable',
                'code': f'tool.{name}.not-applicable',
                'message': str(reason),
                'final_decision': 'continue',
                'attempt_count': 1,
                'last_error_summary': '',
                'recovery_actions': [],
                'artifact_refs': ['audit-output/02-tools/tool-summary.json'],
            })
            continue
        if tool.get('strict_decision') == 'block' or tool.get('status') in {
            'blocked-pending-confirmation',
            'blocked-recovery-required',
            'abnormal',
            'incomplete',
            'not-installed',
            'malformed-output',
            'nonzero-exit',
        }:
            events.append({
                'id': f'EX-03-tool-scan-{name}-blocked',
                'step_id': '03-tool-scan',
                'audit_output_dir': '02-tools',
                'class': 'failed-after-retries',
                'code': f'tool.{name}.blocked',
                'message': f'{name}: {reason}',
                'final_decision': 'failed',
                'attempt_count': 1,
                'last_error_summary': str(reason),
                'recovery_actions': ['recover or install required tools, then rerun tool scan'],
                'artifact_refs': ['audit-output/02-tools/tool-summary.json'],
            })
    return events


def _summary_from_events(events: list[dict], manual_review_count: int) -> dict:
    return {
        'failed_after_retries_count': sum(1 for e in events if e.get('class') == 'failed-after-retries'),
        'recovered_count': sum(1 for e in events if e.get('class') == 'recovered'),
        'not_applicable_count': sum(1 for e in events if e.get('class') == 'not-applicable'),
        'manual_review_count': manual_review_count,
    }


def _pipeline_decision(events: list[dict]) -> str:
    if any(e.get('class') == 'failed-after-retries' for e in events):
        return 'failed'
    return 'continue'


def aggregate_exceptions(audit_output: pathlib.Path, *, merge: bool = False) -> dict:
    base = _empty_index()
    if merge:
        existing = load_json(audit_output / 'machine' / 'exception-index.json', default=None)
        if isinstance(existing, dict):
            base['events'] = list(existing.get('events') or [])
            base['halted_stages'] = list(existing.get('halted_stages') or [])
            base['partial_stages'] = list(existing.get('partial_stages') or [])

    step_events, halted, partial = _scan_workflow_steps(audit_output)
    new_events = step_events + _schema_validation_events(audit_output) + _tool_summary_events(audit_output)
    events = _merge_events(base['events'], new_events) if merge else new_events
    halted_stages = sorted(set(base['halted_stages']) | set(halted))
    partial_stages = sorted(set(base['partial_stages']) | set(partial))
    manual_review_count = _count_manual_review(audit_output)

    return {
        'generated_at': _iso_now(),
        'pipeline_decision': _pipeline_decision(events),
        'summary': _summary_from_events(events, manual_review_count),
        'events': events,
        'halted_stages': halted_stages,
        'partial_stages': partial_stages,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--audit-output', required=True)
    ap.add_argument('--out', help='Output path (default: <audit-output>/machine/exception-index.json)')
    ap.add_argument('--merge', action=argparse.BooleanOptionalAction, default=False)
    args = ap.parse_args()
    audit_output = pathlib.Path(args.audit_output)
    out_path = pathlib.Path(args.out) if args.out else audit_output / 'machine' / 'exception-index.json'
    index = aggregate_exceptions(audit_output, merge=args.merge)
    write_json(out_path, index)
    print({'pipeline_decision': index['pipeline_decision'], 'out': str(out_path)})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
