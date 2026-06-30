#!/usr/bin/env python3
"""Aggregate stage exceptions into audit-output/machine/exception-index.json."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from pvas_io import load_json, write_json

MANDATORY_HALT_STEPS = frozenset({'03-tool-scan', '07-schema-validation', '07-poc-generation'})

STEP_AUDIT_DIRS = {
    '03-tool-scan': '02-tools',
    '07-schema-validation': 'machine',
    '07-poc-generation': '04-validation',
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _empty_index() -> dict:
    return {
        'generated_at': _iso_now(),
        'pipeline_decision': 'continue',
        'summary': {
            'blocked_count': 0,
            'recoverable_count': 0,
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
        decision = step.get('decision', '')
        limitations = step.get('limitations') or []

        if status in {'blocked', 'failed'} and decision == 'block':
            if step_id not in halted_stages:
                halted_stages.append(step_id)
            issues = step.get('blocking_issues') or []
            message = '; '.join(str(i) for i in issues) if issues else f'{step_id} {status}'
            events.append({
                'id': f'EX-{step_id}-blocked',
                'step_id': step_id,
                'audit_output_dir': STEP_AUDIT_DIRS.get(step_id, ''),
                'class': 'blocked',
                'code': f'{step_id}.blocked',
                'message': message,
                'final_decision': 'block',
            })
            continue

        if status == 'partial':
            if step_id not in partial_stages:
                partial_stages.append(step_id)
            if limitations:
                events.append({
                    'id': f'EX-{step_id}-partial',
                    'step_id': step_id,
                    'class': 'recoverable',
                    'code': f'{step_id}.partial',
                    'message': '; '.join(str(x) for x in limitations),
                    'final_decision': 'continue',
                })
    return events, halted_stages, partial_stages


def _schema_validation_events(audit_output: pathlib.Path) -> list[dict]:
    result = load_json(audit_output / 'machine' / 'schema-validation-result.json', default=None)
    if not isinstance(result, dict) or result.get('passed') is not False:
        return []
    errors = result.get('errors') or []
    message = '; '.join(str(e) for e in errors) if errors else 'schema validation failed'
    return [{
        'id': 'EX-SCH-002',
        'step_id': '07-schema-validation',
        'audit_output_dir': 'machine',
        'class': 'blocked',
        'code': 'EX-SCH-002',
        'message': message,
        'final_decision': 'block',
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
        if tool.get('status') != 'not-applicable':
            continue
        name = tool.get('name') or 'unknown'
        reason = tool.get('reason') or tool.get('notes') or 'not applicable to this project'
        events.append({
            'id': f'EX-03-tool-scan-{name}-na',
            'step_id': '03-tool-scan',
            'audit_output_dir': '02-tools',
            'class': 'not-applicable',
            'code': f'tool.{name}.not-applicable',
            'message': str(reason),
            'final_decision': 'continue',
            'artifact_refs': ['audit-output/02-tools/tool-summary.json'],
        })
    return events


def _summary_from_events(events: list[dict], manual_review_count: int) -> dict:
    blocked = sum(1 for e in events if e.get('class') == 'blocked')
    recoverable = sum(1 for e in events if e.get('class') == 'recoverable')
    not_applicable = sum(1 for e in events if e.get('class') == 'not-applicable')
    return {
        'blocked_count': blocked,
        'recoverable_count': recoverable,
        'not_applicable_count': not_applicable,
        'manual_review_count': manual_review_count,
    }


def _pipeline_decision(halted_stages: list[str], events: list[dict]) -> str:
    if MANDATORY_HALT_STEPS.intersection(halted_stages):
        return 'halt'
    for event in events:
        if event.get('class') == 'blocked' and event.get('final_decision') != 'completed':
            return 'halt'
    return 'continue'


def aggregate_exceptions(audit_output: pathlib.Path, *, merge: bool = True) -> dict:
    base = _empty_index()
    if merge:
        existing = load_json(audit_output / 'machine' / 'exception-index.json', default=None)
        if isinstance(existing, dict):
            base['events'] = list(existing.get('events') or [])
            base['halted_stages'] = list(existing.get('halted_stages') or [])
            base['partial_stages'] = list(existing.get('partial_stages') or [])

    step_events, halted, partial = _scan_workflow_steps(audit_output)
    schema_events = _schema_validation_events(audit_output)
    tool_events = _tool_summary_events(audit_output)
    new_events = step_events + schema_events + tool_events

    events = _merge_events(base['events'], new_events) if merge else new_events

    halted_stages = sorted(set(base['halted_stages']) | set(halted))
    partial_stages = sorted(set(base['partial_stages']) | set(partial))

    manual_review_count = _count_manual_review(audit_output)

    return {
        'generated_at': _iso_now(),
        'pipeline_decision': _pipeline_decision(halted_stages, events),
        'summary': _summary_from_events(events, manual_review_count),
        'events': events,
        'halted_stages': halted_stages,
        'partial_stages': partial_stages,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--audit-output', required=True)
    ap.add_argument('--out', help='Output path (default: <audit-output>/machine/exception-index.json)')
    ap.add_argument('--merge', action=argparse.BooleanOptionalAction, default=True)
    args = ap.parse_args()

    audit_output = pathlib.Path(args.audit_output)
    out_path = pathlib.Path(args.out) if args.out else audit_output / 'machine' / 'exception-index.json'

    index = aggregate_exceptions(audit_output, merge=args.merge)
    write_json(out_path, index)
    print(json.dumps({'pipeline_decision': index['pipeline_decision'], 'out': str(out_path)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
