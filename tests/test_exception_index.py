#!/usr/bin/env python3
import json
import pathlib

from tool_runner import run_subprocess, temp_audit_dir


def write_step(audit: pathlib.Path, step_id: str, status: str, decision: str, limitations=None, issues=None, attempts=1):
    d = audit / 'machine' / 'workflow-steps'
    d.mkdir(parents=True, exist_ok=True)
    payload = {
        'step_id': step_id,
        'status': status,
        'decision': decision,
        'blocking_issues': issues or [],
        'limitations': limitations or [],
        'attempt_count': attempts,
        'last_error_summary': '; '.join(issues or []),
        'recovery_actions': ['retry'],
        'artifact_refs': [],
    }
    (d / f'{step_id}.json').write_text(json.dumps(payload))


def run_aggregate(audit: pathlib.Path, extra=None):
    args = ['--audit-output', str(audit), '--out', str(audit / 'machine' / 'exception-index.json')]
    if extra:
        args.extend(extra)
    return run_subprocess('tools/aggregate_exceptions.py', args)


def test_not_applicable_stage_recorded():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        write_step(audit, '09-progressive-disclosure', 'not-applicable', 'continue', ['no D3/D4 findings'])
        write_step(audit, '03-tool-scan', 'completed', 'continue')
        run_aggregate(audit)
        idx = json.loads((audit / 'machine' / 'exception-index.json').read_text())
        assert idx['pipeline_decision'] == 'continue'
        assert '09-progressive-disclosure' in idx['partial_stages']
        assert idx['summary']['not_applicable_count'] >= 1


def test_failed_after_retries_fails_pipeline():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        write_step(audit, '04-ai-hypothesis', 'failed-after-retries', 'failed', issues=['missing ai-hypotheses.json'], attempts=3)
        run_aggregate(audit)
        idx = json.loads((audit / 'machine' / 'exception-index.json').read_text())
        assert idx['pipeline_decision'] == 'failed'
        assert '04-ai-hypothesis' in idx['halted_stages']
        assert idx['summary']['failed_after_retries_count'] >= 1
        event = next(e for e in idx['events'] if e['step_id'] == '04-ai-hypothesis')
        assert event['attempt_count'] == 3
        assert event['last_error_summary']
        assert event['recovery_actions']


def test_schema_validation_failure_emits_event():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        write_step(audit, '06-validation', 'failed-after-retries', 'failed')
        (audit / 'machine').mkdir(parents=True, exist_ok=True)
        (audit / 'machine' / 'schema-validation-result.json').write_text(json.dumps({'passed': False, 'errors': ['finding[0]: missing field']}))
        run_aggregate(audit)
        idx = json.loads((audit / 'machine' / 'exception-index.json').read_text())
        codes = [e['code'] for e in idx['events']]
        assert any('EX-SCH' in c for c in codes)


def test_stale_failed_event_does_not_pollute_current_success_run():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        (audit / 'machine').mkdir(parents=True, exist_ok=True)
        (audit / 'machine/exception-index.json').write_text(json.dumps({
            'pipeline_decision': 'failed',
            'events': [{
                'id': 'EX-04-ai-hypothesis-failed-after-retries',
                'step_id': '04-ai-hypothesis',
                'class': 'failed-after-retries',
            }],
            'halted_stages': ['04-ai-hypothesis'],
            'partial_stages': [],
        }))
        write_step(audit, '04-ai-hypothesis', 'completed', 'continue')
        run_aggregate(audit)
        idx = json.loads((audit / 'machine' / 'exception-index.json').read_text())
        assert idx['pipeline_decision'] == 'continue'
        assert not idx['events']
        assert idx['halted_stages'] == []


def test_blocked_tool_summary_fails_pipeline_even_if_step_completed():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        write_step(audit, '03-tool-scan', 'completed', 'continue')
        (audit / '02-tools').mkdir(parents=True, exist_ok=True)
        (audit / '02-tools/tool-summary.json').write_text(json.dumps({
            'strict_decision': 'block',
            'tools': [{
                'name': 'semgrep',
                'status': 'blocked-recovery-required',
                'reason': 'not-installed',
                'strict_decision': 'block',
            }],
        }))
        run_aggregate(audit)
        idx = json.loads((audit / 'machine' / 'exception-index.json').read_text())
        assert idx['pipeline_decision'] == 'failed'
        assert any(e['code'] == 'tool.semgrep.blocked' for e in idx['events'])


if __name__ == '__main__':
    test_not_applicable_stage_recorded()
    test_failed_after_retries_fails_pipeline()
    test_schema_validation_failure_emits_event()
    test_stale_failed_event_does_not_pollute_current_success_run()
    test_blocked_tool_summary_fails_pipeline_even_if_step_completed()
    print('exception index tests passed')
