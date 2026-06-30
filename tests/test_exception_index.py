#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def write_step(audit: pathlib.Path, step_id: str, status: str, decision: str, limitations=None):
    d = audit / 'machine' / 'workflow-steps'
    d.mkdir(parents=True, exist_ok=True)
    payload = {
        'step_id': step_id, 'status': status, 'decision': decision,
        'blocking_issues': [], 'limitations': limitations or [],
    }
    (d / f'{step_id}.json').write_text(json.dumps(payload))


def run_aggregate(audit: pathlib.Path, extra=None):
    cmd = [sys.executable, str(ROOT / 'tools' / 'aggregate_exceptions.py'),
           '--audit-output', str(audit), '--out', str(audit / 'machine' / 'exception-index.json')]
    if extra:
        cmd.extend(extra)
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


def test_partial_report_stage_recorded():
    with tempfile.TemporaryDirectory() as td:
        audit = pathlib.Path(td)
        write_step(audit, '08-report', 'partial', 'continue', ['no --public-records'])
        write_step(audit, '03-tool-scan', 'completed', 'continue')
        run_aggregate(audit)
        idx = json.loads((audit / 'machine' / 'exception-index.json').read_text())
        assert idx['pipeline_decision'] == 'continue'
        assert '08-report' in idx['partial_stages']


def test_blocked_step_halts_pipeline():
    with tempfile.TemporaryDirectory() as td:
        audit = pathlib.Path(td)
        write_step(audit, '03-tool-scan', 'blocked', 'block')
        run_aggregate(audit)
        idx = json.loads((audit / 'machine' / 'exception-index.json').read_text())
        assert idx['pipeline_decision'] == 'halt'
        assert '03-tool-scan' in idx['halted_stages']
        assert idx['summary']['blocked_count'] >= 1


def test_schema_validation_failure_emits_event():
    with tempfile.TemporaryDirectory() as td:
        audit = pathlib.Path(td)
        write_step(audit, '07-schema-validation', 'failed', 'block')
        (audit / 'machine').mkdir(parents=True, exist_ok=True)
        (audit / 'machine' / 'schema-validation-result.json').write_text(
            json.dumps({'passed': False, 'errors': ['finding[0]: missing field']})
        )
        run_aggregate(audit)
        idx = json.loads((audit / 'machine' / 'exception-index.json').read_text())
        codes = [e['code'] for e in idx['events']]
        assert any('EX-SCH' in c for c in codes)


if __name__ == '__main__':
    test_partial_report_stage_recorded()
    test_blocked_step_halts_pipeline()
    test_schema_validation_failure_emits_event()
    print('exception index tests passed')
