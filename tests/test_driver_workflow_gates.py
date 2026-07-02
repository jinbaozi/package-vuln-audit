#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from enforced_audit_driver import (
    StageResult,
    request_confirmation,
    run_stage,
    validate_finding_schema,
    validate_resume_confirmation,
    write_step,
)
from tool_runner import temp_audit_dir


def test_driver_generates_tool_matrix_before_running_tools():
    text = (ROOT / 'tools' / 'enforced_audit_driver.py').read_text()
    assert 'tools/generate_tool_matrix.py' in text
    assert 'required-tools-matrix.json' in text
    assert 'tools/run_tools.sh' in text


def test_driver_enforces_ai_hypothesis_stage():
    text = (ROOT / 'tools' / 'enforced_audit_driver.py').read_text()
    assert '04-ai-hypothesis' in text
    assert 'tools/exec_ai_hypothesis_agent.py' in text
    assert 'tools/validate_hypotheses.py' in text
    assert 'ai-hypotheses.json' in text
    assert 'no --findings provided; final report gates not executed' not in text


def test_driver_executes_review_and_validation_semantics():
    text = (ROOT / 'tools' / 'enforced_audit_driver.py').read_text()
    assert 'tools/exec_candidate_review_agent.py' in text
    assert 'candidate-summary.json' in text
    assert 'tools/validate_validation_results.py' in text
    assert 'validation-result-summary.json' in text


def test_write_step_rejects_blocked_terminal_state():
    with temp_audit_dir() as td:
        try:
            write_step(pathlib.Path(td), 'x', 'blocked', 'block')
        except ValueError:
            pass
        else:
            raise AssertionError('blocked must not be a driver terminal state')


def test_run_stage_success_retry_and_failure():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        output = audit / 'profile.json'
        def writes_output():
            output.write_text('{}')
            return StageResult(True, outputs=[str(output)])
        ok = run_stage('01-package-profile', None, writes_output, None, out_root=audit)
        assert ok.ok
        step = (audit / 'machine/workflow-steps/01-package-profile.json').read_text()
        assert 'completed' in step

    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        calls = {'n': 0}
        def flaky():
            calls['n'] += 1
            return StageResult(calls['n'] > 1, issues=['temporary failure'])
        ok = run_stage('02-scope-selection', None, flaky, None, out_root=audit)
        assert ok.ok
        assert 'completed-with-recovery' in (audit / 'machine/workflow-steps/02-scope-selection.json').read_text()

    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        ok = run_stage('04-ai-hypothesis', None, lambda: StageResult(False, issues=['missing artifact']), None, out_root=audit)
        assert not ok.ok
        text = (audit / 'machine/workflow-steps/04-ai-hypothesis.json').read_text()
        assert 'failed-after-retries' in text
        assert '"attempt_count": 3' in text


def test_run_stage_fails_when_declared_output_is_missing():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        missing = audit / 'missing-summary.json'
        ok = run_stage('05-candidate-review', None, lambda: StageResult(True), None,
                       out_root=audit, outputs=[str(missing)], retry=0)
        assert not ok.ok
        step = json.loads((audit / 'machine/workflow-steps/05-candidate-review.json').read_text())
        assert step['status'] == 'failed-after-retries'
        assert any('missing declared output' in issue for issue in step['blocking_issues'])


def test_noninteractive_confirmation_writes_required_artifact_and_blocks():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        result = request_confirmation(
            audit,
            'terminate-required-tool',
            '03-tool-scan',
            {'tool': 'semgrep', 'reason': 'stalled'},
            interactive=False,
        )
        assert not result.ok
        assert result.decision == 'blocked-pending-confirmation'
        required = json.loads((audit / 'machine/user-confirmations/confirmation-required.json').read_text())
        assert required['action'] == 'terminate-required-tool'
        assert required['step_id'] == '03-tool-scan'
        assert required['status'] == 'pending'
        assert required['token']


def test_resume_confirmation_accepts_matching_decision_token():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        result = request_confirmation(
            audit,
            'degrade-required-tool',
            '03-tool-scan',
            {'tool': 'semgrep'},
            interactive=False,
        )
        required = json.loads((audit / 'machine/user-confirmations/confirmation-required.json').read_text())
        decisions = audit / 'machine/user-confirmations/confirmation-decisions.json'
        decisions.write_text(json.dumps({
            'decisions': [{
                'token': required['token'],
                'action': 'degrade-required-tool',
                'step_id': '03-tool-scan',
                'decision': 'approved',
                'decided_by': 'test',
            }]
        }))
        assert not result.ok
        assert validate_resume_confirmation(audit, required['token'], 'degrade-required-tool').ok
        assert not validate_resume_confirmation(audit, 'wrong-token', 'degrade-required-tool').ok


def test_run_stage_does_not_retry_pending_confirmation():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td)
        result = run_stage(
            '03-tool-scan',
            None,
            lambda: StageResult(False, decision='blocked-pending-confirmation', issues=['approval required']),
            None,
            out_root=audit,
        )
        assert not result.ok
        attempts = json.loads((audit / 'machine/workflow-attempts/03-tool-scan.json').read_text())
        assert len(attempts['attempts']) == 1
        step = json.loads((audit / 'machine/workflow-steps/03-tool-scan.json').read_text())
        assert step['decision'] == 'blocked-pending-confirmation'


def test_validated_finding_schema_requires_validation_evidence():
    with temp_audit_dir() as td:
        audit = pathlib.Path(td) / 'audit-output'
        findings = pathlib.Path(td) / 'findings.json'
        findings.write_text(json.dumps({'findings': [{
            'id': 'FINDING-001',
            'status': 'Validated',
            'title': 'missing validation evidence',
            'affected_component': {'package': 'demo', 'component': 'parser'},
            'source_code_evidence': [{'file': 'src/parser.c', 'function': 'parse'}],
            'source_to_sink_path': 'input -> parse -> sink',
            'validation': {},
            'cvss': {'version': '3.1', 'vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L', 'base_score': 3.3, 'severity': 'Low'},
            'fix_recommendation': 'add bounds check',
            'discovery_method': [{'type': 'manual', 'description': 'fixture'}],
            'disclosure_status': 'not_found_in_configured_sources',
            'disclosure_level': 'D2-internal-validated',
        }]}))
        assert validate_finding_schema(str(findings), audit, complete_audit=True) == 1
        result = json.loads((audit / 'machine/schema-validation-result.json').read_text())
        assert any('validation evidence' in err for err in result['errors'])


def test_driver_uses_validation_poc_path():
    text = (ROOT / 'tools' / 'enforced_audit_driver.py').read_text()
    assert '04-validation' in text
    assert 'poc-tests' in text
    assert "machine' / 'poc-tests" not in text


if __name__ == '__main__':
    test_driver_generates_tool_matrix_before_running_tools()
    test_driver_enforces_ai_hypothesis_stage()
    test_driver_executes_review_and_validation_semantics()
    test_write_step_rejects_blocked_terminal_state()
    test_run_stage_success_retry_and_failure()
    test_run_stage_fails_when_declared_output_is_missing()
    test_validated_finding_schema_requires_validation_evidence()
    test_driver_uses_validation_poc_path()
    print('driver workflow gate tests passed')
