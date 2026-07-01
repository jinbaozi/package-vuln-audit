#!/usr/bin/env python3
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from enforced_audit_driver import StageResult, run_stage, write_step
from tool_runner import temp_audit_dir


def test_driver_generates_tool_matrix_before_running_tools():
    text = (ROOT / 'tools' / 'enforced_audit_driver.py').read_text()
    assert 'tools/generate_tool_matrix.py' in text
    assert 'required-tools-matrix.json' in text
    assert 'tools/run_tools.sh' in text


def test_driver_enforces_ai_hypothesis_stage():
    text = (ROOT / 'tools' / 'enforced_audit_driver.py').read_text()
    assert '04-ai-hypothesis' in text
    assert 'tools/validate_hypotheses.py' in text
    assert 'ai-hypotheses.json' in text
    assert 'no --findings provided; final report gates not executed' not in text


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
        ok = run_stage('01-package-profile', None, lambda: StageResult(True, outputs=['x']), None, out_root=audit)
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


def test_driver_uses_validation_poc_path():
    text = (ROOT / 'tools' / 'enforced_audit_driver.py').read_text()
    assert '04-validation' in text
    assert 'poc-tests' in text
    assert "machine' / 'poc-tests" not in text


if __name__ == '__main__':
    test_driver_generates_tool_matrix_before_running_tools()
    test_driver_enforces_ai_hypothesis_stage()
    test_write_step_rejects_blocked_terminal_state()
    test_run_stage_success_retry_and_failure()
    test_driver_uses_validation_poc_path()
    print('driver workflow gate tests passed')
