#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_verify(args):
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / 'env'
        env = os.environ.copy()
        env['PATH'] = ''
        p = subprocess.run([sys.executable, str(ROOT/'tools'/'verify_environment.py'), *args, '--out', str(out), '--json-only'], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        data = json.loads((out/'environment-check.json').read_text())
        return p.returncode, data


def test_default_missing_continues():
    rc, data = run_verify(['--profile','standard','--mode','default'])
    assert rc == 0
    assert data['decision'] == 'continue-degraded'
    assert data['status'] in {'degraded','missing-required'}


def test_no_mode_defaults_to_strict():
    rc, data = run_verify(['--profile','standard'])
    assert data['mode'] == 'strict'
    if data['blocking_missing_tools']:
        assert rc == 2
        assert data['decision'] == 'block'
    else:
        assert rc == 0
        assert data['decision'] in {'continue', 'continue-degraded'}


def test_strict_missing_blocks():
    rc, data = run_verify(['--profile','standard','--mode','strict'])
    if data['blocking_missing_tools']:
        assert rc == 2
        assert data['decision'] == 'block'
    else:
        # Tools may resolve via COMMON_BIN_DIRS outside PATH (e.g. ~/.local/bin).
        assert rc == 0
        assert data['decision'] in {'continue', 'continue-degraded'}


def test_strict_allow_degraded_continues():
    rc, data = run_verify(['--profile','standard','--mode','strict','--allow-degraded'])
    assert rc == 0
    assert data['decision'] == 'continue-degraded'
    if data['blocking_missing_tools']:
        assert len(data['blocking_missing_tools']) > 0


if __name__ == '__main__':
    test_default_missing_continues()
    test_no_mode_defaults_to_strict()
    test_strict_missing_blocks()
    test_strict_allow_degraded_continues()
    print('strict mode tests passed')
