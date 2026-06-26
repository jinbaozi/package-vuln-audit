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


def test_strict_missing_blocks():
    rc, data = run_verify(['--profile','standard','--mode','strict'])
    assert rc == 2
    assert data['decision'] == 'block'
    # Verify at least one blocking_missing_tool exists rather than a specific name,
    # because COMMON_BIN_DIRS may find tools outside PATH (e.g. ~/.local/bin).
    assert len(data['blocking_missing_tools']) > 0, (
        f"Expected blocking tools, got installed: {[t['name'] for t in data['tools'] if t['status']=='installed']}"
    )


def test_strict_allow_degraded_continues():
    rc, data = run_verify(['--profile','standard','--mode','strict','--allow-degraded'])
    assert rc == 0
    assert data['decision'] == 'continue-degraded'
    assert len(data['blocking_missing_tools']) > 0


if __name__ == '__main__':
    test_default_missing_continues()
    test_strict_missing_blocks()
    test_strict_allow_degraded_continues()
    print('strict mode tests passed')
