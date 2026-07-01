#!/usr/bin/env python3
import json
import pathlib

from tool_runner import ROOT, run_subprocess, temp_audit_dir


def run_intake(intake_dir: pathlib.Path):
    return run_subprocess(
        'tools/validate_intake.py',
        ['--intake-dir', str(intake_dir)],
        check=False,
    )


def test_missing_scope_blocks():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        (td / 'intake.json').write_text(json.dumps({
            'authorization': 'ok', 'scope_summary': 'x', 'source_path': '.', 'network_policy': 'offline'
        }))
        p = run_intake(td)
        assert p.returncode != 0


def test_missing_authorization_blocks():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        (td / 'scope.md').write_text('# scope\n')
        (td / 'intake.json').write_text(json.dumps({
            'authorization': '', 'scope_summary': 'x', 'source_path': '.', 'network_policy': 'offline'
        }))
        p = run_intake(td)
        assert p.returncode != 0


def test_valid_intake_passes():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        (td / 'scope.md').write_text('# scope\nauthorized audit\n')
        (td / 'intake.json').write_text((ROOT / 'tests/fixtures/sample-intake.json').read_text())
        p = run_intake(td)
        assert p.returncode == 0, p.stdout + p.stderr


def test_legacy_network_policy_is_normalized():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        (td / 'scope.md').write_text('# scope\nauthorized audit\n')
        (td / 'intake.json').write_text(json.dumps({
            'authorization': 'authorized audit',
            'scope_summary': 'demo package',
            'source_path': '.',
            'network_policy': 'limited',
        }))
        p = run_intake(td)
        assert p.returncode == 0, p.stdout + p.stderr
        data = json.loads((td / 'intake.json').read_text())
        assert data['network_policy'] == 'restricted'


def test_invalid_network_policy_lists_allowed_values():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        (td / 'scope.md').write_text('# scope\nauthorized audit\n')
        (td / 'intake.json').write_text(json.dumps({
            'authorization': 'authorized audit',
            'scope_summary': 'demo package',
            'source_path': '.',
            'network_policy': 'whatever the tool wants',
        }))
        p = run_intake(td)
        assert p.returncode != 0
        assert 'allowed values: offline, restricted, online-approved' in p.stderr


if __name__ == '__main__':
    test_missing_scope_blocks()
    test_missing_authorization_blocks()
    test_valid_intake_passes()
    test_legacy_network_policy_is_normalized()
    test_invalid_network_policy_lists_allowed_values()
    print('intake gate tests passed')
