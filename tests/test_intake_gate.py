#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_intake(intake_dir: pathlib.Path):
    return subprocess.run(
        [sys.executable, str(ROOT / 'tools' / 'validate_intake.py'),
         '--intake-dir', str(intake_dir)],
        text=True, capture_output=True,
    )


def test_missing_scope_blocks():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        (td / 'intake.json').write_text(json.dumps({
            'authorization': 'ok', 'scope_summary': 'x', 'source_path': '.', 'network_policy': 'offline'
        }))
        p = run_intake(td)
        assert p.returncode != 0


def test_missing_authorization_blocks():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        (td / 'scope.md').write_text('# scope\n')
        (td / 'intake.json').write_text(json.dumps({
            'authorization': '', 'scope_summary': 'x', 'source_path': '.', 'network_policy': 'offline'
        }))
        p = run_intake(td)
        assert p.returncode != 0


def test_valid_intake_passes():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        (td / 'scope.md').write_text('# scope\nauthorized audit\n')
        (td / 'intake.json').write_text((ROOT / 'tests/fixtures/sample-intake.json').read_text())
        p = run_intake(td)
        assert p.returncode == 0, p.stdout + p.stderr


if __name__ == '__main__':
    test_missing_scope_blocks()
    test_missing_authorization_blocks()
    test_valid_intake_passes()
    print('intake gate tests passed')
