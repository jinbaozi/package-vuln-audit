#!/usr/bin/env python3
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_validate(extra_args=None):
    cmd = [sys.executable, str(ROOT / 'tools' / 'validate_manifest.py'), '--root', str(ROOT)]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(cmd, text=True, capture_output=True)


def test_validate_manifest_passes_on_repo():
    p = run_validate()
    assert p.returncode == 0, p.stdout + p.stderr


if __name__ == '__main__':
    test_validate_manifest_passes_on_repo()
    print('manifest tests passed')
