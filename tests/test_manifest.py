#!/usr/bin/env python3
from tool_runner import ROOT, run_subprocess


def run_validate(extra_args=None):
    args = ['--root', str(ROOT)]
    if extra_args:
        args.extend(extra_args)
    return run_subprocess('tools/validate_manifest.py', args, check=False)


def test_validate_manifest_passes_on_repo():
    p = run_validate()
    assert p.returncode == 0, p.stdout + p.stderr


if __name__ == '__main__':
    test_validate_manifest_passes_on_repo()
    print('manifest tests passed')
