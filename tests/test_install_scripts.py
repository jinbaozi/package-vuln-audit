#!/usr/bin/env python3
import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install' / 'install.sh'
VERIFY = ROOT / 'install' / 'verify-install.sh'


def run(cmd):
    subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def assert_exists(path: pathlib.Path):
    assert path.exists(), f'missing {path}'


def test_install_all_copy():
    with tempfile.TemporaryDirectory() as td:
        target = pathlib.Path(td) / 'repo'
        target.mkdir()
        run([str(INSTALL), '--target', str(target), '--platform', 'all', '--mode', 'copy', '--force'])
        run([str(VERIFY), '--target', str(target), '--platform', 'all'])
        assert_exists(target / '.claude' / 'skills' / 'package-vuln-audit' / 'SKILL.md')
        assert_exists(target / '.codex' / 'skills' / 'package-vuln-audit' / 'SKILL.md')
        assert_exists(target / '.opencode' / 'skills' / 'package-vuln-audit' / 'SKILL.md')
        assert_exists(target / '.opencode' / 'opencode.json')
        assert_exists(target / 'AGENTS.md')


def test_install_opencode_symlink():
    with tempfile.TemporaryDirectory() as td:
        target = pathlib.Path(td) / 'repo'
        target.mkdir()
        run([str(INSTALL), '--target', str(target), '--platform', 'opencode', '--mode', 'symlink', '--force'])
        run([str(VERIFY), '--target', str(target), '--platform', 'opencode'])
        p = target / '.opencode' / 'skills' / 'package-vuln-audit' / 'SKILL.md'
        assert p.is_symlink(), f'expected symlink: {p}'


if __name__ == '__main__':
    test_install_all_copy()
    test_install_opencode_symlink()
    print('install script tests passed', flush=True)
os._exit(0)
