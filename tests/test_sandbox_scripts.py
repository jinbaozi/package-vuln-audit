#!/usr/bin/env python3
"""Smoke checks for sandbox/scripts/ helpers."""
import os, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'sandbox' / 'scripts'

def test_check_backend_script_exists_and_executable():
    p = SCRIPTS / 'pvas-check-backend.sh'
    assert p.is_file(), f'missing {p}'
    assert os.access(p, os.X_OK), f'{p} not executable'

def test_import_image_script_exists_and_executable():
    p = SCRIPTS / 'pvas-import-image.sh'
    assert p.is_file(), f'missing {p}'
    assert os.access(p, os.X_OK), f'{p} not executable'

def test_version_file():
    v = ROOT / 'sandbox' / 'rootfs' / 'VERSION'
    assert v.is_file(), f'missing {v}'
    assert v.read_text().strip(), 'VERSION is empty'

def test_sha256sums_file():
    s = ROOT / 'sandbox' / 'rootfs' / 'SHA256SUMS'
    assert s.is_file(), f'missing {s}'
    line = s.read_text().strip().splitlines()
    assert line, 'SHA256SUMS empty'
    parts = line[0].split()
    assert len(parts) == 2, f'expected "<sha>  <file>" in first line, got {line[0]!r}'
    assert parts[0] != '0' * 64, 'SHA256SUMS must not use the all-zero placeholder'

def test_rootfs_tar_declared_as_lfs_tracked():
    result = subprocess.run(
        ['git', 'check-attr', '-a', '--', 'sandbox/rootfs/v11-2503-rootfs.tar'],
        cwd=str(ROOT), capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    attrs = result.stdout
    assert 'filter: lfs' in attrs, attrs
    assert 'diff: lfs' in attrs, attrs
    assert 'merge: lfs' in attrs, attrs

def test_check_backend_finds_docker_or_podman_or_fails_cleanly():
    """无论主机有没有 docker/podman，脚本都应按文档行为返回 0 或 1。"""
    result = subprocess.run(
        [str(SCRIPTS / 'pvas-check-backend.sh')],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode == 0:
        assert result.stdout.strip() in ('docker', 'podman')
    else:
        assert result.returncode == 1
        assert result.stdout.strip() == ''

if __name__ == '__main__':
    test_check_backend_script_exists_and_executable()
    test_import_image_script_exists_and_executable()
    test_version_file()
    test_sha256sums_file()
    test_rootfs_tar_declared_as_lfs_tracked()
    test_check_backend_finds_docker_or_podman_or_fails_cleanly()
    print('sandbox_scripts tests passed')
