#!/usr/bin/env python3
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_contract_has_no_required_schemas_constant():
    text = (ROOT / 'tools' / 'enforce_workflow_contract.py').read_text()
    assert 'REQUIRED_SCHEMAS = [' not in text


def test_manifest_lists_all_disk_schemas():
    p = subprocess.run(
        [sys.executable, str(ROOT / 'tools' / 'validate_manifest.py'),
         '--root', str(ROOT), '--out', '/tmp/manifest-validation-test.json'],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert p.returncode == 0, p.stdout + p.stderr


if __name__ == '__main__':
    test_contract_has_no_required_schemas_constant()
    test_manifest_lists_all_disk_schemas()
    print('manifest single source tests passed')
