#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest.mock as mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_driver_module():
    spec = importlib.util.spec_from_file_location('driver', ROOT / 'tools' / 'enforced_audit_driver.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_import_error_blocks_complete_audit():
    driver = load_driver_module()
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td)
        findings = out / 'findings.json'
        findings.write_text('{"findings":[]}')
        with mock.patch.dict(sys.modules, {'jsonschema': None}):
            with mock.patch('builtins.__import__', side_effect=ImportError('no jsonschema')):
                rc = driver.validate_finding_schema(str(findings), out, complete_audit=True)
        assert rc == 1
        result = json.loads((out / 'machine' / 'schema-validation-result.json').read_text())
        assert result['passed'] is False
        assert any('EX-SCH-001' in e for e in result.get('errors', []))


if __name__ == '__main__':
    test_import_error_blocks_complete_audit()
    print('schema fail-closed tests passed')
