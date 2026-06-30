#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'import_openeuler_vuln_registry.py'
FIXTURE = ROOT / 'tests' / 'fixtures' / 'sample-openeuler-registry.xlsx'
BUILDER = ROOT / 'tests' / 'build_sample_openeuler_xlsx.py'


def ensure_fixture() -> None:
    if not FIXTURE.is_file():
        subprocess.check_call([sys.executable, str(BUILDER)])


def main() -> None:
    ensure_fixture()
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / 'openeuler'
        subprocess.check_call([
            sys.executable, str(TOOL),
            '--xlsx', str(FIXTURE),
            '--out', str(out),
        ])
        idx = json.loads((out / 'cve-index.json').read_text(encoding='utf-8'))
        assert 'CVE-2026-0001' in idx['index'], idx['index'].keys()
        manifest = json.loads((out / 'manifest.json').read_text(encoding='utf-8'))
        assert manifest['record_count'] >= 5, manifest
        records = json.loads((out / 'records.json').read_text(encoding='utf-8'))
        assert records['record_count'] == manifest['record_count']
        categories = {r['category'] for r in records['records']}
        assert categories == {'unaffected', 'suspended', 'fixed'}, categories
        hidden_skipped = all(r['cve_id'] != 'CVE-2026-0002' for r in records['records'])
        assert hidden_skipped, 'hidden row CVE-2026-0002 must be skipped'
        for rec in records['records']:
            if rec['cve_id'] == 'CVE-2026-0003':
                assert rec['component_location'] == '', rec
                assert rec['affected_branches'] == [], rec
            if rec['cve_id'] == 'CVE-2026-0004':
                assert len(rec['affected_branches']) == 2, rec
    print('import openeuler registry tests passed')


if __name__ == '__main__':
    main()
