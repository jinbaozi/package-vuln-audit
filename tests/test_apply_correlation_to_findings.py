#!/usr/bin/env python3
import json, pathlib, tempfile
from tool_runner import ROOT, run_tool


def main():
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [{
            'id': 'F-1',
            'status': 'Validated',
            'disclosure_level': 'D2-internal-validated',
            'disclosure_status': 'unknown',
            'title': 'buffer overflow CVE-2026-0001',
            'summary': 'validated issue CVE-2026-0001 in parser',
            'affected_component': {'package': 'demo', 'component': 'parser'},
            'source_code_evidence': [{'file': 'src/parser.c', 'function': 'parse'}],
            'source_to_sink_path': 'input -> parse -> overflow',
            'root_cause': 'missing bounds check',
            'security_impact': 'memory corruption',
            'validation': {},
            'cvss': {},
            'fix_recommendation': 'add bounds check',
            'discovery_method': [{'type': 'manual', 'description': 'fixture'}],
        }]}))

        correlation = t / 'correlation.json'
        correlation.write_text(json.dumps({
            'checked_sources': ['openEuler-Registry', 'NVD'],
            'correlations': [{
                'finding_id': 'F-1',
                'status': 'publicly_disclosed',
                'match_level': 'M3',
                'matched_records': [{
                    'source': 'openEuler-Registry',
                    'id': 'CVE-2026-0001',
                    'category': 'fixed',
                    'package': 'demo-pkg',
                    'match_level': 'M3',
                }],
            }],
        }))

        out = t / 'findings-out.json'
        summary = t / 'apply-correlation-result.json'
        run_tool('tools/apply_correlation_to_findings.py', [
            '--findings', str(findings),
            '--correlation', str(correlation),
            '--out', str(out),
            '--summary-out', str(summary),
        ])

        before = json.loads(findings.read_text())['findings'][0]
        after = json.loads(out.read_text())['findings'][0]
        result = json.loads(summary.read_text())

        assert before['disclosure_level'] == 'D2-internal-validated'
        assert after['disclosure_level'] == 'D2-internal-validated'
        assert after['disclosure_status'] == 'publicly_disclosed'
        refs = after.get('public_vulnerability_references') or []
        assert any(r.get('source') == 'openEuler-Registry' and r.get('id') == 'CVE-2026-0001' for r in refs)
        assert result['applied_count'] == 1
        assert result['unchanged_disclosure_level'] is True

    print('apply correlation to findings tests passed')


if __name__ == '__main__':
    main()
