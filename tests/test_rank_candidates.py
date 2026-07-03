#!/usr/bin/env python3
import json
import pathlib

from tool_runner import run_subprocess, temp_audit_dir


def main():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        inp = td / 'in.json'
        out = td / 'out.json'
        data = {'candidates': [
            {'id': 'T-CAND-low', 'type': 'T-CAND', 'status': 'Raw Tool Hit', 'title': 'test fixture',
             'component': 'tests', 'source_locations': [{'file': 'tests/example.c'}], 'evidence': {},
             'confidence': 'low', 'rank_score': 0, 'missing_evidence': [], 'disclosure_level': 'D0-internal-candidate'},
            {'id': 'T-CAND-high', 'type': 'T-CAND', 'status': 'Raw Tool Hit', 'title': 'elf offset memcpy',
             'component': 'bfd parser', 'source_locations': [{'file': 'bfd/elf.c'}],
             'evidence': {'sink': 'memcpy offset size count'}, 'confidence': 'low', 'rank_score': 0,
             'missing_evidence': [], 'disclosure_level': 'D0-internal-candidate'},
        ]}
        inp.write_text(json.dumps(data))
        run_subprocess('tools/rank_candidates.py', ['--input', str(inp), '--out', str(out), '--top', '2'])
        ranked = json.loads(out.read_text())['candidates']
        assert ranked[0]['id'] == 'T-CAND-high', ranked
        assert 'score_breakdown' in ranked[0]
        for key in ['tool_weight', 'sink_weight', 'profile_relevance', 'source_location_quality', 'test_vendor_penalty', 'coverage_admission_penalty']:
            assert key in ranked[0]['score_breakdown']
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        inp = td / 'in.json'
        out = td / 'out.json'
        data = {'candidates': [
            {'id': 'T-CAND-suppressed', 'type': 'T-CAND', 'status': 'Raw Tool Hit', 'title': 'memcpy',
             'component': 'parser', 'source_locations': [{'file': 'src/parser.c'}],
             'evidence': {'tool_refs': ['badtool'], 'admission_policy': 'not_admissible'},
             'rank_score': 100},
            {'id': 'T-CAND-kept', 'type': 'T-CAND', 'status': 'Raw Tool Hit', 'title': 'memcpy',
             'component': 'parser', 'source_locations': [{'file': 'src/parser.c'}],
             'evidence': {'tool_refs': ['semgrep']}, 'rank_score': 1},
        ]}
        inp.write_text(json.dumps(data))
        run_subprocess('tools/rank_candidates.py', ['--input', str(inp), '--out', str(out), '--top', '2'])
        ranked = json.loads(out.read_text())['candidates']
        assert [c['id'] for c in ranked] == ['T-CAND-kept']
    print('rank tests passed')


if __name__ == '__main__':
    main()
