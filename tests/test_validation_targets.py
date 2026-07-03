#!/usr/bin/env python3
import json
import pathlib

from tool_runner import run_subprocess, temp_audit_dir


def test_likely_reviews_become_validation_targets_and_rejected_stays_summary_only():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        ranked = td / 'ranked-candidates.json'
        summary = td / 'candidate-summary.json'
        reviews = td / 'reviews'
        packets = td / 'packets'
        out = td / 'validation-targets.json'
        reviews.mkdir()
        packets.mkdir()
        ranked.write_text(json.dumps({
            'candidates': [
                {'id': 'T-CAND-001', 'status': 'Raw Tool Hit', 'title': 'likely'},
                {'id': 'T-CAND-002', 'status': 'Raw Tool Hit', 'title': 'reject'},
                {'id': 'T-CAND-003', 'status': 'Candidate', 'title': 'candidate only'},
            ]
        }))
        summary.write_text(json.dumps({'candidates': [
            {'id': 'T-CAND-001', 'status': 'Likely', 'title': 'likely'},
            {'id': 'T-CAND-002', 'status': 'Rejected', 'title': 'reject'},
            {'id': 'T-CAND-003', 'status': 'Candidate', 'title': 'candidate only'},
        ]}))
        (reviews / 'T-CAND-001.json').write_text(json.dumps({
            'id': 'T-CAND-001',
            'status': 'Likely',
            'title': 'validated later',
            'affected_component': {'package': 'demo', 'component': 'parser'},
            'source_code_evidence': [{'file': 'src/parser.c', 'function': 'parse', 'start_line': 10, 'end_line': 20}],
            'source_to_sink_path': 'argv -> parse -> memcpy',
            'validation': {'method': 'pending'},
            'fix_recommendation': 'check bounds',
            'discovery_method': [{'type': 'tool', 'tool_name': 'semgrep', 'description': 'fixture'}],
            'disclosure_level': 'D1-internal-likely',
        }))
        (reviews / 'T-CAND-002.json').write_text(json.dumps({'id': 'T-CAND-002', 'status': 'Rejected'}))
        run_subprocess('tools/build_validation_targets.py', [
            '--ranked-candidates', str(ranked),
            '--candidate-summary', str(summary),
            '--review-dir', str(reviews),
            '--packet-dir', str(packets),
            '--out', str(out),
        ])
        data = json.loads(out.read_text())
        assert [t['id'] for t in data['targets']] == ['T-CAND-001']
        assert data['targets'][0]['status'] == 'Likely'
        assert data['targets'][0]['packet_ref'].endswith('T-CAND-001.md')
        assert [r['id'] for r in data['rejected_summary']] == ['T-CAND-002']


def test_finalize_finding_index_filters_reportable_statuses():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        validation = td / 'updated-findings.json'
        targets = td / 'validation-targets.json'
        out = td / 'finding-index.json'
        validation.write_text(json.dumps({'findings': [
            {'id': 'F-1', 'status': 'Validated'},
            {'id': 'F-2', 'status': 'Needs Manual Review'},
            {'id': 'F-3', 'status': 'Rejected'},
            {'id': 'F-4', 'status': 'Candidate'},
        ]}))
        targets.write_text(json.dumps({
            'candidate_summary_ref': 'candidate-summary.json',
            'validation_summary_ref': 'validation-summary.json',
            'rejected_summary': [{'id': 'OLD-REJ', 'status': 'Rejected'}],
        }))
        run_subprocess('tools/finalize_finding_index.py', [
            '--validation-findings', str(validation),
            '--validation-targets', str(targets),
            '--candidate-summary-ref', 'candidate-summary.json',
            '--validation-summary-ref', 'validation-summary.json',
            '--out', str(out),
        ])
        data = json.loads(out.read_text())
        assert [f['id'] for f in data['findings']] == ['F-1', 'F-2']
        assert [r['id'] for r in data['rejected_summary']] == ['OLD-REJ', 'F-3']
        assert 'F-4' not in json.dumps(data)


if __name__ == '__main__':
    test_likely_reviews_become_validation_targets_and_rejected_stays_summary_only()
    test_finalize_finding_index_filters_reportable_statuses()
    print('validation target tests passed')
