#!/usr/bin/env python3
import json
import pathlib

from tool_runner import run_subprocess, temp_audit_dir


def test_validate_hypotheses_accepts_valid_and_rejects_empty():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        valid = td / 'ai-hypotheses.json'
        valid.write_text(json.dumps({'hypotheses': [{
            'id': 'AI-HYP-1', 'profile': 'binary-parser', 'component': 'parser',
            'assumption': 'length is trusted', 'attacker_controlled_input': 'file length',
            'possible_gap': 'bounds check gap', 'possible_sink': 'memcpy',
            'validation_method': 'unit test with sanitizer', 'confidence': 'medium',
        }]}))
        run_subprocess('tools/validate_hypotheses.py', ['--hypotheses', str(valid), '--out', str(td / 'ok.json')])
        assert json.loads((td / 'ok.json').read_text())['passed'] is True
        empty = td / 'empty.json'
        empty.write_text(json.dumps({'hypotheses': []}))
        p = run_subprocess('tools/validate_hypotheses.py', ['--hypotheses', str(empty), '--out', str(td / 'bad.json')], check=False)
        assert p.returncode == 1
        assert json.loads((td / 'bad.json').read_text())['passed'] is False


def test_validate_candidate_reviews_requires_top_n_coverage():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        ranked = td / 'ranked.json'
        ranked.write_text(json.dumps({'candidates': [{'id': 'T-CAND-1'}, {'id': 'T-CAND-2'}]}))
        reviews = td / 'reviews'
        reviews.mkdir()
        (reviews / 'one.json').write_text(json.dumps({'candidate_id': 'T-CAND-1', 'decision': 'Likely', 'source_slice_reviewed': True}))
        p = run_subprocess('tools/validate_candidate_reviews.py', ['--ranked-candidates', str(ranked), '--review-dir', str(reviews), '--max-candidates', '2', '--out', str(td / 'coverage.json')], check=False)
        assert p.returncode == 1
        result = json.loads((td / 'coverage.json').read_text())
        assert any('T-CAND-2' in e for e in result['errors'])
        (reviews / 'two.json').write_text(json.dumps({'candidate_id': 'T-CAND-2', 'decision': 'Reject', 'source_slice_reviewed': True}))
        run_subprocess('tools/validate_candidate_reviews.py', ['--ranked-candidates', str(ranked), '--review-dir', str(reviews), '--max-candidates', '2', '--out', str(td / 'coverage-ok.json')])
        assert json.loads((td / 'coverage-ok.json').read_text())['passed'] is True


def test_generate_ai_hypotheses_executes_stage_semantics():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        ranked = td / 'ranked-candidates.json'
        ranked.write_text(json.dumps({'candidates': [{
            'id': 'T-CAND-1',
            'type': 'T-CAND',
            'title': 'unsafe copy',
            'component': 'parser',
            'profile': 'binary-parser',
            'source_locations': [{'file': 'src/parser.c', 'function': 'parse', 'start_line': 10, 'end_line': 10}],
            'evidence': {'sink': 'memcpy'},
            'missing_evidence': ['validation'],
        }]}))
        scope = td / 'selected-scope.json'
        scope.write_text(json.dumps({'selected_recipes': ['recipes/binary-parser.md']}))
        out = td / '03-candidates'
        run_subprocess('tools/generate_ai_hypotheses.py', [
            '--ranked-candidates', str(ranked),
            '--selected-scope', str(scope),
            '--out', str(out / 'ai-hypotheses.json'),
            '--max-candidates', '1',
        ])
        data = json.loads((out / 'ai-hypotheses.json').read_text())
        assert data['hypotheses'][0]['id'].startswith('AI-HYP-')
        assert data['hypotheses'][0]['source_candidate_id'] == 'T-CAND-1'
        run_subprocess('tools/validate_hypotheses.py', ['--hypotheses', str(out / 'ai-hypotheses.json')])


def test_run_candidate_reviews_writes_summary_from_packets():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        ranked = td / 'ranked-candidates.json'
        ranked.write_text(json.dumps({'candidates': [{
            'id': 'T-CAND-1',
            'type': 'T-CAND',
            'title': 'unsafe copy',
            'component': 'parser',
            'source_locations': [{'file': 'src/parser.c', 'function': 'parse', 'start_line': 7, 'end_line': 7}],
            'missing_evidence': ['validation'],
        }]}))
        packets = td / 'packets'
        packets.mkdir()
        (packets / 'T-CAND-1.md').write_text(
            '# T-CAND-1\n\n## Code Slice\n```text\n7: memcpy(dst, src, len);\n```\n'
        )
        reviews = td / 'reviews'
        summary = td / 'candidate-summary.json'
        run_subprocess('tools/run_candidate_reviews.py', [
            '--ranked-candidates', str(ranked),
            '--packet-dir', str(packets),
            '--review-dir', str(reviews),
            '--summary-out', str(summary),
            '--max-candidates', '1',
        ])
        review = json.loads((reviews / 'T-CAND-1.json').read_text())
        assert review['candidate_id'] == 'T-CAND-1'
        assert review['decision'] in {'Reject', 'Candidate', 'Likely'}
        summary_data = json.loads(summary.read_text())
        assert summary_data['reviewed_count'] == 1
        assert summary_data['candidates'][0]['id'] == 'T-CAND-1'


def test_validate_validation_results_enforces_status_semantics():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        findings = td / 'findings.json'
        findings.write_text(json.dumps({'findings': [{
            'id': 'FINDING-1',
            'status': 'Validated',
            'validation': {'method': 'sanitizer', 'command': 'cat testcase'},
            'false_positive_exclusion': 'local sanitizer reproduction',
        }, {
            'id': 'MANUAL-1',
            'status': 'Needs Manual Review',
            'validation': {},
            'manual_review': {'blocked_reason': 'needs corpus'},
        }]}))
        run_subprocess('tools/validate_validation_results.py', ['--findings', str(findings), '--out', str(td / 'validation-ok.json')])
        assert json.loads((td / 'validation-ok.json').read_text())['passed'] is True

        bad = td / 'bad-findings.json'
        bad.write_text(json.dumps({'findings': [{
            'id': 'FINDING-2',
            'status': 'Validated',
            'validation': {},
        }]}))
        p = run_subprocess('tools/validate_validation_results.py', ['--findings', str(bad), '--out', str(td / 'validation-bad.json')], check=False)
        assert p.returncode == 1
        errors = json.loads((td / 'validation-bad.json').read_text())['errors']
        assert any('validation evidence' in err for err in errors)


def test_select_scope_is_deterministic_for_common_profiles():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        profile = td / 'profile.json'
        profile.write_text(json.dumps({'package_name': 'demo', 'profiles': ['binary-parser', 'cli-tool', 'build-system']}))
        out = td / '01-profile'
        run_subprocess('tools/select_scope.py', ['--profile', str(profile), '--source', '/src/demo', '--out-dir', str(out)])
        data = json.loads((out / 'selected-scope.json').read_text())
        assert data['selected_recipes'] == sorted(data['selected_recipes'])
        assert 'recipes/binary-parser.md' in data['selected_recipes']
        assert 'recipes/cli-tool.md' in data['selected_recipes']
        assert 'recipes/build-system.md' in data['selected_recipes']
        assert (out / 'selected-recipes.md').exists()


if __name__ == '__main__':
    test_validate_hypotheses_accepts_valid_and_rejects_empty()
    test_validate_candidate_reviews_requires_top_n_coverage()
    test_generate_ai_hypotheses_executes_stage_semantics()
    test_run_candidate_reviews_writes_summary_from_packets()
    test_validate_validation_results_enforces_status_semantics()
    test_select_scope_is_deterministic_for_common_profiles()
    print('workflow validator tests passed')
