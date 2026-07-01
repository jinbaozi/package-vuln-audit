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
        (reviews / 'one.json').write_text(json.dumps({'candidate_id': 'T-CAND-1', 'decision': 'Likely'}))
        p = run_subprocess('tools/validate_candidate_reviews.py', ['--ranked-candidates', str(ranked), '--review-dir', str(reviews), '--max-candidates', '2', '--out', str(td / 'coverage.json')], check=False)
        assert p.returncode == 1
        result = json.loads((td / 'coverage.json').read_text())
        assert any('T-CAND-2' in e for e in result['errors'])
        (reviews / 'two.json').write_text(json.dumps({'candidate_id': 'T-CAND-2', 'decision': 'Reject'}))
        run_subprocess('tools/validate_candidate_reviews.py', ['--ranked-candidates', str(ranked), '--review-dir', str(reviews), '--max-candidates', '2', '--out', str(td / 'coverage-ok.json')])
        assert json.loads((td / 'coverage-ok.json').read_text())['passed'] is True


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
    test_select_scope_is_deterministic_for_common_profiles()
    print('workflow validator tests passed')
