#!/usr/bin/env python3
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import manifest_io


def test_load_manifest_has_business_workflows_and_l4_forbidden():
    m = manifest_io.load_manifest(ROOT / 'core' / 'manifest.yaml')
    step_ids = {s['step_id'] for s in m['stages']}
    for step in [
        '00-intake', '01-package-profile', '02-scope-selection', '03-tool-scan',
        '04-ai-hypothesis', '05-candidate-review', '06-validation',
        '07-cvss-scoring', '08-report', '09-progressive-disclosure',
    ]:
        assert step in step_ids
    assert '03-candidate-packets' not in step_ids
    forbidden = m.get('l4_forbidden_patterns') or []
    assert any('raw' in p for p in forbidden)


def test_artifact_load_tiers_are_valid():
    m = manifest_io.load_manifest(ROOT / 'core' / 'manifest.yaml')
    valid = {'L0', 'L1', 'L2', 'L3', 'L4'}
    for art in m.get('artifacts', []):
        assert art['load_tier'] in valid


if __name__ == '__main__':
    test_load_manifest_has_business_workflows_and_l4_forbidden()
    test_artifact_load_tiers_are_valid()
    print('manifest_io tests passed')
