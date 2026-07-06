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


def test_business_workflow_ids_are_manifest_derived_and_exclude_system_gates():
    steps = manifest_io.business_workflow_ids(ROOT)
    assert steps == [
        '00-intake', '01-package-profile', '02-scope-selection', '03-tool-scan',
        '04-ai-hypothesis', '05-candidate-review', '06-validation',
        '07-cvss-scoring', '08-report', '09-progressive-disclosure',
    ]
    assert '00-environment' not in steps
    assert '10-final-completeness' not in steps


def test_every_workflow_doc_has_manifest_business_stage():
    workflow_ids = [p.stem for p in sorted((ROOT / 'workflows').glob('*.md'))]
    assert manifest_io.business_workflow_ids(ROOT) == workflow_ids


def test_artifact_load_tiers_are_valid():
    m = manifest_io.load_manifest(ROOT / 'core' / 'manifest.yaml')
    valid = {'L0', 'L1', 'L2', 'L3', 'L4'}
    for art in m.get('artifacts', []):
        assert art['load_tier'] in valid


if __name__ == '__main__':
    test_load_manifest_has_business_workflows_and_l4_forbidden()
    test_business_workflow_ids_are_manifest_derived_and_exclude_system_gates()
    test_every_workflow_doc_has_manifest_business_stage()
    test_artifact_load_tiers_are_valid()
    print('manifest_io tests passed')
