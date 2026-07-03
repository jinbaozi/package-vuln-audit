#!/usr/bin/env python3
"""Validate stage policy, manifest, workflow docs, and driver step IDs stay aligned."""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
import manifest_io
from pvas_io import write_json

BUSINESS_WORKFLOWS = [
    '00-intake', '01-package-profile', '02-scope-selection', '03-tool-scan',
    '04-ai-hypothesis', '05-candidate-review', '06-validation',
    '07-cvss-scoring', '08-report', '09-progressive-disclosure',
]


def _step_ids(entries: object) -> list[str]:
    if not isinstance(entries, list):
        return []
    return [str(e.get('step_id')) for e in entries if isinstance(e, dict) and e.get('step_id')]


def _policy_step_ids(text: str) -> list[str]:
    return re.findall(r'^\s*-\s+step_id:\s*"([^"]+)"', text, flags=re.M)


def validate(root: pathlib.Path) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    manifest_path = root / 'core' / 'manifest.yaml'
    policies_path = root / 'core' / 'exceptions' / 'stage-policies.yaml'
    driver_path = root / 'tools' / 'enforced_audit_driver.py'

    manifest = manifest_io.load_manifest(manifest_path)
    policies_text = policies_path.read_text(errors='ignore')
    manifest_steps = _step_ids(manifest.get('stages'))
    policy_steps = _policy_step_ids(policies_text)
    workflow_steps = [p.stem for p in sorted((root / 'workflows').glob('*.md'))]
    driver_text = driver_path.read_text(errors='ignore')

    for step in BUSINESS_WORKFLOWS:
        if step not in manifest_steps:
            errors.append(f'{step}: missing from core/manifest.yaml stages')
        if step not in policy_steps:
            errors.append(f'{step}: missing from stage-policies.yaml policies')
        if step not in workflow_steps:
            errors.append(f'{step}: missing workflow doc workflows/{step}.md')
        if repr(step) not in driver_text and f'"{step}"' not in driver_text:
            errors.append(f'{step}: missing from enforced_audit_driver.py')

    manifest_business = [s for s in manifest_steps if s in BUSINESS_WORKFLOWS]
    policy_business = [s for s in policy_steps if s in BUSINESS_WORKFLOWS]
    if manifest_business != BUSINESS_WORKFLOWS:
        errors.append(f'manifest business step order mismatch: {manifest_business}')
    if policy_business != BUSINESS_WORKFLOWS:
        errors.append(f'policy business step order mismatch: {policy_business}')

    artifacts = manifest.get('artifacts') or []
    artifact_step_ids = {
        str(a.get('step_id')) for a in artifacts
        if isinstance(a, dict) and a.get('step_id')
    }
    for step in BUSINESS_WORKFLOWS:
        if step not in artifact_step_ids:
            warnings.append(f'{step}: no registered artifact with this step_id')

    return {
        'passed': not errors,
        'status': 'passed' if not errors else 'failed',
        'errors': errors,
        'warnings': warnings,
        'workflow_steps': BUSINESS_WORKFLOWS,
        'manifest_business_steps': manifest_business,
        'policy_business_steps': policy_business,
        'workflow_doc_steps': workflow_steps,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.')
    ap.add_argument('--out', default='audit-output/machine/stage-policy-sync.json')
    args = ap.parse_args()
    result = validate(pathlib.Path(args.root).resolve())
    write_json(args.out, result)
    print({'status': result['status'], 'errors': len(result['errors']), 'warnings': len(result['warnings'])})
    return 1 if result['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
