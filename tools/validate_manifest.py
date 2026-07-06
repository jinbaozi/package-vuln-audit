#!/usr/bin/env python3
"""Validate core/manifest.yaml against on-disk workflows, schemas, and invariants."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import manifest_io
from pvas_io import emit_gate_result, load_json, write_json

VALID_LOAD_TIERS = frozenset({'L0', 'L1', 'L2', 'L3', 'L4'})


def validate_manifest(root: pathlib.Path, manifest_path: pathlib.Path) -> dict:
    errors: list[str] = []
    warnings: list[str] = []

    try:
        manifest = manifest_io.load_manifest(manifest_path)
    except (OSError, ValueError) as exc:
        errors.append(f'failed to load manifest: {exc}')
        return {'status': 'failed', 'errors': errors, 'warnings': warnings}

    schema_root = pathlib.Path(manifest.get('schema_root', 'schemas'))
    workflow_files = sorted((root / 'workflows').glob('*.md'))
    workflow_file_ids = [p.stem for p in workflow_files]
    business_ids: list[str] = []

    seen_step_ids: dict[str, int] = {}
    for stage in manifest.get('stages') or []:
        if not isinstance(stage, dict):
            errors.append(f'invalid stage entry (expected mapping): {stage!r}')
            continue
        step_id = stage.get('step_id')
        if step_id is not None:
            seen_step_ids[step_id] = seen_step_ids.get(step_id, 0) + 1
        workflow_doc = stage.get('workflow_doc')
        if workflow_doc is None:
            continue
        wf_path = root / workflow_doc
        if not wf_path.is_file():
            errors.append(f'missing workflow_doc for step {step_id!r}: {workflow_doc}')
        expected_workflow_doc = pathlib.PurePosixPath('workflows') / f'{step_id}.md'
        if pathlib.PurePosixPath(str(workflow_doc)) == expected_workflow_doc:
            business_ids.append(str(step_id))
        elif str(workflow_doc).startswith('workflows/'):
            errors.append(
                f'business workflow stage {step_id!r}: step_id must match workflow file stem '
                f'({workflow_doc})'
            )

    for step_id, count in sorted(seen_step_ids.items()):
        if count > 1:
            errors.append(f'duplicate step_id in stages: {step_id!r} ({count} occurrences)')

    business_set = set(business_ids)
    for wf_id in workflow_file_ids:
        if wf_id not in business_set:
            errors.append(f'workflow file missing manifest business stage: workflows/{wf_id}.md')
    for step_id in business_ids:
        if step_id not in workflow_file_ids:
            errors.append(f'manifest business stage missing workflow file: {step_id}')
    if business_ids != workflow_file_ids:
        errors.append(
            'manifest business workflow order must match workflow file numbering: '
            f'manifest={business_ids}, files={workflow_file_ids}'
        )

    for art in manifest.get('artifacts') or []:
        if not isinstance(art, dict):
            errors.append(f'invalid artifact entry (expected mapping): {art!r}')
            continue
        art_id = art.get('id', '<unknown>')
        load_tier = art.get('load_tier')
        if load_tier is not None and load_tier not in VALID_LOAD_TIERS:
            errors.append(
                f'artifact {art_id!r}: invalid load_tier {load_tier!r} (expected L0–L4)'
            )
        schema_name = art.get('schema')
        if schema_name:
            schema_file = root / schema_root / schema_name
            if not schema_file.is_file():
                errors.append(
                    f'artifact {art_id!r}: missing schema {schema_root / schema_name}'
                )

    exc_agg = manifest.get('exception_aggregation') or {}
    if isinstance(exc_agg, dict):
        schema_path = exc_agg.get('schema_path')
        if schema_path:
            exc_schema = root / schema_path
            if not exc_schema.is_file():
                errors.append(f'missing exception_aggregation.schema_path: {schema_path}')
    else:
        errors.append('exception_aggregation must be a mapping')

    xc_errs, xc_warns = manifest_io.crosscheck_schemas(root, manifest)
    errors.extend(xc_errs)
    # Schema files on disk not in registered_schemas must block validation
    for w in xc_warns:
        if 'not registered in manifest' in w:
            errors.append(w)
        else:
            warnings.append(w)

    return {
        'status': 'failed' if errors else 'passed',
        'errors': errors,
        'warnings': warnings,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description='Validate PVAS core manifest consistency')
    ap.add_argument('--root', default='.')
    ap.add_argument('--manifest', default='core/manifest.yaml')
    ap.add_argument('--out', default='audit-output/machine/manifest-validation.json')
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    manifest_path = root / args.manifest
    result = validate_manifest(root, manifest_path)
    emit_gate_result(args.out, result)
    print(
        json.dumps(
            {
                'status': result['status'],
                'errors': len(result['errors']),
                'warnings': len(result['warnings']),
            },
            indent=2,
        )
    )
    return 1 if result['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
