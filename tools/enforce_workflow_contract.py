#!/usr/bin/env python3
"""Enforce workflow/agent/tool/schema/template/adapter consistency."""
from __future__ import annotations
import argparse, json, pathlib, re, sys

from pvas_io import emit_gate_result

REQUIRED_DIRS = ['workflows', 'tools', 'schemas', 'templates', 'agents', 'adapters']
REQUIRED_TOOLS = [
    'verify_environment.py',
    'generate_install_plan.py',
    'install_assistant.py',
    'context_budget.py',
    'make_ai_packets.py',
    'correlate_public_vulns.py',
    'publish_bilingual_reports.py',
    'validate_report_completeness.py',
    'check_offline_db_freshness.py',
    'enforced_audit_driver.py',
    'enforce_workflow_contract.py',
    'normalize_results.py',
    'rank_candidates.py',
    'generate_poc_testcase.py',
    'validate_poc_artifacts.py',
    'generate_final_report.py',
    'fetch_public_vuln_sources.py',
    'normalize_public_vuln_records.py',
    'summarize_artifacts.py',
    'cvss31_calculator.py',
    'import_openeuler_vuln_registry.py',
    'tool_catalog.py',
    'validate_manifest.py',
    'validate_intake.py',
    'aggregate_exceptions.py',
    'manifest_io.py',
    'pvas_env.py',
    'budget_common.py',
    'generate_guides_index.py',
]
REQUIRED_TEMPLATES = ['tool-install-plan.md', 'finding.md', 'internal-report.md']
REQUIRED_WORKFLOW_TERMS = ['Purpose', 'Inputs', 'Outputs']
REQUIRED_ADAPTER_TERMS = ['package-profiler', 'tool-runner', 'candidate-reviewer', 'validator', 'report-writer']


def fail(msg: str, errors: list[str]):
    errors.append(msg)


def check_root(root: pathlib.Path) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    for d in REQUIRED_DIRS:
        if not (root / d).is_dir():
            fail(f'missing required directory: {d}', errors)
    for f in REQUIRED_TOOLS:
        if not (root / 'tools' / f).is_file():
            fail(f'missing required tool: tools/{f}', errors)

    manifest_path = root / 'core' / 'manifest.yaml'
    if not manifest_path.is_file():
        warnings.append('missing core/manifest.yaml')
    else:
        try:
            sys.path.insert(0, str(root / 'tools'))
            import validate_manifest as vm
            mv = vm.validate_manifest(root, manifest_path)
            warnings.extend(mv.get('warnings') or [])
            for e in mv.get('errors') or []:
                fail(e, errors)
        except Exception as e:
            warnings.append(f'manifest validation skipped: {e}')

    for f in REQUIRED_TEMPLATES:
        if not (root / 'templates' / f).is_file():
            fail(f'missing required template: templates/{f}', errors)

    workflows = sorted((root / 'workflows').glob('*.md'))
    if not workflows:
        fail('no workflows found', errors)
    for wf in workflows:
        text = wf.read_text(errors='ignore')
        for term in REQUIRED_WORKFLOW_TERMS:
            if term.lower() not in text.lower():
                warnings.append(f'{wf}: missing explicit workflow section/term: {term}')
        if 'machine' not in text or 'zh-CN' not in text or 'en-US' not in text:
            warnings.append(f'{wf}: should explicitly mention machine/zh-CN/en-US step conclusions')

    agent_names = {p.stem for p in (root / 'agents').glob('*.md')}
    for term in REQUIRED_ADAPTER_TERMS:
        if term not in agent_names:
            warnings.append(f'agent not found in root agents/: {term}')

    command_files = list((root / 'adapters').glob('*/commands/*.md'))
    if not command_files:
        fail('no adapter command files found under adapters/*/commands', errors)
    complete_commands = [p for p in command_files if p.name == 'package-vuln-audit.md']
    if not complete_commands:
        fail('missing package-vuln-audit adapter command', errors)
    for cmd in complete_commands:
        text = cmd.read_text(errors='ignore')
        for term in REQUIRED_ADAPTER_TERMS:
            if term not in text:
                fail(f'{cmd}: missing adapter command term: {term}', errors)
        for gate in ['Context Budget', 'public', 'correlation']:
            if gate.lower() not in text.lower():
                warnings.append(f'{cmd}: should mention enforced {gate} gate')

    return {
        'status': 'failed' if errors else 'passed',
        'errors': errors,
        'warnings': warnings,
        'checked': {
            'workflow_count': len(workflows),
            'adapter_command_count': len(command_files),
            'root_agents_count': len(agent_names),
        }
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.')
    ap.add_argument('--out', default='audit-output/machine/workflow-contract.json')
    args = ap.parse_args()
    result = check_root(pathlib.Path(args.root))
    emit_gate_result(args.out, result)
    print(json.dumps({'status': result['status'], 'errors': len(result['errors']), 'warnings': len(result['warnings'])}, indent=2))
    return 1 if result['errors'] else 0

if __name__ == '__main__':
    raise SystemExit(main())
