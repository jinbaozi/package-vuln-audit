#!/usr/bin/env python3
"""Enforce workflow/agent/tool/schema/template/adapter consistency."""
from __future__ import annotations
import argparse, json, pathlib, re, sys

REQUIRED_DIRS = ['workflows', 'tools', 'schemas', 'templates', 'agents', 'adapters']
REQUIRED_TOOLS = [
    'verify_environment.py', 'generate_install_plan.py', 'install_assistant.py', 'context_budget.py',
    'make_ai_packets.py', 'correlate_public_vulns.py', 'publish_bilingual_reports.py',
    'validate_report_completeness.py', 'check_offline_db_freshness.py'
]
REQUIRED_SCHEMAS = [
    'environment-check.schema.json', 'tool-install-plan.schema.json', 'install-assistant-summary.schema.json',
    'install-assistant-decision.schema.json', 'context-budget.schema.json', 'public-vuln-correlation.schema.json',
    'report.schema.json', 'bilingual-output.schema.json', 'poc-testcase.schema.json'
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
    for f in REQUIRED_SCHEMAS:
        if not (root / 'schemas' / f).is_file():
            fail(f'missing required schema: schemas/{f}', errors)
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
    out = pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(result, indent=2))
    print(json.dumps({'status': result['status'], 'errors': len(result['errors']), 'warnings': len(result['warnings'])}, indent=2))
    return 1 if result['errors'] else 0

if __name__ == '__main__':
    raise SystemExit(main())
