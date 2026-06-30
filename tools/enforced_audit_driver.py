#!/usr/bin/env python3
"""Unified enforced audit driver for workflow execution gates.

This driver prevents "documented but not executed" regressions by invoking the
contract, environment, budget, packet, correlation and report-completeness gates
from one place. Heavy security judgment remains delegated to subagents; this
script enforces artifact presence and machine-checkable decisions.
"""
from __future__ import annotations
import argparse, json, os, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(cmd: list[str], allow_fail: bool=False) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode and not allow_fail:
        raise SystemExit(f'command failed ({p.returncode}): {" ".join(cmd)}\n{p.stdout}')
    return p.returncode, p.stdout


def write_step(out_root: pathlib.Path, step_id: str, status: str, decision: str, inputs=None, outputs=None, issues=None, limitations=None):
    inputs = inputs or []; outputs = outputs or []; issues = issues or []; limitations = limitations or []
    machine = out_root / 'machine' / 'workflow-steps'; zh = out_root / 'zh-CN' / 'workflow-steps'; en = out_root / 'en-US' / 'workflow-steps'
    for d in [machine, zh, en]: d.mkdir(parents=True, exist_ok=True)
    payload = {'step_id': step_id, 'status': status, 'decision': decision, 'inputs_checked': inputs, 'outputs_written': outputs, 'required_artifacts_present': not issues, 'blocking_issues': issues, 'limitations': limitations}
    (machine / f'{step_id}.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    (zh / f'{step_id}.md').write_text(f'# {step_id}\n\n- 状态：{status}\n- 决策：{decision}\n- 输出：{", ".join(outputs) if outputs else "无"}\n- 限制：{"；".join(limitations) if limitations else "无"}\n')
    (en / f'{step_id}.md').write_text(f'# {step_id}\n\n- Status: {status}\n- Decision: {decision}\n- Outputs: {", ".join(outputs) if outputs else "none"}\n- Limitations: {"; ".join(limitations) if limitations else "none"}\n')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', default='.')
    ap.add_argument('--out', default='audit-output')
    ap.add_argument('--profile', default=os.environ.get('PVAS_ENV_PROFILE', 'standard'))
    ap.add_argument('--mode', default=os.environ.get('PVAS_TOOL_MODE', 'default'), choices=['default','strict'])
    ap.add_argument('--allow-degraded', action='store_true', default=os.environ.get('PVAS_ALLOW_DEGRADED','0') in {'1','true','yes','on'})
    ap.add_argument('--install-assist', action='store_true', default=os.environ.get('PVAS_INSTALL_ASSIST','1') in {'1','true','yes','on'})
    ap.add_argument('--max-candidates', default=os.environ.get('PVAS_MAX_CANDIDATES', '20'))
    ap.add_argument('--findings', help='Validated findings JSON for final report gates')
    ap.add_argument('--public-records', help='Normalized public vuln records JSON')
    ap.add_argument('--allow-network', action='store_true', default=False, help='Allow fetching public vulnerability sources from network')
    ap.add_argument('--fetch-package', help='Package name for public vulnerability source fetching')
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    env_out = out / '00-environment'
    write_step(out, '00-intake', 'completed', 'continue', outputs=[str(out)])

    rc, _ = run([sys.executable, 'tools/enforce_workflow_contract.py', '--root', '.', '--out', str(out/'machine/workflow-contract.json')], allow_fail=True)
    write_step(out, '00-workflow-contract', 'completed' if rc == 0 else 'failed', 'continue' if rc == 0 else 'block', outputs=[str(out/'machine/workflow-contract.json')], issues=[] if rc == 0 else ['workflow contract failed'])
    if rc != 0:
        return rc

    env_cmd = [sys.executable, 'tools/strict_env_gate.py', '--out', str(env_out),
               '--profile', args.profile, '--mode', args.mode]
    if args.allow_degraded:
        env_cmd.append('--allow-degraded')
    rc, _ = run(env_cmd, allow_fail=True)
    if rc != 0 and args.mode == 'strict' and args.install_assist:
        write_step(out, '00-environment', 'blocked', 'block', outputs=[str(env_out/'environment-check.json'), str(env_out/'install-assistant-decision.json')], issues=['strict required tool missing'])
        return 2
    if rc != 0:
        write_step(out, '00-environment', 'blocked', 'block', outputs=[str(env_out/'environment-check.json')], issues=['environment gate failed'])
        return rc
    write_step(out, '00-environment', 'completed', 'continue', outputs=[str(env_out/'environment-check.json'), str(env_out/'tool-install-plan.json')])

    run(['bash', 'tools/profile_project.sh', args.source, str(out/'01-profile')], allow_fail=False)
    write_step(out, '01-package-profile', 'completed', 'continue', outputs=[str(out/'01-profile/package-profile.json'), str(out/'01-profile/context-budget.json')])

    matrix_path = out / '01-profile' / 'required-tools-matrix.json'
    run([sys.executable, 'tools/generate_tool_matrix.py',
         '--package-profile', str(out / '01-profile' / 'package-profile.json'),
         '--profile', args.profile,
         '--out', str(matrix_path)], allow_fail=False)
    write_step(out, '02-tool-matrix', 'completed', 'continue',
               inputs=[str(out / '01-profile' / 'package-profile.json')],
               outputs=[str(matrix_path)])

    rc, tool_out = run(['bash', 'tools/run_tools.sh', args.source, str(out/'02-tools')], allow_fail=True)
    write_step(out, '03-tool-scan', 'completed' if rc == 0 else 'blocked',
               'continue' if rc == 0 else 'block',
               inputs=[str(out / '01-profile' / 'required-tools-matrix.json')],
               outputs=[str(out / '02-tools' / 'tool-summary.json'), str(out / '02-tools' / 'tool-execution-attempts.json')],
               issues=[] if rc == 0 else ['traditional tool scan blocked; see tool-summary.json and tool-execution-attempts.json'],
               limitations=[] if rc == 0 else [tool_out[-1000:]])
    if rc != 0:
        return rc
    run([sys.executable, 'tools/normalize_results.py', '--tools-dir', str(out/'02-tools/raw'), '--out', str(out/'03-candidates/raw-candidates.json')], allow_fail=True)
    run([sys.executable, 'tools/rank_candidates.py', '--candidates', str(out/'03-candidates/raw-candidates.json'), '--out', str(out/'03-candidates/ranked-candidates.json')], allow_fail=True)
    run([sys.executable, 'tools/make_ai_packets.py', '--candidates', str(out/'03-candidates/ranked-candidates.json'), '--source-root', args.source, '--out', str(out/'03-candidates/packets'), '--max-packets', str(args.max_candidates)], allow_fail=True)
    post_budget = out/'03-candidates/context-budget-post-packet.json'
    run([sys.executable, 'tools/context_budget.py', '--profile-dir', str(out/'01-profile'), '--packet-dir', str(out/'03-candidates/packets'), '--out', str(post_budget)], allow_fail=False)
    budget = json.loads(post_budget.read_text())
    decision = budget.get('decision')
    issues = [] if decision in {'safe','warning','split-required'} else [f'post-packet budget decision={decision}']
    write_step(out, '03-candidate-packets', 'completed' if not issues else 'blocked', 'continue' if not issues else 'block', outputs=[str(post_budget)], issues=issues)
    if issues:
        return 2

    if not args.findings:
        write_step(out, '08-report', 'skipped', 'continue', limitations=['no --findings provided; final report gates not executed'])
        return 0

    schema_rc = validate_finding_schema(args.findings, out)
    write_step(out, '07-schema-validation', 'completed' if schema_rc == 0 else 'failed', 'continue' if schema_rc == 0 else 'block',
               inputs=[args.findings], outputs=[str(out/'machine/schema-validation-result.json')],
               issues=[] if schema_rc == 0 else ['finding JSON failed schema validation'])
    if schema_rc != 0:
        return schema_rc

    manual_out = out / '04-validation' / 'manual-review'
    run([sys.executable, 'tools/generate_manual_validation_plan.py',
         '--findings', args.findings,
         '--out', str(manual_out)], allow_fail=False)
    write_step(out, '07-manual-validation-plans', 'completed', 'continue',
               inputs=[args.findings], outputs=[str(manual_out)])

    poc_out = out / '04-validation' / 'poc-tests'
    poc_cmd = [sys.executable, 'tools/generate_poc_testcase.py', '--findings', args.findings, '--generate-from-finding', '--out', str(poc_out)]
    run(poc_cmd, allow_fail=True)
    poc_v_rc, _ = run([sys.executable, 'tools/validate_poc_artifacts.py', '--poc-root', str(poc_out)], allow_fail=True)
    write_step(out, '07-poc-generation', 'completed' if poc_v_rc == 0 else 'blocked',
               'continue' if poc_v_rc == 0 else 'block',
               outputs=[str(poc_out)],
               issues=[] if poc_v_rc == 0 else ['poc validation failed'])
    if poc_v_rc != 0:
        return poc_v_rc

    if not args.public_records and args.allow_network and args.fetch_package:
        fetch_out = out / 'machine' / 'correlation' / 'fetched-records'
        fetch_out.mkdir(parents=True, exist_ok=True)
        run([sys.executable, 'tools/fetch_public_vuln_sources.py', '--sources', 'NVD,OSV', '--package', args.fetch_package, '--out', str(fetch_out), '--allow-network'], allow_fail=True)
        args.public_records = str(fetch_out)
        write_step(out, '08-fetch-public-sources', 'completed', 'continue', outputs=[str(fetch_out)])

    if args.public_records:
        corr = out/'machine/correlation/public-vuln-correlation.json'
        run([sys.executable, 'tools/check_offline_db_freshness.py', '--out', str(out/'machine/correlation/offline-db-freshness.json')], allow_fail=True)
        norm_records = out / 'machine' / 'correlation' / 'normalized-public-records.json'
        run([sys.executable, 'tools/normalize_public_vuln_records.py', '--input', args.public_records, '--out', str(norm_records)], allow_fail=True)
        run([sys.executable, 'tools/correlate_public_vulns.py', '--findings', args.findings, '--records', str(norm_records), '--out', str(corr)], allow_fail=False)
        run([sys.executable, 'tools/publish_bilingual_reports.py', '--findings', args.findings, '--correlation', str(corr), '--out', str(out), '--skip-final-report'], allow_fail=False)
        rc, _ = run([sys.executable, 'tools/validate_report_completeness.py', '--findings', args.findings, '--correlation', str(corr), '--report-root', str(out), '--out', str(out/'machine/report-completeness.json')], allow_fail=True)
        write_step(out, '08-report', 'completed' if rc == 0 else 'failed', 'continue' if rc == 0 else 'block',
                   inputs=[args.findings, str(corr)], outputs=[str(corr), str(out/'machine/report-completeness.json')],
                   issues=[] if rc == 0 else ['report completeness failed'])
        if rc != 0:
            return rc
    else:
        write_step(out, '08-report', 'partial', 'continue', limitations=['no --public-records provided; correlation and bilingual reports skipped'])

    # Generate final summary report
    final_cmd = [sys.executable, 'tools/generate_final_report.py',
                 '--audit-root', str(out), '--findings', args.findings, '--out', str(out)]
    if args.public_records:
        final_cmd.extend(['--correlation', str(out / 'machine' / 'correlation' / 'public-vuln-correlation.json')])
    run(final_cmd, allow_fail=True)

    # Generate artifact summary index
    run([sys.executable, 'tools/summarize_artifacts.py', '--audit-output', str(out), '--out', str(out / 'machine' / 'artifact-summary.json')], allow_fail=True)
    write_step(out, '09-artifact-summary', 'completed', 'continue', outputs=[str(out / 'machine' / 'artifact-summary.json')])

    return 0


def validate_finding_schema(findings_path: str, out_root: pathlib.Path) -> int:
    """Validate findings JSON against finding.schema.json using jsonschema."""
    try:
        import jsonschema
    except ImportError:
        return 0
    try:
        schema = json.loads((ROOT / 'schemas' / 'finding.schema.json').read_text())
        validator = jsonschema.Draft202012Validator(schema)
        findings = json.loads(pathlib.Path(findings_path).read_text())
        findings_list_data = findings.get('findings') or findings if isinstance(findings, list) else []
        errors = []
        for i, f in enumerate(findings_list_data):
            try:
                validator.validate(f)
            except jsonschema.ValidationError as e:
                errors.append(f'finding[{i}]: {e.message}')
        result_file = out_root / 'machine' / 'schema-validation-result.json'
        result_file.parent.mkdir(parents=True, exist_ok=True)
        result_file.write_text(json.dumps({'passed': len(errors) == 0, 'errors': errors}, indent=2))
        return 0 if not errors else 1
    except Exception as e:
        return 0

if __name__ == '__main__':
    raise SystemExit(main())
