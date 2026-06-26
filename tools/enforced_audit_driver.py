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
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    env_out = out / '00-environment'
    write_step(out, '00-intake', 'completed', 'continue', outputs=[str(out)])

    rc, _ = run([sys.executable, 'tools/enforce_workflow_contract.py', '--root', '.', '--out', str(out/'machine/workflow-contract.json')], allow_fail=True)
    write_step(out, '00-workflow-contract', 'completed' if rc == 0 else 'failed', 'continue' if rc == 0 else 'block', outputs=[str(out/'machine/workflow-contract.json')], issues=[] if rc == 0 else ['workflow contract failed'])
    if rc != 0:
        return rc

    env_cmd = [sys.executable, 'tools/verify_environment.py', '--profile', args.profile, '--mode', args.mode, '--out', str(env_out)]
    if args.allow_degraded:
        env_cmd.append('--allow-degraded')
    rc, _ = run(env_cmd, allow_fail=True)
    run([sys.executable, 'tools/generate_install_plan.py', '--environment-check', str(env_out/'environment-check.json'), '--out', str(env_out)], allow_fail=True)
    if rc != 0 and args.mode == 'strict' and args.install_assist:
        env = json.loads((env_out/'environment-check.json').read_text())
        missing = ','.join(env.get('blocking_missing_tools') or env.get('missing_tools') or [])
        run([sys.executable, 'tools/install_assistant.py', '--tools', missing, '--mode', 'strict', '--dry-run', '--out', str(env_out)], allow_fail=True)
        write_step(out, '00-environment', 'blocked', 'block', outputs=[str(env_out/'environment-check.json'), str(env_out/'install-assistant-decision.json')], issues=['strict required tool missing'])
        return 2
    if rc != 0:
        write_step(out, '00-environment', 'blocked', 'block', outputs=[str(env_out/'environment-check.json')], issues=['environment gate failed'])
        return rc
    write_step(out, '00-environment', 'completed', 'continue', outputs=[str(env_out/'environment-check.json'), str(env_out/'tool-install-plan.json')])

    run(['bash', 'tools/profile_project.sh', args.source, str(out/'01-profile')], allow_fail=False)
    write_step(out, '01-package-profile', 'completed', 'continue', outputs=[str(out/'01-profile/package-profile.json'), str(out/'01-profile/context-budget.json')])

    run(['bash', 'tools/run_tools.sh', args.source, str(out/'02-tools')], allow_fail=True)
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

    if args.findings and args.public_records:
        corr = out/'machine/correlation/public-vuln-correlation.json'
        run([sys.executable, 'tools/check_offline_db_freshness.py', '--out', str(out/'machine/correlation/offline-db-freshness.json')], allow_fail=True)
        run([sys.executable, 'tools/correlate_public_vulns.py', '--findings', args.findings, '--records', args.public_records, '--out', str(corr)], allow_fail=False)
        run([sys.executable, 'tools/publish_bilingual_reports.py', '--findings', args.findings, '--correlation', str(corr), '--out', str(out)], allow_fail=False)
        rc, _ = run([sys.executable, 'tools/validate_report_completeness.py', '--findings', args.findings, '--correlation', str(corr), '--report-root', str(out), '--out', str(out/'machine/report-completeness.json')], allow_fail=True)
        write_step(out, '08-report', 'completed' if rc == 0 else 'failed', 'continue' if rc == 0 else 'block', outputs=[str(corr), str(out/'machine/report-completeness.json')], issues=[] if rc == 0 else ['report completeness failed'])
        return rc
    write_step(out, '08-report', 'skipped', 'continue', limitations=['no --findings/--public-records provided; final report gates not executed'])
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
