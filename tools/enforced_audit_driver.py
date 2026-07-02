#!/usr/bin/env python3
"""Unified enforced audit driver for PVAS workflow execution gates.

The driver records and enforces every business workflow stage (00-09). Each
stage receives one initial attempt plus two retries. A mandatory artifact or
postflight failure ends as failed-after-retries, triggers exception aggregation,
and returns non-zero instead of continuing to a pseudo-complete report.
"""
import argparse
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / 'tools'
OPENEULER_INDEX = ROOT / 'offline-bundle' / 'vuln-db' / 'openeuler' / 'cve-index.json'
OPENEULER_MANIFEST = ROOT / 'offline-bundle' / 'vuln-db' / 'openeuler' / 'manifest.json'
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from pvas_env import env_flag
from pvas_io import load_json, write_json
from validate_validation_results import finding_errors as validation_finding_errors

FINAL_STATUSES = {'completed', 'completed-with-recovery', 'not-applicable', 'failed-after-retries'}
TOOL_BLOCKING_STATUSES = {'blocked-pending-confirmation', 'blocked-recovery-required', 'abnormal'}
BUSINESS_WORKFLOWS = [
    '00-intake', '01-package-profile', '02-scope-selection', '03-tool-scan',
    '04-ai-hypothesis', '05-candidate-review', '06-validation',
    '07-cvss-scoring', '08-report', '09-progressive-disclosure',
]


@dataclass
class StageResult:
    ok: bool
    decision: str = 'continue'
    outputs: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    not_applicable: bool = False
    details: dict = field(default_factory=dict)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _summary_limit() -> int:
    try:
        return max(int(os.environ.get('PVAS_TERMINAL_SUMMARY_CHARS', '1000')), 80)
    except ValueError:
        return 1000


def _truncate_text(text: str, limit: int | None = None) -> str:
    text = str(text)
    limit = _summary_limit() if limit is None else limit
    if len(text) <= limit:
        return text
    return text[: max(limit - 15, 0)] + '...[truncated]'


def _truncate_list(items: list[str]) -> list[str]:
    return [_truncate_text(str(item)) for item in items]


def run(cmd: list[str], allow_fail: bool = False) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode and not allow_fail:
        raise RuntimeError(f'command failed ({p.returncode}): {" ".join(cmd)}\n{p.stdout}')
    return p.returncode, p.stdout


def refresh_exception_index(out: pathlib.Path) -> None:
    run([sys.executable, 'tools/aggregate_exceptions.py', '--audit-output', str(out)], allow_fail=True)


def _write_localized_step(out_root: pathlib.Path, payload: dict) -> None:
    step_id = payload['step_id']
    zh = out_root / 'zh-CN' / 'workflow-steps'
    en = out_root / 'en-US' / 'workflow-steps'
    zh.mkdir(parents=True, exist_ok=True)
    en.mkdir(parents=True, exist_ok=True)
    outputs = payload.get('outputs_written') or []
    issues = payload.get('blocking_issues') or []
    limitations = payload.get('limitations') or []
    zh_lines = [
        f'# {step_id}', '',
        f"- 状态：{payload.get('status')}",
        f"- 决策：{payload.get('decision')}",
        f"- 尝试次数：{payload.get('attempt_count', 0)}",
        f"- 输出：{', '.join(outputs) if outputs else '无'}",
        f"- 问题：{'；'.join(issues) if issues else '无'}",
        f"- 限制：{'；'.join(limitations) if limitations else '无'}",
    ]
    en_lines = [
        f'# {step_id}', '',
        f"- Status: {payload.get('status')}",
        f"- Decision: {payload.get('decision')}",
        f"- Attempts: {payload.get('attempt_count', 0)}",
        f"- Outputs: {', '.join(outputs) if outputs else 'none'}",
        f"- Issues: {'; '.join(issues) if issues else 'none'}",
        f"- Limitations: {'; '.join(limitations) if limitations else 'none'}",
    ]
    (zh / f'{step_id}.md').write_text('\n'.join(zh_lines) + '\n')
    (en / f'{step_id}.md').write_text('\n'.join(en_lines) + '\n')


def write_step(out_root: pathlib.Path, step_id: str, status: str, decision: str, inputs=None, outputs=None,
               issues=None, limitations=None, *, attempt_count: int = 1, last_error_summary: str = '',
               recovery_actions=None, artifact_refs=None, details=None) -> dict:
    if status not in FINAL_STATUSES:
        raise ValueError(f'invalid workflow status {status!r}')
    inputs = inputs or []
    outputs = outputs or []
    issues = issues or []
    limitations = limitations or []
    recovery_actions = recovery_actions or []
    artifact_refs = artifact_refs or outputs
    payload = {
        'step_id': step_id,
        'status': status,
        'decision': decision,
        'inputs_checked': inputs,
        'outputs_written': outputs,
        'required_artifacts_present': not issues,
        'blocking_issues': issues,
        'limitations': limitations,
        'attempt_count': attempt_count,
        'last_error_summary': last_error_summary,
        'recovery_actions': recovery_actions,
        'artifact_refs': artifact_refs,
        'details': details or {},
        'generated_at': _iso_now(),
    }
    machine = out_root / 'machine' / 'workflow-steps'
    write_json(machine / f'{step_id}.json', payload)
    _write_localized_step(out_root, payload)
    return payload


def _coerce_stage_result(value) -> StageResult:
    if isinstance(value, StageResult):
        return value
    if value is None:
        return StageResult(True)
    if isinstance(value, bool):
        return StageResult(value, issues=[] if value else ['stage returned false'])
    if isinstance(value, tuple):
        ok = bool(value[0])
        issues = [str(x) for x in value[1:]] if len(value) > 1 and not ok else []
        return StageResult(ok, issues=issues)
    return StageResult(True, details={'result': str(value)})


def _summarize_error(exc: BaseException) -> str:
    text = ''.join(traceback.format_exception_only(type(exc), exc)).strip()
    return _truncate_text(text)


def run_stage(step_id: str, preflight: Callable[[], StageResult | bool | None] | None,
              execute: Callable[[], StageResult | bool | None] | None,
              postflight: Callable[[], StageResult | bool | None] | None,
              *, out_root: pathlib.Path, retry: int = 2, inputs=None,
              outputs=None, recovery_actions=None) -> StageResult:
    attempts: list[dict] = []
    attempts_dir = out_root / 'machine' / 'workflow-attempts'
    attempts_dir.mkdir(parents=True, exist_ok=True)
    outputs = outputs or []
    recovery_actions = recovery_actions or ['retry stage execution after recording failure']
    last = StageResult(False, issues=['stage did not run'])
    last_error = ''

    for attempt in range(1, retry + 2):
        record = {'step_id': step_id, 'attempt': attempt, 'started_at': _iso_now(), 'status': 'running'}
        try:
            pre = _coerce_stage_result(preflight() if preflight else None)
            if not pre.ok:
                last = pre
                raise RuntimeError('; '.join(pre.issues) or 'preflight failed')
            exe = _coerce_stage_result(execute() if execute else None)
            if not exe.ok:
                last = exe
                raise RuntimeError('; '.join(exe.issues) or 'execution failed')
            post = _coerce_stage_result(postflight() if postflight else None)
            if not post.ok:
                last = post
                raise RuntimeError('; '.join(post.issues) or 'postflight failed')
            merged_outputs = list(dict.fromkeys(outputs + exe.outputs + post.outputs))
            missing_outputs = [p for p in merged_outputs if p and not pathlib.Path(p).exists()]
            if missing_outputs and not (pre.not_applicable or exe.not_applicable or post.not_applicable):
                last = StageResult(False, issues=[f'missing declared output: {p}' for p in missing_outputs])
                raise RuntimeError('; '.join(last.issues))
            limitations = list(dict.fromkeys(pre.limitations + exe.limitations + post.limitations))
            status = 'not-applicable' if (pre.not_applicable or exe.not_applicable or post.not_applicable) else ('completed-with-recovery' if attempt > 1 else 'completed')
            decision = 'continue'
            final = StageResult(True, decision=decision, outputs=merged_outputs, limitations=limitations,
                                not_applicable=status == 'not-applicable', details={**pre.details, **exe.details, **post.details})
            record.update({'status': status, 'decision': decision, 'finished_at': _iso_now(), 'outputs': merged_outputs})
            attempts.append(record)
            write_json(attempts_dir / f'{step_id}.json', {'step_id': step_id, 'attempts': attempts})
            write_step(out_root, step_id, status, decision, inputs=inputs, outputs=merged_outputs,
                       limitations=limitations, attempt_count=attempt, last_error_summary=last_error,
                       recovery_actions=recovery_actions if attempt > 1 else [], details=final.details)
            return final
        except Exception as exc:
            last_error = _summarize_error(exc)
            issues = _truncate_list(list(last.issues)) if last.issues else [last_error]
            record.update({'status': 'failed-attempt', 'decision': 'retry' if attempt <= retry else 'fail',
                           'finished_at': _iso_now(), 'error': last_error,
                           'issues': issues, 'recovery_actions': recovery_actions})
            attempts.append(record)
            write_json(attempts_dir / f'{step_id}.json', {'step_id': step_id, 'attempts': attempts})
            if str(last.decision).startswith('blocked-'):
                final = StageResult(False, decision=last.decision, outputs=outputs, issues=issues, details=last.details)
                write_step(out_root, step_id, 'failed-after-retries', last.decision, inputs=inputs, outputs=outputs,
                           issues=issues, attempt_count=attempt, last_error_summary=last_error,
                           recovery_actions=['obtain user confirmation and rerun with --resume'], artifact_refs=outputs,
                           details=last.details)
                refresh_exception_index(out_root)
                return final

    issues = list(last.issues) if last.issues else [last_error or 'stage failed after retries']
    issues = _truncate_list(issues)
    final = StageResult(False, decision='failed', outputs=outputs, issues=issues)
    write_step(out_root, step_id, 'failed-after-retries', 'failed', inputs=inputs, outputs=outputs,
               issues=issues, attempt_count=retry + 1, last_error_summary=last_error,
               recovery_actions=recovery_actions, artifact_refs=outputs, details=last.details)
    refresh_exception_index(out_root)
    return final


def require_paths(paths: list[pathlib.Path], label: str = 'artifact') -> StageResult:
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        return StageResult(False, issues=[f'missing {label}: {p}' for p in missing])
    return StageResult(True, outputs=[str(p) for p in paths])


def intake_network_policy(intake_dir: pathlib.Path) -> str:
    data = load_json(intake_dir / 'intake.json', default={})
    policy = data.get('network_policy') if isinstance(data, dict) else None
    return policy if policy in {'offline', 'restricted', 'online-approved'} else 'restricted'


def tool_scan_decision(summary_path: pathlib.Path) -> tuple[bool, list[str]]:
    summary = load_json(summary_path, default={})
    tools = summary.get('tools') if isinstance(summary, dict) else []
    abnormal = [
        t.get('name', '?') for t in tools
        if isinstance(t, dict)
        and (t.get('status') in TOOL_BLOCKING_STATUSES or t.get('strict_decision') == 'block')
    ]
    limitations = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        if t.get('status') in {'incomplete', 'not-installed', 'blocked-pending-confirmation', 'blocked-recovery-required'}:
            limitations.append(f"{t.get('name', '?')}: {t.get('reason') or t.get('status')}")
    return bool(abnormal), limitations


def _confirmation_dir(out_root: pathlib.Path) -> pathlib.Path:
    return out_root / 'machine' / 'user-confirmations'


def _load_confirmation_required(out_root: pathlib.Path) -> dict:
    return load_json(_confirmation_dir(out_root) / 'confirmation-required.json', default={}) or {}


def _load_confirmation_decisions(out_root: pathlib.Path) -> list[dict]:
    data = load_json(_confirmation_dir(out_root) / 'confirmation-decisions.json', default={}) or {}
    if isinstance(data, dict):
        decisions = data.get('decisions', [])
        return decisions if isinstance(decisions, list) else []
    if isinstance(data, list):
        return data
    return []


def validate_resume_confirmation(out_root: pathlib.Path, token: str | None = None, action: str | None = None) -> StageResult:
    required = _load_confirmation_required(out_root)
    expected_token = token or required.get('token')
    expected_action = action or required.get('action')
    if not expected_token or not expected_action:
        return StageResult(False, issues=['missing confirmation token or action'])
    for decision in _load_confirmation_decisions(out_root):
        if not isinstance(decision, dict):
            continue
        if (
            decision.get('token') == expected_token
            and decision.get('action') == expected_action
            and decision.get('decision') == 'approved'
        ):
            return StageResult(True, decision='continue', details={'confirmation_token': expected_token, 'confirmation_action': expected_action})
    return StageResult(False, issues=['missing approved confirmation decision'])


def _write_confirmation_decision(out_root: pathlib.Path, decision: dict) -> None:
    path = _confirmation_dir(out_root) / 'confirmation-decisions.json'
    decisions = _load_confirmation_decisions(out_root)
    decisions.append(decision)
    write_json(path, {'decisions': decisions})


def request_confirmation(out_root: pathlib.Path, action: str, step_id: str, reason: dict,
                         *, interactive: bool | None = None) -> StageResult:
    token = secrets.token_urlsafe(18)
    payload = {
        'schema_version': '1.0',
        'status': 'pending',
        'step_id': step_id,
        'action': action,
        'reason': reason,
        'token': token,
        'instructions': [
            'Review the requested action and its audit impact.',
            'To resume non-interactively, add an approved matching token to confirmation-decisions.json and rerun enforced_audit_driver.py --resume.',
        ],
        'generated_at': _iso_now(),
    }
    write_json(_confirmation_dir(out_root) / 'confirmation-required.json', payload)
    use_tty = sys.stdin.isatty() if interactive is None else interactive
    if use_tty:
        answer = input(f"PVAS confirmation required for {action} at {step_id}. Approve? [y/N] ").strip().lower()
        if answer == 'y':
            _write_confirmation_decision(out_root, {
                'token': token,
                'action': action,
                'step_id': step_id,
                'decision': 'approved',
                'decided_by': os.environ.get('USER', 'interactive-user'),
                'decided_at': _iso_now(),
            })
            return StageResult(True, decision='continue', details={'confirmation_token': token, 'confirmation_action': action})
    return StageResult(
        False,
        decision='blocked-pending-confirmation',
        issues=[f'user confirmation required for {action}; see machine/user-confirmations/confirmation-required.json'],
        details={'confirmation_token': token, 'confirmation_action': action},
    )


def _findings(path: str | None) -> list[dict]:
    if not path:
        return []
    data = load_json(pathlib.Path(path), default=[])
    if isinstance(data, dict):
        return data.get('findings', [])
    return data if isinstance(data, list) else []


def _candidate_review_required(path: pathlib.Path, limit: int) -> bool:
    data = load_json(path, default={})
    cands = data.get('candidates', []) if isinstance(data, dict) else []
    return bool(cands[:limit])


def _has_scoreable_findings(findings: list[dict]) -> bool:
    return any((f.get('status') or f.get('state')) in {'Likely', 'Validated'} for f in findings)


def _has_d3_d4_findings(findings: list[dict]) -> bool:
    for f in findings:
        level = str(f.get('disclosure_level') or f.get('disclosure', '')).upper()
        if level.startswith('D3') or level.startswith('D4') or 'D3' in level or 'D4' in level:
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', default='.')
    ap.add_argument('--out', default='audit-output')
    ap.add_argument('--profile', default=os.environ.get('PVAS_ENV_PROFILE', 'standard'))
    ap.add_argument('--mode', default=os.environ.get('PVAS_TOOL_MODE', 'default'), choices=['default', 'strict'])
    ap.add_argument('--allow-degraded', action='store_true', default=env_flag('PVAS_ALLOW_DEGRADED'))
    ap.add_argument('--install-assist', action='store_true', default=env_flag('PVAS_INSTALL_ASSIST', default=True))
    ap.add_argument('--max-candidates', default=os.environ.get('PVAS_MAX_CANDIDATES', '20'))
    ap.add_argument('--findings', help='Validated findings JSON for final report gates')
    ap.add_argument('--public-records', help='Normalized public vuln records JSON')
    ap.add_argument('--allow-network', action='store_true', default=False, help='Allow fetching public vulnerability sources from network')
    ap.add_argument('--fetch-package', help='Package name for public vulnerability source fetching')
    ap.add_argument('--resume', action='store_true', help='Resume after an approved user confirmation decision')
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    max_candidates = int(args.max_candidates)

    # System gates retained as pre-business gates.
    contract = run_stage(
        '00-workflow-contract',
        None,
        lambda: StageResult(*(lambda rc: (rc == 0, 'continue'))(run([sys.executable, 'tools/enforce_workflow_contract.py', '--root', '.', '--out', str(out / 'machine/workflow-contract.json')], allow_fail=True)[0])),
        lambda: require_paths([out / 'machine/workflow-contract.json']),
        out_root=out,
        outputs=[str(out / 'machine/workflow-contract.json')],
    )
    if not contract.ok:
        return 2

    manifest = run_stage(
        '00-manifest-validation',
        None,
        lambda: StageResult(run([sys.executable, 'tools/validate_manifest.py', '--root', '.', '--out', str(out / 'machine/manifest-validation.json')], allow_fail=True)[0] == 0,
                            issues=['manifest validation failed; see manifest-validation.json']),
        lambda: require_paths([out / 'machine/manifest-validation.json']),
        out_root=out,
        outputs=[str(out / 'machine/manifest-validation.json')],
    )
    if not manifest.ok:
        return 2

    intake_dir = out / '00-intake'
    intake_dir.mkdir(parents=True, exist_ok=True)
    def exec_intake():
        cmd = [sys.executable, 'tools/validate_intake.py', '--intake-dir', str(intake_dir), '--out', str(out / 'machine/intake-validation.json')]
        if args.findings:
            cmd.append('--require-present')
        rc, _ = run(cmd, allow_fail=True)
        return StageResult(rc == 0, issues=['intake preflight failed; see intake-validation.json'])
    stage = run_stage('00-intake', None, exec_intake,
                      lambda: require_paths([intake_dir / 'intake.json', out / 'machine/intake-validation.json']),
                      out_root=out, outputs=[str(intake_dir / 'intake.json'), str(out / 'machine/intake-validation.json')],
                      recovery_actions=['create or correct intake.json/scope.md, then retry validation'])
    if not stage.ok:
        return 2
    network_policy = intake_network_policy(intake_dir)

    env_out = out / '00-environment'
    def exec_env():
        cmd = [sys.executable, 'tools/strict_env_gate.py', '--out', str(env_out), '--profile', args.profile, '--mode', args.mode]
        if args.allow_degraded:
            cmd.append('--allow-degraded')
        rc, _ = run(cmd, allow_fail=True)
        issues = ['strict required tool missing'] if rc != 0 and args.mode == 'strict' and args.install_assist else ['environment gate failed']
        return StageResult(rc == 0, issues=issues)
    stage = run_stage('00-environment', lambda: require_paths([intake_dir / 'intake.json']), exec_env,
                      lambda: require_paths([env_out / 'environment-check.json']),
                      out_root=out, outputs=[str(env_out / 'environment-check.json')])
    if not stage.ok:
        return 2

    stage = run_stage('01-package-profile', lambda: require_paths([intake_dir / 'intake.json']),
                      lambda: StageResult(run(['bash', 'tools/profile_project.sh', args.source, str(out / '01-profile')], allow_fail=True)[0] == 0,
                                          issues=['package profiling failed']),
                      lambda: require_paths([out / '01-profile/package-profile.json', out / '01-profile/context-budget.json']),
                      out_root=out, outputs=[str(out / '01-profile/package-profile.json'), str(out / '01-profile/context-budget.json')])
    if not stage.ok:
        return 2

    def exec_scope():
        rc, tool_out = run([sys.executable, 'tools/select_scope.py', '--profile', str(out / '01-profile/package-profile.json'), '--source', args.source, '--out-dir', str(out / '01-profile')], allow_fail=True)
        if rc != 0:
            return StageResult(False, issues=[tool_out[-1000:] or 'scope selection failed'])
        matrix_path = out / '01-profile' / 'required-tools-matrix.json'
        cmd = [sys.executable, 'tools/generate_tool_matrix.py', '--package-profile', str(out / '01-profile/package-profile.json'), '--profile', args.profile, '--network-policy', network_policy]
        if args.allow_network and network_policy == 'online-approved':
            cmd.append('--allow-network')
        cmd.extend(['--out', str(matrix_path)])
        rc, tool_out = run(cmd, allow_fail=True)
        return StageResult(rc == 0, issues=[tool_out[-1000:] or 'tool matrix generation failed'])
    stage = run_stage('02-scope-selection', lambda: require_paths([out / '01-profile/package-profile.json']), exec_scope,
                      lambda: require_paths([out / '01-profile/selected-scope.json', out / '01-profile/selected-recipes.md', out / '01-profile/required-tools-matrix.json']),
                      out_root=out, outputs=[str(out / '01-profile/selected-scope.json'), str(out / '01-profile/selected-recipes.md'), str(out / '01-profile/required-tools-matrix.json')])
    if not stage.ok:
        return 2

    def exec_tools():
        os.environ['PVAS_SKIP_ENV_GATE'] = '1'
        rc, tool_out = run(['bash', 'tools/run_tools.sh', args.source, str(out / '02-tools')], allow_fail=True)
        abnormal, tool_limitations = tool_scan_decision(out / '02-tools/tool-summary.json')
        should_fail = abnormal or (rc != 0 and not (out / '02-tools/tool-summary.json').is_file())
        if should_fail and (out / '02-tools/tool-summary.json').is_file():
            summary = load_json(out / '02-tools/tool-summary.json', default={}) or {}
            blocked_tools = [
                {
                    'name': t.get('name'),
                    'status': t.get('status'),
                    'reason': t.get('reason'),
                    'coverage_impact': t.get('coverage_impact'),
                }
                for t in summary.get('tools', [])
                if isinstance(t, dict) and (t.get('status') in TOOL_BLOCKING_STATUSES or t.get('strict_decision') == 'block')
            ]
            action = 'recover-required-tools'
            if args.resume:
                resume = validate_resume_confirmation(out, action=action)
                if resume.ok:
                    return StageResult(
                        True,
                        limitations=tool_limitations + [f"user-approved continuation after blocked tool scan: {', '.join(t.get('name') or '?' for t in blocked_tools)}"],
                        details=resume.details,
                    )
                return resume
            confirmation = request_confirmation(out, action, '03-tool-scan', {'tools': blocked_tools, 'runner_exit_code': rc}, interactive=None)
            if not confirmation.ok:
                return confirmation
            return StageResult(
                True,
                limitations=tool_limitations + [f"user-approved continuation after blocked tool scan: {', '.join(t.get('name') or '?' for t in blocked_tools)}"],
                details=confirmation.details,
            )
        return StageResult(not should_fail,
                           issues=['traditional tool scan abnormal; see tool-summary.json and tool-execution-attempts.json'] if should_fail else [],
                           limitations=tool_limitations + ([] if rc == 0 else [tool_out[-1000:]]))
    stage = run_stage('03-tool-scan', lambda: require_paths([out / '01-profile/required-tools-matrix.json']), exec_tools,
                      lambda: require_paths([out / '02-tools/tool-summary.json']),
                      out_root=out, outputs=[str(out / '02-tools/tool-summary.json'), str(out / '02-tools/tool-execution-attempts.json')],
                      recovery_actions=['retry traditional tool scan; preserve tool-execution-attempts.json'])
    if not stage.ok:
        return 2

    def exec_ai_hypothesis():
        run([sys.executable, 'tools/normalize_results.py', '--tools-dir', str(out / '02-tools/raw'), '--out', str(out / '03-candidates/raw-candidates.json')])
        run([sys.executable, 'tools/rank_candidates.py', '--input', str(out / '03-candidates/raw-candidates.json'), '--out', str(out / '03-candidates/ranked-candidates.json')])
        run([sys.executable, 'tools/make_ai_packets.py', '--candidates', str(out / '03-candidates/ranked-candidates.json'), '--source-root', args.source, '--out', str(out / '03-candidates/packets'), '--max-packets', str(max_candidates)])
        post_budget = out / '03-candidates/context-budget-post-packet.json'
        rc, tool_out = run([sys.executable, 'tools/context_budget.py', '--profile-dir', str(out / '01-profile'), '--packet-dir', str(out / '03-candidates/packets'), '--out', str(post_budget)])
        if rc != 0:
            return StageResult(False, issues=[tool_out[-1000:] or 'post-packet context budget failed'])
        budget = load_json(post_budget, required=True)
        decision = budget.get('decision')
        if decision not in {'safe', 'warning', 'split-required'}:
            return StageResult(False, issues=[f'post-packet budget decision={decision}'])
        rc, tool_out = run([sys.executable, 'tools/prepare_ai_hypothesis_task.py', '--ranked-candidates', str(out / '03-candidates/ranked-candidates.json'), '--selected-scope', str(out / '01-profile/selected-scope.json'), '--out-dir', str(out / '03-candidates'), '--max-candidates', str(max_candidates)])
        rc, tool_out = run([sys.executable, 'tools/exec_ai_hypothesis_agent.py', '--ranked-candidates', str(out / '03-candidates/ranked-candidates.json'), '--packet-dir', str(out / '03-candidates/packets'), '--selected-scope', str(out / '01-profile/selected-scope.json'), '--out', str(out / '03-candidates/ai-hypotheses.json'), '--max-candidates', str(max_candidates)])
        return StageResult(rc == 0, issues=[tool_out[-1000:] or 'AI hypothesis generation failed'])
    def post_ai_hypothesis():
        rc, tool_out = run([sys.executable, 'tools/validate_hypotheses.py', '--hypotheses', str(out / '03-candidates/ai-hypotheses.json'), '--out', str(out / '03-candidates/ai-hypotheses-validation.json')], allow_fail=True)
        return StageResult(rc == 0, issues=[tool_out[-1000:] or 'AI hypotheses validation failed'], outputs=[str(out / '03-candidates/ai-hypotheses-validation.json')])
    stage = run_stage('04-ai-hypothesis', lambda: require_paths([out / '02-tools/tool-summary.json', out / '01-profile/selected-scope.json']), exec_ai_hypothesis, post_ai_hypothesis,
                      out_root=out,
                      outputs=[str(out / '03-candidates/raw-candidates.json'), str(out / '03-candidates/ranked-candidates.json'), str(out / '03-candidates/packets'), str(out / '03-candidates/context-budget-post-packet.json'), str(out / '03-candidates/ai-hypothesis-task.json'), str(out / '03-candidates/ai-hypotheses.json')],
                      recovery_actions=['regenerate AI hypothesis task packet and revalidate ai-hypotheses.json'])
    if not stage.ok:
        return 2

    def exec_reviews():
        if not _candidate_review_required(out / '03-candidates/ranked-candidates.json', max_candidates):
            summary = {'candidates': [], 'not_applicable': True, 'reason': 'no ranked candidates require review'}
            write_json(out / '03-candidates/candidate-summary.json', summary)
            return StageResult(True, not_applicable=True, outputs=[str(out / '03-candidates/candidate-summary.json')])
        rc, tool_out = run([sys.executable, 'tools/exec_candidate_review_agent.py', '--ranked-candidates', str(out / '03-candidates/ranked-candidates.json'), '--packet-dir', str(out / '03-candidates/packets'), '--review-dir', str(out / '03-candidates/reviews'), '--summary-out', str(out / '03-candidates/candidate-summary.json'), '--max-candidates', str(max_candidates)], allow_fail=True)
        return StageResult(rc == 0, issues=[tool_out[-1000:] or 'candidate review execution failed'], outputs=[str(out / '03-candidates/candidate-summary.json')])
    def post_reviews():
        if not _candidate_review_required(out / '03-candidates/ranked-candidates.json', max_candidates):
            return require_paths([out / '03-candidates/candidate-summary.json'])
        rc, tool_out = run([sys.executable, 'tools/validate_candidate_reviews.py', '--ranked-candidates', str(out / '03-candidates/ranked-candidates.json'), '--review-dir', str(out / '03-candidates/reviews'), '--max-candidates', str(max_candidates), '--out', str(out / '03-candidates/candidate-review-validation.json')], allow_fail=True)
        if rc != 0:
            return StageResult(False, issues=[tool_out[-1000:] or 'candidate review coverage failed'], outputs=[str(out / '03-candidates/candidate-review-validation.json')])
        return require_paths([out / '03-candidates/candidate-review-validation.json', out / '03-candidates/candidate-summary.json'])
    stage = run_stage('05-candidate-review', lambda: require_paths([out / '03-candidates/ranked-candidates.json', out / '03-candidates/ai-hypotheses.json']), exec_reviews, post_reviews,
                      out_root=out, outputs=[str(out / '03-candidates/reviews'), str(out / '03-candidates/candidate-summary.json')],
                      recovery_actions=['regenerate missing candidate review packets and validate coverage'])
    if not stage.ok:
        return 2

    findings = _findings(args.findings)
    def exec_validation():
        if not args.findings:
            write_json(out / '04-validation/validation-summary.json', {'status': 'not-applicable', 'reason': 'no --findings provided'})
            return StageResult(True, not_applicable=True, outputs=[str(out / '04-validation/validation-summary.json')])
        schema_rc = validate_finding_schema(args.findings, out, complete_audit=True)
        if schema_rc != 0:
            return StageResult(False, issues=['finding JSON failed schema validation'])

        findings_out = out / '04-validation' / 'updated-findings.json'
        validation_root = out / '04-validation'
        val_cmd = [sys.executable, 'tools/exec_validation_agent.py',
                   '--findings', args.findings,
                   '--packet-dir', str(out / '03-candidates/packets'),
                   '--source-root', args.source,
                   '--candidate-summary', str(out / '03-candidates/candidate-summary.json'),
                   '--out', str(validation_root),
                   '--findings-out', str(findings_out)]
        if env_flag('ALLOW_VALIDATION_RUN'):
            val_cmd.append('--allow-run')
        exec_rc, exec_out = run(val_cmd, allow_fail=True)
        if exec_rc != 0:
            return StageResult(False, issues=[exec_out[-1000:] or 'validation agent execution failed'])

        validation_result = validation_root / 'validation-result-summary.json'
        rc, tool_out = run([sys.executable, 'tools/validate_validation_results.py', '--findings', str(findings_out), '--out', str(validation_result)], allow_fail=True)
        if rc != 0:
            return StageResult(False, issues=[tool_out[-1000:] or 'validation result evidence failed'])
        manual_out = validation_root / 'manual-review'
        run([sys.executable, 'tools/generate_manual_validation_plan.py', '--findings', str(findings_out), '--out', str(manual_out)], allow_fail=False)
        poc_out = validation_root / 'poc-tests'
        run([sys.executable, 'tools/generate_poc_testcase.py', '--findings', str(findings_out), '--generate-from-finding', '--out', str(poc_out)], allow_fail=True)
        poc_v_rc, _ = run([sys.executable, 'tools/validate_poc_artifacts.py', '--poc-root', str(poc_out)], allow_fail=True)
        if poc_v_rc != 0:
            return StageResult(False, issues=['poc validation failed'])
        write_json(out / '04-validation/validation-summary.json', {'status': 'completed', 'findings': len(findings)})
        return StageResult(True, outputs=[str(out / 'machine/schema-validation-result.json'), str(validation_result), str(manual_out), str(poc_out), str(out / '04-validation/validation-summary.json')])
    stage = run_stage('06-validation', lambda: require_paths([out / '03-candidates/candidate-review-validation.json']) if _candidate_review_required(out / '03-candidates/ranked-candidates.json', max_candidates) else None,
                      exec_validation, lambda: require_paths([out / '04-validation/validation-summary.json']),
                      out_root=out, outputs=[str(out / 'machine/schema-validation-result.json'), str(out / '04-validation/manual-review'), str(out / '04-validation/poc-tests'), str(out / '04-validation/validation-summary.json')],
                      recovery_actions=['regenerate validation plans or PoC artifacts and rerun validators'])
    if not stage.ok:
        return 2

    def exec_cvss():
        if not _has_scoreable_findings(findings):
            write_json(out / '05-findings/cvss-summary.json', {'status': 'not-applicable', 'reason': 'no Likely or Validated findings'})
            return StageResult(True, not_applicable=True, outputs=[str(out / '05-findings/cvss-summary.json')])
        issues = validate_cvss31_findings(args.findings)
        if issues:
            return StageResult(False, issues=issues)
        write_json(out / '05-findings/cvss-summary.json', {'status': 'completed', 'scored_findings': len([f for f in findings if (f.get('status') or f.get('state')) in {'Likely', 'Validated'}])})
        return StageResult(True, outputs=[str(out / '05-findings/cvss-summary.json')])
    stage = run_stage('07-cvss-scoring', lambda: require_paths([out / '04-validation/validation-summary.json']), exec_cvss,
                      lambda: require_paths([out / '05-findings/cvss-summary.json']), out_root=out,
                      outputs=[str(out / '05-findings/cvss-summary.json')], recovery_actions=['rerun CVSS calculator validation for scoreable findings'])
    if not stage.ok:
        return 2

    def exec_report():
        if not args.findings:
            write_json(out / '06-report/machine/report-completeness.json', {'status': 'not-applicable', 'reason': 'no --findings provided'})
            return StageResult(True, not_applicable=True, outputs=[str(out / '06-report/machine/report-completeness.json')])
        if not args.public_records and args.allow_network and args.fetch_package:
            fetch_out = out / 'machine' / 'correlation' / 'fetched-records'
            fetch_out.mkdir(parents=True, exist_ok=True)
            run([sys.executable, 'tools/fetch_public_vuln_sources.py', '--sources', 'NVD,OSV', '--package', args.fetch_package, '--out', str(fetch_out), '--allow-network'], allow_fail=True)
            args.public_records = str(fetch_out)
        corr = out / 'machine' / 'correlation' / 'public-vuln-correlation.json'
        if args.public_records:
            freshness_cmd = [sys.executable, 'tools/check_offline_db_freshness.py', '--out', str(out / 'machine/correlation/offline-db-freshness.json')]
            if OPENEULER_MANIFEST.is_file():
                freshness_cmd.extend(['--extra-manifest', str(OPENEULER_MANIFEST)])
            run(freshness_cmd, allow_fail=True)
            norm_records = out / 'machine' / 'correlation' / 'normalized-public-records.json'
            run([sys.executable, 'tools/normalize_public_vuln_records.py', '--input', args.public_records, '--out', str(norm_records)], allow_fail=True)
            run([sys.executable, 'tools/correlate_public_vulns.py', '--findings', args.findings, '--records', str(norm_records), '--openeuler-index', str(OPENEULER_INDEX), '--out', str(corr)], allow_fail=False)
            run([sys.executable, 'tools/apply_correlation_to_findings.py', '--findings', args.findings, '--correlation', str(corr), '--out', args.findings], allow_fail=False)
            run([sys.executable, 'tools/publish_bilingual_reports.py', '--findings', args.findings, '--correlation', str(corr), '--out', str(out), '--skip-final-report'], allow_fail=False)
        run([sys.executable, 'tools/generate_final_report.py', '--audit-root', str(out), '--findings', args.findings, '--out', str(out / '06-report')] + (['--correlation', str(corr)] if corr.exists() else []), allow_fail=False)
        rc, _ = run([sys.executable, 'tools/validate_report_completeness.py', '--findings', args.findings, '--correlation', str(corr), '--report-root', str(out), '--require-workflow-steps', '--out', str(out / 'machine/report-completeness.json')], allow_fail=True)
        if rc != 0:
            return StageResult(False, issues=['report completeness failed'])
        return StageResult(True, outputs=[str(out / '06-report/machine'), str(out / '06-report/zh-CN'), str(out / '06-report/en-US'), str(out / 'machine/report-completeness.json')])
    stage = run_stage('08-report', lambda: require_paths([out / '05-findings/cvss-summary.json']), exec_report,
                      lambda: StageResult(True, not_applicable=not bool(args.findings)) if not args.findings else require_paths([out / '06-report/machine', out / '06-report/zh-CN', out / '06-report/en-US', out / 'machine/report-completeness.json']),
                      out_root=out, outputs=[str(out / '06-report/machine'), str(out / '06-report/zh-CN'), str(out / '06-report/en-US'), str(out / 'machine/report-completeness.json')],
                      recovery_actions=['regenerate reports and rerun report completeness gate'])
    if not stage.ok:
        return 2

    def exec_disclosure():
        run([sys.executable, 'tools/summarize_artifacts.py', '--audit-output', str(out), '--out', str(out / 'machine/artifact-summary.json')], allow_fail=True)
        if not _has_d3_d4_findings(findings):
            write_json(out / '07-disclosure/disclosure-summary.json', {'status': 'not-applicable', 'reason': 'no D3/D4 findings'})
            return StageResult(True, not_applicable=True, outputs=[str(out / 'machine/artifact-summary.json'), str(out / '07-disclosure/disclosure-summary.json')])
        disclosure_dir = out / '07-disclosure'
        disclosure_dir.mkdir(parents=True, exist_ok=True)
        write_json(disclosure_dir / 'disclosure-summary.json', {'status': 'completed', 'findings': [f.get('id') for f in findings]})
        return StageResult(True, outputs=[str(out / 'machine/artifact-summary.json'), str(disclosure_dir / 'disclosure-summary.json')])
    stage = run_stage('09-progressive-disclosure', lambda: require_paths([out / 'machine/workflow-steps/08-report.json']), exec_disclosure,
                      lambda: require_paths([out / 'machine/artifact-summary.json', out / '07-disclosure/disclosure-summary.json']),
                      out_root=out, outputs=[str(out / 'machine/artifact-summary.json'), str(out / '07-disclosure/disclosure-summary.json')])
    if not stage.ok:
        return 2

    refresh_exception_index(out)
    return 0


def validate_cvss31_findings(findings_path: str) -> list[str]:
    raw = load_json(findings_path, required=True)
    findings_list_data = raw.get('findings') if isinstance(raw, dict) and 'findings' in raw else (raw if isinstance(raw, list) else [])
    issues: list[str] = []
    for f in findings_list_data:
        if f.get('status') not in {'Validated', 'Likely'}:
            continue
        cvss = f.get('cvss') or {}
        if not cvss:
            issues.append(f"{f.get('id', '?')}: missing CVSS block")
            continue
        if cvss.get('version') != '3.1':
            issues.append(f"{f.get('id', '?')}: CVSS version must be 3.1")
            continue
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as tf:
            json.dump({'cvss': cvss}, tf)
            tf_path = tf.name
        try:
            rc, out = run([sys.executable, 'tools/cvss31_calculator.py', '--validate', '--in', tf_path], allow_fail=True)
            if rc != 0:
                issues.append(f"{f.get('id', '?')}: CVSS v3.1 validation failed: {out.strip()[-500:]}")
        finally:
            pathlib.Path(tf_path).unlink(missing_ok=True)
    return issues


def validate_finding_schema(findings_path: str, out_root: pathlib.Path, *, complete_audit: bool = False) -> int:
    result_file = out_root / 'machine' / 'schema-validation-result.json'

    def write_result(passed: bool, errors: list[str]) -> None:
        write_json(result_file, {'passed': passed, 'errors': errors})

    try:
        import jsonschema
    except ImportError:
        if complete_audit:
            write_result(False, ['EX-SCH-001: jsonschema required for complete audit'])
            return 1
        return 0
    try:
        schema = load_json(ROOT / 'schemas' / 'finding.schema.json', required=True)
        validator = jsonschema.Draft202012Validator(schema)
        findings = load_json(findings_path, required=True)
        if isinstance(findings, dict):
            findings_list_data = findings.get('findings') or []
        elif isinstance(findings, list):
            findings_list_data = findings
        else:
            findings_list_data = []
        errors = []
        for i, f in enumerate(findings_list_data):
            try:
                validator.validate(f)
            except jsonschema.ValidationError as e:
                errors.append(f'finding[{i}]: {e.message}')
            if isinstance(f, dict):
                errors.extend(validation_finding_errors(f))
        write_result(len(errors) == 0, errors)
        return 0 if not errors else 1
    except Exception as e:
        if complete_audit:
            write_result(False, [str(e)])
            return 1
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
