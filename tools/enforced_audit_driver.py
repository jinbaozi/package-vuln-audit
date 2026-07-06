#!/usr/bin/env python3
"""Unified enforced audit driver for PVAS workflow execution gates.

The driver records and enforces every business workflow stage (00-09). Each
stage receives one initial attempt plus two retries. A mandatory artifact or
postflight failure ends as failed-after-retries, triggers exception aggregation,
and returns non-zero instead of continuing to a pseudo-complete report.
"""
import argparse
import atexit
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import traceback
import uuid
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
import pvas_container
import pvas_image
import pvas_netpolicy
from validate_validation_results import finding_errors as validation_finding_errors

FINAL_STATUSES = {'completed', 'completed-with-recovery', 'not-applicable', 'failed-after-retries'}
TOOL_BLOCKING_STATUSES = {'blocked-pending-confirmation', 'blocked-recovery-required', 'abnormal'}
BUSINESS_WORKFLOWS = [
    '00-intake', '01-package-profile', '02-scope-selection', '03-tool-scan',
    '04-ai-hypothesis', '05-candidate-review', '06-validation',
    '07-cvss-scoring', '08-report', '09-progressive-disclosure',
]
WORKFLOW_PRESETS = {
    'strict-efficient': {
        'mode': 'strict',
        'allow_degraded': False,
        'context_efficient': True,
        'packet_strict_budget': True,
    },
    'strict-degraded': {
        'mode': 'strict',
        'allow_degraded': True,
        'context_efficient': True,
        'packet_strict_budget': True,
    },
    'compat-default': {
        'mode': 'default',
        'allow_degraded': False,
        'context_efficient': False,
        'packet_strict_budget': False,
    },
}
STARTUP_PATH = pathlib.Path('machine/workflow-startup.json')
CPPCHECK_MODE_PATH = pathlib.Path('machine/cppcheck-mode.json')
CPPCHECK_MODES = {'fast', 'deep'}
_SANDBOX_CLEANUP_REGISTERED = False


@dataclass
class StageResult:
    ok: bool
    decision: str = 'continue'
    outputs: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    not_applicable: bool = False
    details: dict = field(default_factory=dict)


@dataclass
class StartupConfig:
    preset: str
    mode: str
    allow_degraded: bool
    context_efficient: bool
    packet_strict_budget: bool
    prompt_source: str
    overrides: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            'preset': self.preset,
            'mode': self.mode,
            'allow_degraded': self.allow_degraded,
            'context_efficient': self.context_efficient,
            'packet_strict_budget': self.packet_strict_budget,
            'prompt_source': self.prompt_source,
            'overrides': self.overrides,
            'generated_at': _iso_now(),
        }


@dataclass
class CppcheckModeConfig:
    mode: str
    mode_source: str
    previous_mode_source: str = ''

    def as_dict(self) -> dict:
        payload = {
            'mode': self.mode,
            'mode_source': self.mode_source,
            'generated_at': _iso_now(),
        }
        if self.previous_mode_source:
            payload['previous_mode_source'] = self.previous_mode_source
        return payload


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _read_rootfs_sha256(rootfs_dir: pathlib.Path) -> str:
    sums = rootfs_dir / 'SHA256SUMS'
    if not sums.exists():
        return '0' * 64
    for line in sums.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == 'v11-2503-rootfs.tar':
            return parts[0]
    return '0' * 64


def _sandbox_cleanup(audit_id: str, backend: str, out: pathlib.Path) -> None:
    try:
        pvas_netpolicy.flush_all()
    except Exception:
        pass
    if backend:
        try:
            pvas_image.prompt_cleanup(audit_id, backend, log_path=out / 'machine/sandbox-cleanup.jsonl')
        except Exception:
            pass


def initialize_sandbox_runtime(out: pathlib.Path) -> dict:
    global _SANDBOX_CLEANUP_REGISTERED
    audit_id = os.environ.get('PVAS_AUDIT_ID') or f"pvas-{uuid.uuid4()}"
    os.environ['PVAS_AUDIT_ID'] = audit_id
    mode = os.environ.get('PVAS_SANDBOX', 'enabled').lower()
    state = {
        'audit_id': audit_id,
        'mode': mode,
        'status': 'disabled' if mode in {'0', 'false', 'no', 'disabled'} else 'unknown',
        'backend': '',
        'imported_image': '',
        'runtime_image': '',
        'generated_at': _iso_now(),
    }
    if state['status'] == 'disabled':
        write_json(out / 'machine/sandbox-runtime.json', state)
        return state
    try:
        backend = pvas_container.detect_backend()
        state['backend'] = backend
    except pvas_container.SandboxUnavailable as exc:
        state.update({'status': 'unavailable', 'error': str(exc)})
        write_json(out / 'machine/sandbox-runtime.json', state)
        return state

    if not _SANDBOX_CLEANUP_REGISTERED:
        atexit.register(_sandbox_cleanup, audit_id, backend, out)
        _SANDBOX_CLEANUP_REGISTERED = True

    rootfs_dir = ROOT / 'sandbox' / 'rootfs'
    tar_path = rootfs_dir / 'v11-2503-rootfs.tar'
    dockerfile = ROOT / 'sandbox' / 'images' / 'Dockerfile.runtime'
    try:
        imported = pvas_image.ensure_imported(
            tar_path,
            _read_rootfs_sha256(rootfs_dir),
            pvas_image.DEFAULT_IMAGE_IMPORTED,
            backend,
        )
        runtime = pvas_image.ensure_runtime_image(
            imported,
            pvas_image.DEFAULT_IMAGE_RUNTIME,
            dockerfile,
            backend,
        )
        os.environ['PVAS_RUNTIME_IMAGE'] = runtime
        state.update({'status': 'ready', 'imported_image': imported, 'runtime_image': runtime})
    except Exception as exc:
        state.update({'status': 'image-unavailable', 'error': str(exc)})
    write_json(out / 'machine/sandbox-runtime.json', state)
    return state


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


def _resolve_from_cwd(path_value: str | None, invocation_cwd: pathlib.Path) -> str:
    if not path_value:
        return ''
    path = pathlib.Path(path_value)
    if not path.is_absolute():
        path = invocation_cwd / path
    return str(path.resolve())


def resolve_invocation_paths(
    *,
    source: str,
    out: str,
    findings: str | None = None,
    public_records: str | None = None,
    invocation_cwd: pathlib.Path | None = None,
) -> dict:
    invocation_cwd = (invocation_cwd or pathlib.Path.cwd()).resolve()
    return {
        'invocation_cwd': str(invocation_cwd),
        'skill_root': str(ROOT.resolve()),
        'source_abs': _resolve_from_cwd(source, invocation_cwd),
        'out_abs': _resolve_from_cwd(out, invocation_cwd),
        'findings_abs': _resolve_from_cwd(findings, invocation_cwd),
        'public_records_abs': _resolve_from_cwd(public_records, invocation_cwd),
    }


def write_intake_templates(intake_dir: pathlib.Path, source_abs: str) -> None:
    if not (intake_dir / 'intake.json').exists():
        write_json(intake_dir / 'intake.template.json', {
            'authorization': 'REQUIRED: describe the explicit authorization for this audit',
            'scope_summary': 'REQUIRED: summarize package, commit/version, and in-scope components',
            'source_path': source_abs,
            'network_policy': 'restricted',
        })
    if not (intake_dir / 'scope.md').exists():
        (intake_dir / 'scope.template.md').write_text(
            '# Audit Scope\n\n'
            '- Authorization: REQUIRED\n'
            '- Source path: REQUIRED\n'
            '- In scope: REQUIRED\n'
            '- Out of scope: REQUIRED\n'
            '- Network policy: offline | restricted | online-approved\n'
        )


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


def _truthy_env_value(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    return None


def _choose_interactive_preset(input_fn: Callable[[str], str]) -> str:
    menu = (
        'PVAS workflow preset:\n'
        '  1) strict-efficient (default): strict tools, no degraded continuation, context efficient, strict packet budget\n'
        '  2) strict-degraded: strict tools with explicit degraded continuation, context efficient, strict packet budget\n'
        '  3) compat-default: legacy default/debug behavior\n'
        'Select preset [1]: '
    )
    answer = input_fn(menu).strip()
    return {'': 'strict-efficient', '1': 'strict-efficient', '2': 'strict-degraded', '3': 'compat-default'}.get(answer, 'strict-efficient')


def _normalize_cppcheck_mode(value: str | None, source: str) -> str:
    mode = (value or '').strip().lower()
    if mode not in CPPCHECK_MODES:
        raise ValueError(f'invalid cppcheck mode from {source}: {value!r}')
    return mode


def _choose_interactive_cppcheck_mode(input_fn: Callable[[str], str]) -> str:
    menu = (
        'PVAS cppcheck scan mode:\n'
        '  1) fast (default)\n'
        '  2) deep\n'
        'Select cppcheck mode [1]: '
    )
    answer = input_fn(menu).strip().lower()
    return {'': 'fast', '1': 'fast', 'fast': 'fast', '2': 'deep', 'deep': 'deep'}.get(answer, 'fast')


def resolve_cppcheck_mode(args, out_root: pathlib.Path, *, argv: list[str] | None = None,
                          environ: dict | None = None, input_fn: Callable[[str], str] = input,
                          stdin_is_tty: bool | None = None) -> CppcheckModeConfig:
    environ = os.environ if environ is None else environ
    cli_mode = getattr(args, 'cppcheck_mode', None)
    env_mode = environ.get('PVAS_CPPCHECK_MODE') or ''
    if cli_mode:
        return CppcheckModeConfig(_normalize_cppcheck_mode(cli_mode, 'cli'), 'cli-cppcheck-mode')
    if env_mode:
        return CppcheckModeConfig(_normalize_cppcheck_mode(env_mode, 'env'), 'env-cppcheck-mode')

    mode_file = out_root / CPPCHECK_MODE_PATH
    if getattr(args, 'resume', False) and mode_file.exists():
        previous = load_json(mode_file, default={}) or {}
        previous_mode = previous.get('mode')
        if previous_mode in CPPCHECK_MODES:
            return CppcheckModeConfig(previous_mode, 'resume-cppcheck-mode', previous_mode_source=previous.get('mode_source', ''))

    prompt_disabled = bool(getattr(args, 'no_startup_prompt', False)) or environ.get('PVAS_WORKFLOW_PROMPT') == '0'
    use_tty = sys.stdin.isatty() if stdin_is_tty is None else stdin_is_tty
    if use_tty and not prompt_disabled:
        return CppcheckModeConfig(_choose_interactive_cppcheck_mode(input_fn), 'interactive-tty')
    if getattr(args, 'no_startup_prompt', False):
        return CppcheckModeConfig('fast', 'cli-no-startup-prompt')
    if environ.get('PVAS_WORKFLOW_PROMPT') == '0':
        return CppcheckModeConfig('fast', 'env-no-startup-prompt')
    return CppcheckModeConfig('fast', 'default-noninteractive')


def resolve_startup_config(args, out_root: pathlib.Path, *, argv: list[str] | None = None,
                           environ: dict | None = None, input_fn: Callable[[str], str] = input,
                           stdin_is_tty: bool | None = None) -> StartupConfig:
    environ = os.environ if environ is None else environ
    startup_file = out_root / STARTUP_PATH
    cli_preset = args.workflow_preset
    env_preset = environ.get('PVAS_WORKFLOW_PRESET') or ''
    if env_preset and env_preset not in WORKFLOW_PRESETS:
        raise ValueError(f'invalid PVAS_WORKFLOW_PRESET {env_preset!r}')

    prompt_source = 'default-noninteractive'
    preset = cli_preset or env_preset or ''
    if not preset and args.resume and startup_file.exists():
        previous = load_json(startup_file, default={}) or {}
        previous_preset = previous.get('preset')
        if previous_preset in WORKFLOW_PRESETS:
            preset = previous_preset
            prompt_source = 'resume-workflow-startup'
    if not preset:
        prompt_disabled = bool(args.no_startup_prompt) or environ.get('PVAS_WORKFLOW_PROMPT') == '0'
        use_tty = sys.stdin.isatty() if stdin_is_tty is None else stdin_is_tty
        if use_tty and not prompt_disabled:
            preset = _choose_interactive_preset(input_fn)
            prompt_source = 'interactive-tty'
        else:
            preset = 'strict-efficient'
            if args.no_startup_prompt:
                prompt_source = 'cli-no-startup-prompt'
            elif environ.get('PVAS_WORKFLOW_PROMPT') == '0':
                prompt_source = 'env-no-startup-prompt'
    elif cli_preset:
        prompt_source = 'cli-workflow-preset'
    elif env_preset:
        prompt_source = 'env-workflow-preset'

    config = dict(WORKFLOW_PRESETS[preset])
    overrides = {}
    if args.mode is not None:
        config['mode'] = args.mode
        overrides['mode'] = {'source': 'cli', 'value': args.mode}
    elif environ.get('PVAS_TOOL_MODE'):
        config['mode'] = environ['PVAS_TOOL_MODE']
        overrides['mode'] = {'source': 'env', 'value': environ['PVAS_TOOL_MODE']}

    if args.allow_degraded is not None:
        config['allow_degraded'] = bool(args.allow_degraded)
        overrides['allow_degraded'] = {'source': 'cli', 'value': bool(args.allow_degraded)}
    else:
        env_allow = _truthy_env_value(environ.get('PVAS_ALLOW_DEGRADED'))
        if env_allow is not None:
            config['allow_degraded'] = env_allow
            overrides['allow_degraded'] = {'source': 'env', 'value': env_allow}

    env_context = _truthy_env_value(environ.get('PVAS_CONTEXT_EFFICIENT'))
    if env_context is not None:
        config['context_efficient'] = env_context
        overrides['context_efficient'] = {'source': 'env', 'value': env_context}
    env_packet = _truthy_env_value(environ.get('PVAS_PACKET_STRICT_BUDGET'))
    if env_packet is not None:
        config['packet_strict_budget'] = env_packet
        overrides['packet_strict_budget'] = {'source': 'env', 'value': env_packet}

    return StartupConfig(
        preset=preset,
        mode=config['mode'],
        allow_degraded=bool(config['allow_degraded']),
        context_efficient=bool(config['context_efficient']),
        packet_strict_budget=bool(config['packet_strict_budget']),
        prompt_source=prompt_source,
        overrides=overrides,
    )


def apply_startup_config(config: StartupConfig) -> None:
    os.environ['PVAS_TOOL_MODE'] = config.mode
    os.environ['PVAS_ALLOW_DEGRADED'] = '1' if config.allow_degraded else '0'
    os.environ['PVAS_CONTEXT_EFFICIENT'] = '1' if config.context_efficient else '0'
    os.environ['PVAS_PACKET_STRICT_BUDGET'] = '1' if config.packet_strict_budget else '0'


def apply_cppcheck_mode(config: CppcheckModeConfig) -> None:
    os.environ['PVAS_CPPCHECK_MODE'] = config.mode


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


def _reportable_findings(path: pathlib.Path) -> list[dict]:
    return [
        f for f in _findings(str(path))
        if isinstance(f, dict) and f.get('status') in {'Validated', 'Needs Manual Review'}
    ]


def _candidate_review_required(path: pathlib.Path, limit: int) -> bool:
    data = load_json(path, default={})
    cands = data.get('candidates', []) if isinstance(data, dict) else []
    return bool(cands[:limit])


def _has_scoreable_findings(findings: list[dict]) -> bool:
    return any((f.get('status') or f.get('state')) == 'Validated' for f in findings)


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
    ap.add_argument('--workflow-preset', choices=sorted(WORKFLOW_PRESETS))
    ap.add_argument('--no-startup-prompt', action='store_true',
                    help='Disable interactive startup preset selection')
    ap.add_argument('--mode', choices=['default', 'strict'])
    ap.add_argument('--cppcheck-mode', choices=sorted(CPPCHECK_MODES),
                    help='cppcheck scan depth: fast uses warning checks; deep adds style/performance/portability')
    ap.add_argument('--allow-degraded', action='store_true', default=None)
    ap.add_argument('--install-assist', action='store_true', default=env_flag('PVAS_INSTALL_ASSIST', default=True))
    ap.add_argument('--max-candidates', default=os.environ.get('PVAS_MAX_CANDIDATES', '20'))
    ap.add_argument('--findings', help='Validated findings JSON for final report gates')
    ap.add_argument('--public-records', help='Normalized public vuln records JSON')
    ap.add_argument('--allow-network', action='store_true', default=False, help='Allow fetching public vulnerability sources from network')
    ap.add_argument('--fetch-package', help='Package name for public vulnerability source fetching')
    ap.add_argument('--resume', action='store_true', help='Resume after an approved user confirmation decision')
    args = ap.parse_args()

    invocation = resolve_invocation_paths(
        source=args.source,
        out=args.out,
        findings=args.findings,
        public_records=args.public_records,
        invocation_cwd=pathlib.Path.cwd(),
    )
    args.source = invocation['source_abs']
    args.out = invocation['out_abs']
    args.findings = invocation['findings_abs'] or None
    args.public_records = invocation['public_records_abs'] or None

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / 'machine/invocation.json', invocation)
    initialize_sandbox_runtime(out)
    max_candidates = int(args.max_candidates)
    try:
        startup = resolve_startup_config(args, out, argv=sys.argv[1:])
        cppcheck_mode = resolve_cppcheck_mode(args, out, argv=sys.argv[1:])
    except ValueError as exc:
        print(f'[PVAS-STARTUP] {exc}', file=sys.stderr)
        return 2
    apply_startup_config(startup)
    apply_cppcheck_mode(cppcheck_mode)
    args.mode = startup.mode
    args.allow_degraded = startup.allow_degraded
    write_json(out / STARTUP_PATH, startup.as_dict())
    write_json(out / CPPCHECK_MODE_PATH, cppcheck_mode.as_dict())

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
        write_intake_templates(intake_dir, args.source)
        cmd = [sys.executable, 'tools/validate_intake.py', '--intake-dir', str(intake_dir), '--out', str(out / 'machine/intake-validation.json'), '--require-present']
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
                      lambda: require_paths([out / '01-profile/package-profile.json', out / '01-profile/cppcheck-scope.json', out / '01-profile/context-budget.json']),
                      out_root=out, outputs=[str(out / '01-profile/package-profile.json'), str(out / '01-profile/cppcheck-scope.json'), str(out / '01-profile/context-budget.json')])
    if not stage.ok:
        return 2

    def exec_scope():
        rc, tool_out = run([sys.executable, 'tools/select_scope.py', '--profile', str(out / '01-profile/package-profile.json'), '--source', args.source, '--out-dir', str(out / '01-profile')], allow_fail=True)
        if rc != 0:
            return StageResult(False, issues=[tool_out[-1000:] or 'scope selection failed'])
        matrix_path = out / '01-profile' / 'required-tools-matrix.json'
        cmd = [
            sys.executable,
            'tools/generate_tool_matrix.py',
            '--package-profile',
            str(out / '01-profile/package-profile.json'),
            '--profile',
            args.profile,
            '--network-policy',
            network_policy,
            '--cppcheck-mode',
            cppcheck_mode.mode,
            '--cppcheck-mode-source',
            cppcheck_mode.mode_source,
        ]
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
        run([sys.executable, 'tools/normalize_results.py', '--tools-dir', str(out / '02-tools/raw'), '--tool-summary', str(out / '02-tools/tool-summary.json'), '--out', str(out / '03-candidates/raw-candidates.json')])
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
        rc, tool_out = run([sys.executable, 'tools/exec_candidate_review_agent.py', '--ranked-candidates', str(out / '03-candidates/ranked-candidates.json'), '--packet-dir', str(out / '03-candidates/packets'), '--review-dir', str(out / '03-candidates/reviews'), '--summary-out', str(out / '03-candidates/candidate-summary.json'), '--hypotheses', str(out / '03-candidates/ai-hypotheses.json'), '--max-candidates', str(max_candidates)], allow_fail=True)
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

    finding_index_path = out / '05-findings' / 'finding-index.json'
    def exec_validation():
        validation_root = out / '04-validation'
        targets_path = validation_root / 'validation-targets.json'
        rc, tool_out = run([
            sys.executable, 'tools/build_validation_targets.py',
            '--ranked-candidates', str(out / '03-candidates/ranked-candidates.json'),
            '--candidate-summary', str(out / '03-candidates/candidate-summary.json'),
            '--review-dir', str(out / '03-candidates/reviews'),
            '--packet-dir', str(out / '03-candidates/packets'),
            '--out', str(targets_path),
        ], allow_fail=True)
        if rc != 0:
            return StageResult(False, issues=[tool_out[-1000:] or 'validation target generation failed'])

        validation_input = args.findings
        if validation_input:
            schema_rc = validate_finding_schema(validation_input, out, complete_audit=True)
            if schema_rc != 0:
                return StageResult(False, issues=['finding JSON failed schema validation'])

        findings_out = out / '04-validation' / 'updated-findings.json'
        val_cmd = [sys.executable, 'tools/exec_validation_agent.py',
                   '--packet-dir', str(out / '03-candidates/packets'),
                   '--source-root', args.source,
                   '--candidate-summary', str(out / '03-candidates/candidate-summary.json'),
                   '--out', str(validation_root),
                   '--findings-out', str(findings_out)]
        if validation_input:
            val_cmd.extend(['--findings', validation_input])
        else:
            val_cmd.extend(['--targets', str(targets_path)])
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
        poc_gen_rc, poc_gen_out = run([sys.executable, 'tools/generate_poc_testcase.py', '--findings', str(findings_out), '--generate-from-finding', '--out', str(poc_out)], allow_fail=True)
        if poc_gen_rc != 0:
            return StageResult(False, issues=[poc_gen_out[-1000:] or 'poc generation or execution failed'])
        poc_v_rc, _ = run([sys.executable, 'tools/validate_poc_artifacts.py', '--poc-root', str(poc_out)], allow_fail=True)
        if poc_v_rc != 0:
            return StageResult(False, issues=['poc validation failed'])
        rc, tool_out = run([
            sys.executable, 'tools/finalize_finding_index.py',
            '--validation-findings', str(findings_out),
            '--validation-targets', str(targets_path),
            '--candidate-summary-ref', str(out / '03-candidates/candidate-summary.json'),
            '--validation-summary-ref', str(out / '04-validation/validation-summary.json'),
            '--out', str(finding_index_path),
        ], allow_fail=True)
        if rc != 0:
            return StageResult(False, issues=[tool_out[-1000:] or 'finding index finalization failed'])
        write_json(out / '04-validation/validation-summary.json', {
            'status': 'completed',
            'reportable_findings': len(_reportable_findings(finding_index_path)),
        })
        return StageResult(True, outputs=[
            str(targets_path), str(findings_out), str(validation_result),
            str(manual_out), str(poc_out), str(out / '04-validation/validation-summary.json'),
            str(finding_index_path),
        ])
    stage = run_stage('06-validation', lambda: require_paths([out / '03-candidates/candidate-review-validation.json']) if _candidate_review_required(out / '03-candidates/ranked-candidates.json', max_candidates) else None,
                      exec_validation, lambda: require_paths([out / '04-validation/validation-summary.json']),
                      out_root=out, outputs=[str(out / '04-validation/validation-targets.json'), str(out / '04-validation/updated-findings.json'), str(out / '04-validation/manual-review'), str(out / '04-validation/poc-tests'), str(out / '04-validation/validation-summary.json'), str(finding_index_path)],
                      recovery_actions=['regenerate validation plans or PoC artifacts and rerun validators'])
    if not stage.ok:
        return 2

    def exec_cvss():
        findings = _findings(str(finding_index_path))
        if not _has_scoreable_findings(findings):
            write_json(out / '05-findings/cvss-summary.json', {'status': 'completed', 'scored_findings': 0, 'reason': 'no Validated findings'})
            return StageResult(True, outputs=[str(out / '05-findings/cvss-summary.json')])
        issues = validate_cvss31_findings(str(finding_index_path))
        if issues:
            return StageResult(False, issues=issues)
        write_json(out / '05-findings/cvss-summary.json', {'status': 'completed', 'scored_findings': len([f for f in findings if (f.get('status') or f.get('state')) == 'Validated'])})
        return StageResult(True, outputs=[str(out / '05-findings/cvss-summary.json')])
    stage = run_stage('07-cvss-scoring', lambda: require_paths([out / '04-validation/validation-summary.json']), exec_cvss,
                      lambda: require_paths([out / '05-findings/cvss-summary.json']), out_root=out,
                      outputs=[str(out / '05-findings/cvss-summary.json')], recovery_actions=['rerun CVSS calculator validation for scoreable findings'])
    if not stage.ok:
        return 2

    def exec_report():
        findings = _findings(str(finding_index_path))
        validated = [f for f in findings if f.get('status') == 'Validated']
        if not args.public_records and args.allow_network and args.fetch_package:
            fetch_out = out / 'machine' / 'correlation' / 'fetched-records'
            fetch_out.mkdir(parents=True, exist_ok=True)
            run([sys.executable, 'tools/fetch_public_vuln_sources.py', '--sources', 'NVD,OSV', '--package', args.fetch_package, '--out', str(fetch_out), '--allow-network'], allow_fail=True)
            args.public_records = str(fetch_out)
        corr = out / 'machine' / 'correlation' / 'public-vuln-correlation.json'
        if validated and not args.public_records:
            write_json(corr, {'correlations': [], 'status': 'unknown', 'reason': 'public records not configured'})
            return StageResult(False, issues=['Validated findings require configured public vulnerability correlation sources'])
        if args.public_records:
            freshness_cmd = [sys.executable, 'tools/check_offline_db_freshness.py', '--out', str(out / 'machine/correlation/offline-db-freshness.json')]
            if OPENEULER_MANIFEST.is_file():
                freshness_cmd.extend(['--extra-manifest', str(OPENEULER_MANIFEST)])
            run(freshness_cmd, allow_fail=True)
            norm_records = out / 'machine' / 'correlation' / 'normalized-public-records.json'
            run([sys.executable, 'tools/normalize_public_vuln_records.py', '--input', args.public_records, '--out', str(norm_records)], allow_fail=True)
            run([sys.executable, 'tools/correlate_public_vulns.py', '--findings', str(finding_index_path), '--records', str(norm_records), '--openeuler-index', str(OPENEULER_INDEX), '--out', str(corr)], allow_fail=False)
            run([sys.executable, 'tools/apply_correlation_to_findings.py', '--findings', str(finding_index_path), '--correlation', str(corr), '--out', str(finding_index_path)], allow_fail=False)
        elif not corr.exists():
            write_json(corr, {'correlations': [], 'status': 'not_applicable', 'reason': 'no Validated findings'})
        run([sys.executable, 'tools/publish_bilingual_reports.py', '--findings', str(finding_index_path), '--correlation', str(corr), '--poc-root', str(out / '04-validation/poc-tests'), '--out', str(out), '--skip-final-report'], allow_fail=False)
        run([sys.executable, 'tools/generate_final_report.py', '--audit-root', str(out), '--findings', str(finding_index_path), '--out', str(out / '06-report'), '--correlation', str(corr)], allow_fail=False)
        rc, _ = run([sys.executable, 'tools/validate_report_completeness.py', '--findings', str(finding_index_path), '--correlation', str(corr), '--report-root', str(out), '--manual-root', str(out / '04-validation/manual-review'), '--poc-root', str(out / '04-validation/poc-tests'), '--require-workflow-steps', '--out', str(out / 'machine/report-completeness.json')], allow_fail=True)
        if rc != 0:
            return StageResult(False, issues=['report completeness failed'])
        return StageResult(True, outputs=[str(out / '06-report/machine'), str(out / '06-report/zh-CN'), str(out / '06-report/en-US'), str(out / 'machine/report-completeness.json')])
    stage = run_stage('08-report', lambda: require_paths([out / '05-findings/cvss-summary.json']), exec_report,
                      lambda: require_paths([out / '06-report/machine', out / '06-report/zh-CN', out / '06-report/en-US', out / 'machine/report-completeness.json']),
                      out_root=out, outputs=[str(out / '06-report/machine'), str(out / '06-report/zh-CN'), str(out / '06-report/en-US'), str(out / 'machine/report-completeness.json')],
                      recovery_actions=['regenerate reports and rerun report completeness gate'])
    if not stage.ok:
        return 2

    def exec_disclosure():
        findings = _findings(str(finding_index_path))
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
        if f.get('status') != 'Validated':
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
