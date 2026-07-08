#!/usr/bin/env python3
"""Reusable hardening layer for run_tool_matrix.py.

The original P0 safety fix introduced `run_tool_matrix_safe.py` as a wrapper.
This module makes the same behavior reusable by the canonical runner so the
workflow can call `run_tool_matrix.py` directly while preserving compatibility
for the old wrapper.
"""
from __future__ import annotations

import dataclasses
import os
import pathlib
import subprocess
import time
from types import SimpleNamespace
from typing import Any, Mapping

import pvas_container


def _truthy(value: str | None) -> bool:
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def allow_netpolicy_degraded() -> bool:
    return _truthy(os.environ.get('PVAS_ALLOW_NETPOLICY_DEGRADED'))


def semgrep_config_requires_network(command: list[str]) -> bool:
    for idx, part in enumerate(command):
        if part != '--config' or idx + 1 >= len(command):
            continue
        value = str(command[idx + 1])
        if value == 'auto' or value.startswith('p/'):
            return True
        if value.startswith('http://') or value.startswith('https://'):
            return True
    return False


def _runtime(runtime: Any | None = None) -> Any:
    if runtime is not None:
        return runtime
    import run_tool_matrix as rtm  # local import for test/compat use
    return rtm


def runtime_from_globals(glob: Mapping[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(**dict(glob))


def _semgrep_policy_row(runtime: Any, tool: dict, reason: str) -> tuple[dict, list[dict]]:
    status, reason, strict_decision = runtime.block_required_status(tool, 'incomplete', reason)
    row = {
        'name': tool.get('name', 'semgrep'),
        'status': status,
        'output': '',
        'reason': reason,
        'notes': 'Semgrep config requires network but current network policy does not approve remote rule sources.',
        'strict_decision': strict_decision,
        'coverage_impact': 'semgrep rule-based SAST coverage missing',
        'watchdog_events': [],
        'network_used': False,
        'result_count': 0,
        'output_bytes': 0,
        'raw_output_ref': '',
        'terminal_summary_truncated': False,
    }
    return row, [{
        'tool': tool.get('name', 'semgrep'),
        'attempt': 1,
        'status': status,
        'command': tool.get('command', []),
        'elapsed_ms': 0,
        'exit_code': None,
        'recovery_action': 'provide-local-semgrep-rules-or-authorize-network',
        'watchdog_events': [],
        'network_used': False,
    }]


def hard_timeout_for(tool: dict, soft_timeout: float, runtime: Any | None = None) -> float:
    runtime = _runtime(runtime)
    watchdog = tool.get('watchdog') or {}
    raw = watchdog.get('hard_timeout') or tool.get('hard_timeout')
    if raw:
        return runtime.parse_duration(raw, max(soft_timeout * 3.0, soft_timeout + 60.0))
    return max(soft_timeout * 3.0, soft_timeout + 60.0)


def hardened_run_with_watchdog(
    command: list[str],
    env: dict[str, str],
    output: pathlib.Path,
    tool: dict,
    runtime: Any | None = None,
) -> tuple[int | None, int, list[dict], str]:
    runtime = _runtime(runtime)
    soft_timeout = runtime.parse_duration(tool.get('timeout'), 600.0)
    hard_timeout = hard_timeout_for(tool, soft_timeout, runtime=runtime)
    watchdog_events: list[dict] = []
    start = time.monotonic()
    last_progress = start
    last_size = runtime.output_size(output)
    last_cpu = 0
    blocking = runtime.is_blocking_tool(tool)
    stalled = False

    merged_env = os.environ.copy()
    merged_env.update(env)
    for key in ('SEMGREP_SETTINGS_FILE', 'SEMGREP_LOG_FILE'):
        if key in merged_env:
            pathlib.Path(merged_env[key]).parent.mkdir(parents=True, exist_ok=True)

    try:
        with output.open('w') as fh:
            proc = subprocess.Popen(
                command,
                stdout=fh,
                stderr=subprocess.STDOUT,
                text=True,
                env=merged_env,
                start_new_session=True,
            )
            last_cpu = runtime.proc_cpu_ticks(proc.pid)
            while True:
                rc = proc.poll()
                now = time.monotonic()
                current_size = runtime.output_size(output)
                current_cpu = runtime.proc_cpu_ticks(proc.pid)
                elapsed_ms = int((now - start) * 1000)

                if current_size > last_size or current_cpu > last_cpu:
                    last_progress = now
                    last_size = current_size
                    last_cpu = current_cpu
                    watchdog_events.append({
                        'event': 'progress',
                        'elapsed_ms': elapsed_ms,
                        'output_bytes': current_size,
                    })

                if rc is not None:
                    return rc, elapsed_ms, watchdog_events, 'stalled' if stalled else 'exited'

                if now - start > hard_timeout:
                    runtime.terminate_process(proc)
                    watchdog_events.append({
                        'event': 'hard-limit',
                        'elapsed_ms': int((time.monotonic() - start) * 1000),
                        'output_bytes': current_size,
                        'diagnostic': 'tool exceeded hard timeout',
                    })
                    return None, int((time.monotonic() - start) * 1000), watchdog_events, 'hard-limit'

                if now - last_progress > soft_timeout:
                    if blocking and not stalled:
                        stalled = True
                        watchdog_events.append({
                            'event': 'stalled-diagnostic',
                            'elapsed_ms': elapsed_ms,
                            'output_bytes': current_size,
                            'diagnostic': 'required tool made no observed CPU/output progress; hard timeout still applies',
                        })
                        last_progress = now
                        time.sleep(0.1)
                        continue
                    if not blocking:
                        runtime.terminate_process(proc)
                        watchdog_events.append({'event': 'abnormal-timeout', 'elapsed_ms': elapsed_ms})
                        return None, int((time.monotonic() - start) * 1000), watchdog_events, 'abnormal-timeout'
                time.sleep(0.1)
    except OSError as e:
        watchdog_events.append({'event': 'spawn-failed', 'error': str(e)})
        return None, int((time.monotonic() - start) * 1000), watchdog_events, 'spawn-failed'


def make_hardened_run_with_watchdog(runtime: Any):
    def _run_with_watchdog(command: list[str], env: dict[str, str], output: pathlib.Path, tool: dict):
        return hardened_run_with_watchdog(command, env, output, tool, runtime=runtime)
    return _run_with_watchdog


def make_hardened_run_one(runtime: Any, original_run_one):
    def _run_one(tool: dict, source: pathlib.Path, raw: pathlib.Path, file_list=None):
        command = runtime.expand_command(tool.get('command', []), source, raw, file_list=file_list)
        if tool.get('name') == 'semgrep' and semgrep_config_requires_network(command):
            if tool.get('network_policy') != 'online-approved':
                return _semgrep_policy_row(runtime, tool, 'network-config-not-approved')
        return original_run_one(tool, source, raw, file_list=file_list)
    return _run_one


def make_hardened_run_one_container(runtime: Any, original_run_one_container):
    def _run_one_container(tool: dict, source: pathlib.Path, raw: pathlib.Path, result=None, file_list=None):
        command = runtime.expand_command(tool.get('command', []), source, raw, file_list=file_list)
        if tool.get('name') == 'semgrep' and semgrep_config_requires_network(command):
            if tool.get('network_policy') != 'online-approved':
                return _semgrep_policy_row(runtime, tool, 'network-config-not-approved')
        return original_run_one_container(tool, source, raw, result=result, file_list=file_list)
    return _run_one_container


def hardened_container_run(original_run):
    def _run(spec: pvas_container.ContainerSpec, backend=None) -> pvas_container.ContainerResult:
        pvas_container._validate_mem_limits(spec)
        if backend is None:
            backend = pvas_container.detect_backend()

        start = time.time()
        npid = None
        applied_policy = spec.network_policy
        executed_via = 'container'

        try:
            npid = pvas_container._apply_network_policy(spec)
        except pvas_container.NetworkPolicyApplyFailed as exc:
            if not allow_netpolicy_degraded():
                return pvas_container.ContainerResult(
                    exit_code=-1,
                    stdout='',
                    stderr=f'network-policy-apply-failed: {exc}',
                    duration_seconds=time.time() - start,
                    container_id='',
                    oom_killed=False,
                    timed_out=False,
                    netpolicy_id=None,
                    executed_via='container',
                )
            applied_policy = 'host'
            npid = 'degraded-no-netpolicy'
            executed_via = 'host-degraded-network-policy'

        actual_spec = spec
        if applied_policy != spec.network_policy:
            actual_spec = dataclasses.replace(spec, network_policy='host')

        args = pvas_container._build_docker_args(actual_spec, backend)
        try:
            exit_code, stdout, stderr, timed_out, cid = pvas_container._run_with_subprocess(args, spec)
        except pvas_container.SandboxUnavailable:
            raise
        finally:
            if npid and npid != 'degraded-no-netpolicy':
                pvas_container._remove_network_policy(npid)

        oom = pvas_container._detect_oom(stderr)
        return pvas_container.ContainerResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.time() - start,
            container_id=cid,
            oom_killed=oom,
            timed_out=timed_out,
            netpolicy_id=npid,
            executed_via=executed_via,
        )
    return _run


def apply_to_runtime(runtime: Any) -> None:
    if getattr(runtime, '_PVAS_TOOL_MATRIX_HARDENED', False):
        return
    runtime.run_with_watchdog = make_hardened_run_with_watchdog(runtime)
    runtime.run_one = make_hardened_run_one(runtime, runtime.run_one)
    runtime.run_one_container = make_hardened_run_one_container(runtime, runtime.run_one_container)
    pvas_container.run = hardened_container_run(pvas_container.run)
    setattr(runtime, '_PVAS_TOOL_MATRIX_HARDENED', True)


def apply_to_globals(glob: dict[str, Any]) -> None:
    if glob.get('_PVAS_TOOL_MATRIX_HARDENED'):
        return
    runtime = runtime_from_globals(glob)
    glob['run_with_watchdog'] = make_hardened_run_with_watchdog(runtime)
    glob['run_one'] = make_hardened_run_one(runtime, glob['run_one'])
    glob['run_one_container'] = make_hardened_run_one_container(runtime, glob['run_one_container'])
    pvas_container.run = hardened_container_run(pvas_container.run)
    glob['_PVAS_TOOL_MATRIX_HARDENED'] = True


def apply_to_imported_run_tool_matrix() -> None:
    import run_tool_matrix as rtm
    apply_to_runtime(rtm)
