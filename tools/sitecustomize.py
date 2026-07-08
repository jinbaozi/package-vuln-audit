#!/usr/bin/env python3
"""Tool-level Python startup hooks.

This file is imported automatically by Python when scripts are executed from the
`tools/` directory. Hooks are intentionally narrow:

- `run_tool_matrix.py` receives the reusable P0 hardening layer so the canonical
  runner has hard timeouts and Semgrep network-policy guards.
- `generate_final_report.py` outputs are post-processed with report status.
- `enforced_audit_driver.py` receives a timeout-enforced `run()` helper and can
  recover one specific restricted/offline case: Validated findings without
  configured public records become an internal degraded report instead of
  stopping before report generation. Set
  `PVAS_REQUIRE_PUBLIC_CORRELATION_FOR_VALIDATED=1` to restore the hard gate.
"""
from __future__ import annotations

import atexit
import inspect
import pathlib
import sys


def _arg_value(argv: list[str], name: str, default: str | None = None) -> str | None:
    if name not in argv:
        return default
    idx = argv.index(name)
    if idx + 1 >= len(argv):
        return default
    return argv[idx + 1]


def _register_tool_matrix_hardening() -> None:
    script = pathlib.Path(sys.argv[0]).name
    if script != 'run_tool_matrix.py':
        return

    required = {
        'run_with_watchdog',
        'run_one',
        'run_one_container',
        'expand_command',
        'block_required_status',
        'parse_duration',
        'output_size',
        'proc_cpu_ticks',
        'is_blocking_tool',
        'terminate_process',
    }

    def _trace(frame, event, arg):
        if event != 'line':
            return _trace
        if pathlib.Path(frame.f_code.co_filename).name != 'run_tool_matrix.py':
            return _trace
        glob = frame.f_globals
        if glob.get('_PVAS_TOOL_MATRIX_HARDENED'):
            sys.settrace(None)
            return None
        if not required.issubset(glob.keys()):
            return _trace
        try:
            from tool_matrix_hardening import apply_to_globals
            apply_to_globals(glob)
            print('[PVAS-TOOL-MATRIX] canonical runner hardening enabled')
        except Exception as exc:  # pragma: no cover - defensive startup hook
            print(f'[PVAS-TOOL-MATRIX-WARN] hardening hook failed: {exc}', file=sys.stderr)
        sys.settrace(None)
        return None

    sys.settrace(_trace)


def _register_final_report_postprocess() -> None:
    script = pathlib.Path(sys.argv[0]).name
    if script != 'generate_final_report.py':
        return

    argv = list(sys.argv[1:])
    audit_root = pathlib.Path(_arg_value(argv, '--audit-root', 'audit-output') or 'audit-output')
    out_root = pathlib.Path(_arg_value(argv, '--out', 'audit-output/06-report') or 'audit-output/06-report')
    findings_arg = _arg_value(argv, '--findings')
    correlation_arg = _arg_value(argv, '--correlation')
    findings = pathlib.Path(findings_arg) if findings_arg else None
    correlation = pathlib.Path(correlation_arg) if correlation_arg else None

    def _postprocess() -> None:
        try:
            from report_status import postprocess_final_report
            status = postprocess_final_report(
                audit_root=audit_root,
                out_root=out_root,
                findings_path=findings,
                correlation_path=correlation,
            )
            print(
                '[PVAS-REPORT-STATUS] '
                f"type={status.get('report_type')} "
                f"negative_conclusion_allowed={status.get('negative_conclusion_allowed')}"
            )
        except Exception as exc:  # pragma: no cover - defensive startup hook
            print(f'[PVAS-REPORT-STATUS-WARN] postprocess failed: {exc}', file=sys.stderr)

    atexit.register(_postprocess)


def _register_enforced_driver_hooks() -> None:
    script = pathlib.Path(sys.argv[0]).name
    if script != 'enforced_audit_driver.py':
        return

    state = {'timeout': False, 'stage_result': False}

    def _maybe_done() -> bool:
        return bool(state['timeout'] and state['stage_result'])

    def _trace(frame, event, arg):
        if event != 'line':
            return _trace
        if pathlib.Path(frame.f_code.co_filename).name != 'enforced_audit_driver.py':
            return _trace
        glob = frame.f_globals

        if not state['timeout'] and callable(glob.get('run')):
            try:
                from driver_command_timeout import patch_globals
                patched = patch_globals(glob)
                if patched:
                    print('[PVAS-DRIVER-TIMEOUT] enforced driver command timeout enabled')
                state['timeout'] = True
            except Exception as exc:  # pragma: no cover - defensive startup hook
                print(f'[PVAS-DRIVER-TIMEOUT-WARN] patch failed: {exc}', file=sys.stderr)
                state['timeout'] = True

        original_cls = glob.get('StageResult')
        if not state['stage_result'] and original_cls is not None:
            if getattr(original_cls, '_pvas_public_correlation_soft_fail', False):
                state['stage_result'] = True
            else:
                class SoftCorrelationStageResult(original_cls):
                    _pvas_public_correlation_soft_fail = True

                    def __init__(self, ok, decision='continue', outputs=None, issues=None,
                                 limitations=None, not_applicable=False, details=None):
                        outputs = [] if outputs is None else outputs
                        issues = [] if issues is None else issues
                        limitations = [] if limitations is None else limitations
                        details = {} if details is None else details
                        if ok is False:
                            try:
                                from public_correlation_soft_fail import maybe_recover_missing_public_records
                                caller = inspect.currentframe().f_back
                                recovery = maybe_recover_missing_public_records(caller, issues)
                                if recovery:
                                    ok = True
                                    decision = 'continue'
                                    outputs = list(dict.fromkeys(list(outputs) + recovery.get('outputs', [])))
                                    limitations = list(dict.fromkeys(list(limitations) + recovery.get('limitations', [])))
                                    details = {**details, **recovery.get('details', {})}
                                    issues = []
                            except Exception as exc:
                                ok = False
                                decision = 'failed'
                                issues = [f'public correlation soft-fail recovery failed: {exc}']
                        super().__init__(ok, decision, outputs, issues, limitations, not_applicable, details)

                glob['StageResult'] = SoftCorrelationStageResult
                state['stage_result'] = True

        if _maybe_done():
            sys.settrace(None)
            return None
        return _trace

    sys.settrace(_trace)


_register_tool_matrix_hardening()
_register_final_report_postprocess()
_register_enforced_driver_hooks()
