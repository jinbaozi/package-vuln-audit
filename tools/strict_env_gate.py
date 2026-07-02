#!/usr/bin/env python3
"""Strict-mode environment gate: verify, install plan, install assistant."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS_DIR.parent

from pvas_env import env_flag
from pvas_io import load_json, resolve_output_path


def run_strict_assist(env_out: pathlib.Path, *, dry_run: bool = False) -> int:
    """Run install plan + assistant when strict mode blocks on missing tools."""
    check_path = env_out / 'environment-check.json'
    if not check_path.exists():
        return 2
    env = load_json(check_path, required=True)
    missing = ','.join(env.get('blocking_missing_tools') or env.get('missing_tools') or [])
    subprocess.run(
        [sys.executable, str(TOOLS_DIR / 'generate_install_plan.py'),
         '--environment-check', str(check_path), '--out', str(env_out)],
        cwd=ROOT, check=False,
    )
    assist_cmd = [
        sys.executable, str(TOOLS_DIR / 'install_assistant.py'),
        '--tools', missing, '--mode', 'strict', '--out', str(env_out),
    ]
    if dry_run or env_flag('PVAS_INSTALL_DRY_RUN'):
        assist_cmd.append('--dry-run')
    subprocess.run(assist_cmd, cwd=ROOT, check=False)
    print(
        f'[PVAS-STRICT-BLOCK] audit paused after controlled install-assistant. '
        f'Review {env_out / "install-assistant-decision.json"} '
        f'or rerun with PVAS_ALLOW_DEGRADED=1.',
        file=sys.stderr,
    )
    return 2


def verify_and_gate(
    env_out: pathlib.Path,
    *,
    profile: str,
    mode: str,
    allow_degraded: bool,
    install_assist: bool,
) -> int:
    """Run verify_environment; on strict block optionally run install assistant."""
    cmd = [
        sys.executable, str(TOOLS_DIR / 'verify_environment.py'),
        '--profile', profile, '--mode', mode, '--out', str(env_out),
    ]
    if allow_degraded:
        cmd.append('--allow-degraded')
    rc = subprocess.run(cmd, cwd=ROOT).returncode
    if rc == 0:
        return 0
    if mode == 'strict' and install_assist:
        return run_strict_assist(env_out, dry_run=env_flag('PVAS_INSTALL_DRY_RUN'))
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description='PVAS strict environment gate')
    ap.add_argument('--out', default='audit-output/00-environment')
    ap.add_argument('--profile', default=os.environ.get('PVAS_ENV_PROFILE', 'standard'))
    ap.add_argument('--mode', default=os.environ.get('PVAS_TOOL_MODE', 'strict'))
    ap.add_argument('--allow-degraded', action='store_true',
                    default=env_flag('PVAS_ALLOW_DEGRADED'))
    ap.add_argument('--install-assist', action='store_true',
                    default=env_flag('PVAS_INSTALL_ASSIST', True))
    ap.add_argument('--assist-only', action='store_true',
                    help='Skip verify; only run install assistant from existing check')
    args = ap.parse_args()
    env_out = resolve_output_path(args.out, is_dir=True)
    if args.assist_only:
        return run_strict_assist(env_out, dry_run=env_flag('PVAS_INSTALL_DRY_RUN'))
    return verify_and_gate(
        env_out,
        profile=args.profile,
        mode=args.mode,
        allow_degraded=args.allow_degraded,
        install_assist=args.install_assist,
    )


if __name__ == '__main__':
    raise SystemExit(main())
