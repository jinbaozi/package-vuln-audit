#!/usr/bin/env python3
"""Check traditional tool availability and enforce default/strict execution gates."""
from __future__ import annotations
import argparse, json, os, pathlib, shutil, subprocess, sys
from tool_catalog import CATALOG, COMMON_BIN_DIRS, PROFILE_TOOLS, STRICT_REQUIRED_TOOLS

STRICT_MODES = {"default", "strict"}


def version_for(binary: str, args: list[str]) -> str:
    try:
        p = subprocess.run([binary, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
        return (p.stdout or '').splitlines()[0][:200]
    except Exception:
        return ''


def parse_required_tools(value: str | None, profile: str) -> set[str]:
    if value:
        return {x.strip() for x in value.split(',') if x.strip()}
    return set(STRICT_REQUIRED_TOOLS.get(profile, []))


def check_tool(name: str, strict_required: set[str]) -> dict:
    meta = CATALOG[name]
    binary = meta['binary']
    path = shutil.which(binary)
    if not path:
        for d in COMMON_BIN_DIRS:
            candidate = pathlib.Path(d).expanduser() / binary
            if candidate.exists() and os.access(candidate, os.X_OK):
                path = str(candidate)
                break
    if path:
        status = 'installed'
        version = version_for(path, meta.get('version_args', ['--version']))
    else:
        status = 'missing'
        version = ''
    level = 'required' if name in strict_required else meta['level']
    return {
        'name': name,
        'binary': binary,
        'status': status,
        'version': version,
        'path': path or '',
        'required_for': meta['required_for'],
        'requirement_level': level,
        'impact': meta['impact'],
        'install_hint_id': meta['install_hint_id'],
    }


def capability_summary(rows: list[dict]) -> dict:
    caps = {}
    for r in rows:
        val = 'available' if r['status'] == 'installed' else 'missing'
        for cap in r['required_for']:
            old = caps.get(cap)
            if old == 'available':
                continue
            caps[cap] = val
    return caps


def decision_for(mode: str, missing: list[str], blocking_missing: list[str], allow_degraded: bool) -> tuple[str, str]:
    if not missing:
        return 'ok', 'continue'
    if mode == 'strict' and blocking_missing and not allow_degraded:
        return 'missing-required', 'block'
    return ('missing-required' if blocking_missing else 'degraded'), 'continue-degraded'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', default=os.environ.get('PVAS_ENV_PROFILE', 'standard'), choices=sorted(PROFILE_TOOLS))
    ap.add_argument('--mode', default=os.environ.get('PVAS_TOOL_MODE', 'default'), choices=sorted(STRICT_MODES))
    ap.add_argument('--required-tools', default=os.environ.get('PVAS_REQUIRED_TOOLS', ''))
    ap.add_argument('--allow-degraded', action='store_true', default=os.environ.get('PVAS_ALLOW_DEGRADED', '0') in {'1','true','yes','on'})
    ap.add_argument('--out', default='audit-output/00-environment')
    ap.add_argument('--json-only', action='store_true')
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    strict_required = parse_required_tools(args.required_tools, args.profile) if args.mode == 'strict' else set()
    names = PROFILE_TOOLS[args.profile]
    # Permit --required-tools to pull explicitly required tools into the scan set.
    for extra in sorted(strict_required):
        if extra not in CATALOG:
            ap.error(f'unknown required tool: {extra}')
        if extra not in names:
            names = [*names, extra]
    rows = [check_tool(n, strict_required) for n in names]
    missing = [r['name'] for r in rows if r['status'] == 'missing']
    blocking_missing = [r['name'] for r in rows if r['status'] == 'missing' and r['requirement_level'] == 'required']
    status, decision = decision_for(args.mode, missing, blocking_missing, args.allow_degraded)
    recommended = []
    for r in rows:
        if r['status'] == 'missing':
            action = 'Install or explicitly degrade' if r['name'] in blocking_missing else 'Install to restore coverage'
            recommended.append(f"{action}: {r['name']} enables {', '.join(r['required_for'])}. Impact: {r['impact']}")

    result = {
        'environment_profile': args.profile,
        'mode': args.mode,
        'allow_degraded': bool(args.allow_degraded),
        'status': status,
        'decision': decision,
        'tools': rows,
        'capability_summary': capability_summary(rows),
        'missing_tools': missing,
        'strict_required_tools': sorted(strict_required),
        'blocking_missing_tools': blocking_missing,
        'recommended_action': recommended,
        'install_assistant_recommended': decision == 'block',
        'degraded_capabilities': [cap for cap, st in capability_summary(rows).items() if st != 'available'],
        'output_files': [],
    }
    check_path = out / 'environment-check.json'
    result['output_files'].append(str(check_path))
    check_path.write_text(json.dumps(result, indent=2))

    if not args.json_only:
        if decision == 'block':
            print(f"[PVAS-STRICT-BLOCK] profile '{args.profile}' missing required tools: {', '.join(blocking_missing)}", file=sys.stderr)
            print('[PVAS-STRICT-BLOCK] run controlled install-assistant, install tools, or rerun with --allow-degraded / PVAS_ALLOW_DEGRADED=1.', file=sys.stderr)
        elif missing:
            print(f"[PVAS-ENV] environment profile '{args.profile}' is {status}; decision={decision}; missing tools: {', '.join(missing)}", file=sys.stderr)
        else:
            print(f"[PVAS-ENV] environment profile '{args.profile}' ok; decision=continue; wrote {check_path}", file=sys.stderr)
        if missing:
            for r in rows:
                if r['status'] == 'missing':
                    print(f"[PVAS-TOOL-MISSING] {r['name']} not installed. Impact: {r['impact']}", file=sys.stderr)
            print(f"[PVAS-ENV] wrote {check_path}", file=sys.stderr)
    return 2 if decision == 'block' else 0

if __name__ == '__main__':
    raise SystemExit(main())
