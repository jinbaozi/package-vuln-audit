#!/usr/bin/env python3
"""Controlled traditional-tool install assistant.

This helper is designed for subagent use. It emits only summary/decision files for the
parent agent and keeps raw logs inside an internal directory.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, platform, shutil, subprocess, sys, time
from tool_catalog import CATALOG

NETWORK_MODES = {"offline", "restricted", "online-approved"}
DECISION_DRY = "dry-run-only"


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def safe_prefix(prefix: pathlib.Path, allowed_root: pathlib.Path) -> tuple[bool, str]:
    try:
        rp = prefix.resolve(strict=False)
        ar = allowed_root.resolve(strict=False)
        rp.relative_to(ar)
        return True, str(rp)
    except Exception:
        return False, str(prefix)


def load_manifest(bundle: pathlib.Path) -> dict:
    p = bundle / 'install-manifest.json'
    if not p.exists():
        return {'present': False, 'hash_verified': False, 'tools': {}}
    try:
        data = json.loads(p.read_text())
    except Exception as exc:
        return {'present': True, 'hash_verified': False, 'error': f'cannot parse install-manifest.json: {exc}', 'tools': {}}
    return {'present': True, 'hash_verified': False, **data}


def verify_bundle_hashes(bundle: pathlib.Path, manifest: dict, tools: list[str]) -> tuple[bool, list[str], dict]:
    failures: list[str] = []
    details: dict = {}
    if not manifest.get('present'):
        return False, ['offline bundle manifest not found'], details
    manifest_tools = manifest.get('tools') or {}
    for tool in tools:
        item = manifest_tools.get(tool)
        if not item:
            failures.append(f'{tool}: no manifest entry')
            continue
        rel = item.get('path') or item.get('file') or f'binaries/{tool}'
        expected = item.get('sha256') or item.get('hash')
        if not expected:
            failures.append(f'{tool}: no sha256 in manifest')
            continue
        path = (bundle / rel).resolve(strict=False)
        try:
            path.relative_to(bundle.resolve(strict=False))
        except Exception:
            failures.append(f'{tool}: manifest path escapes offline bundle')
            continue
        if not path.exists():
            failures.append(f'{tool}: payload missing at {rel}')
            continue
        actual = sha256_file(path)
        ok = actual.lower() == expected.lower()
        details[tool] = {'path': rel, 'sha256': actual, 'expected_sha256': expected, 'verified': ok}
        if not ok:
            failures.append(f'{tool}: sha256 mismatch')
    return not failures, failures, details


def detect_environment() -> dict:
    return {
        'platform': platform.platform(),
        'machine': platform.machine(),
        'python': sys.version.split()[0],
        'glibc': '-'.join(platform.libc_ver()).strip('-'),
        'path_entries': len(os.environ.get('PATH', '').split(os.pathsep)),
        'has_pipx': bool(shutil.which('pipx')),
        'has_uv': bool(shutil.which('uv')),
        'has_npm': bool(shutil.which('npm')),
        'has_go': bool(shutil.which('go')),
        'has_dnf': bool(shutil.which('dnf')),
        'has_rpm': bool(shutil.which('rpm')),
    }


def verify_tool(tool: str, prefix: pathlib.Path) -> dict:
    binary = CATALOG.get(tool, {}).get('binary', tool)
    candidates = [prefix / 'bin' / binary, pathlib.Path(shutil.which(binary) or '')]
    for cand in candidates:
        if cand and str(cand) != '.' and cand.exists():
            try:
                args = CATALOG.get(tool, {}).get('version_args', ['--version'])
                p = subprocess.run([str(cand), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
                return {'tool': tool, 'status': 'installed', 'path': str(cand), 'version': (p.stdout or '').splitlines()[0][:200]}
            except Exception as exc:
                return {'tool': tool, 'status': 'failed', 'path': str(cand), 'error': str(exc)}
    return {'tool': tool, 'status': 'missing', 'path': ''}


def summarize_plan(tool: str, authorized: bool, system_install_authorized: bool, network_mode: str) -> dict:
    if tool not in CATALOG:
        return {'tool': tool, 'status': 'unknown-tool', 'authorized': authorized, 'planned_actions': []}
    actions = [
        'inspect environment',
        'validate prefix containment',
        'verify offline-bundle manifest/hash when present',
        'install only under user prefix after per-tool authorization',
        'verify tool version/smoke command',
    ]
    if network_mode == 'offline':
        actions.append('skip network-based installers')
    if not system_install_authorized:
        actions.append('emit RPM/DNF administrator plan only; do not execute')
    return {'tool': tool, 'status': 'planned', 'authorized': authorized, 'planned_actions': actions}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--tool', action='append', dest='tool_list', default=[])
    ap.add_argument('--tools', dest='tools_csv', help='comma-separated tool names')
    ap.add_argument('--mode', default=os.environ.get('PVAS_TOOL_MODE', 'default'), choices=['default','strict'])
    ap.add_argument('--dry-run', action='store_true', default=os.environ.get('PVAS_INSTALL_DRY_RUN', '1') in {'1','true','yes','on'})
    ap.add_argument('--execute', action='store_true', help='execute authorized user-prefix install actions; overrides dry-run')
    ap.add_argument('--mock-only', action='store_true', default=os.environ.get('PVAS_INSTALL_MOCK_ONLY', '0') in {'1','true','yes','on'})
    ap.add_argument('--network-mode', default=os.environ.get('PVAS_NETWORK_MODE', 'offline'), choices=sorted(NETWORK_MODES))
    ap.add_argument('--prefix', default=os.environ.get('PVAS_TOOL_PREFIX', '.pvas/tools'))
    ap.add_argument('--allowed-root', default=os.environ.get('PVAS_ALLOWED_PREFIX_ROOT', os.getcwd()))
    ap.add_argument('--offline-bundle', default=os.environ.get('PVAS_OFFLINE_BUNDLE', 'offline-bundle'))
    ap.add_argument('--authorize-tool', action='append', default=[], help='tool name approved for user-prefix installation')
    ap.add_argument('--authorize-all', action='store_true')
    ap.add_argument('--authorize-system-install', action='store_true', default=os.environ.get('PVAS_AUTHORIZE_SYSTEM_INSTALL', '0') in {'1','true','yes','on'})
    ap.add_argument('--out', default='audit-output/00-environment')
    args = ap.parse_args()

    tools = list(args.tool_list)
    if args.tools_csv:
        tools.extend([x.strip() for x in args.tools_csv.split(',') if x.strip()])
    tools = sorted(set(tools))
    if not tools:
        ap.error('provide --tool or --tools')

    out = pathlib.Path(args.out); out.mkdir(parents=True, exist_ok=True)
    raw = out / 'install-assistant-raw'; raw.mkdir(parents=True, exist_ok=True)
    log_file = raw / f'install-assistant-{int(time.time())}.log'
    allowed_root = pathlib.Path(args.allowed_root)
    prefix = pathlib.Path(args.prefix)
    prefix_ok, resolved_prefix = safe_prefix(prefix, allowed_root)
    prefix_path = pathlib.Path(resolved_prefix)
    bundle = pathlib.Path(args.offline_bundle)
    manifest = load_manifest(bundle)
    hash_ok, hash_failures, hash_details = verify_bundle_hashes(bundle, manifest, tools) if bundle.exists() else (False, ['offline bundle not present'], {})
    authorized_set = set(args.authorize_tool)
    env = detect_environment()

    failure_summary: list[str] = []
    if not prefix_ok:
        failure_summary.append('prefix escape check failed')
    if args.network_mode == 'offline' and not hash_ok:
        failure_summary.extend(hash_failures)

    tool_rows = []
    for tool in tools:
        authorized = args.authorize_all or tool in authorized_set
        row = summarize_plan(tool, authorized, args.authorize_system_install, args.network_mode)
        row['version_constraint'] = ''
        row['offline_bundle_hash'] = hash_details.get(tool, {})
        row['verification'] = verify_tool(tool, prefix_path)
        if (args.dry_run and not args.execute) or args.mock_only:
            row['execution'] = 'dry-run'
        elif not prefix_ok:
            row['execution'] = 'blocked-prefix-escape'
        elif not authorized:
            row['execution'] = 'blocked-per-tool-authorization-required'
            failure_summary.append(f'{tool}: per-tool authorization missing')
        elif args.network_mode == 'offline' and not hash_details.get(tool, {}).get('verified'):
            row['execution'] = 'blocked-offline-bundle-hash'
        else:
            detail = hash_details.get(tool, {})
            if detail.get('verified') and detail.get('path'):
                src = (bundle / detail['path']).resolve(strict=False)
                dest_dir = prefix_path / 'bin'
                dest_dir.mkdir(parents=True, exist_ok=True)
                binary = CATALOG.get(tool, {}).get('binary', tool)
                dest = dest_dir / binary
                shutil.copy2(src, dest)
                dest.chmod(0o755)
                row['execution'] = 'installed-from-offline-bundle-user-prefix'
                row['verification'] = verify_tool(tool, prefix_path)
            else:
                row['execution'] = 'blocked-no-verified-offline-payload'
                failure_summary.append(f'{tool}: no verified offline payload for user-prefix install')
        tool_rows.append(row)

    installed_after = [r['tool'] for r in tool_rows if r.get('verification', {}).get('status') == 'installed']
    missing_after = [r['tool'] for r in tool_rows if r.get('verification', {}).get('status') != 'installed']
    if (args.dry_run and not args.execute) or args.mock_only:
        status = 'planned'
        decision = DECISION_DRY
        resume = False
    elif failure_summary or missing_after:
        status = 'blocked'
        decision = 'blocked'
        resume = False
    else:
        status = 'completed'
        decision = 'resume'
        resume = True

    summary = {
        'status': status,
        'mode': args.mode,
        'dry_run': bool((args.dry_run and not args.execute) or args.mock_only),
        'mock_only': bool(args.mock_only),
        'network_mode': args.network_mode,
        'prefix': resolved_prefix,
        'prefix_escape_check': 'passed' if prefix_ok else 'failed',
        'system_install_authorized': bool(args.authorize_system_install),
        'environment': env,
        'offline_bundle': {
            'path': str(bundle),
            'present': bundle.exists(),
            'manifest_present': bool(manifest.get('present')),
            'hash_verified': hash_ok,
            'hash_failures': hash_failures,
        },
        'tools': tool_rows,
        'installed_after_assist': installed_after,
        'missing_after_assist': missing_after,
        'failure_summary': sorted(set(failure_summary)),
    }
    summary_path = out / 'install-assistant-summary.json'
    decision_obj = {
        'decision': decision,
        'resume_audit': resume,
        'missing_after_assist': missing_after,
        'summary_file': str(summary_path),
        'log_digest_file': str(out / 'install-assistant-log-digest.txt'),
        'next_actions': [] if resume else ['install missing required tools using an approved path', 'or rerun strict mode with explicit --allow-degraded'],
    }
    decision_path = out / 'install-assistant-decision.json'
    summary_path.write_text(json.dumps(summary, indent=2))
    decision_path.write_text(json.dumps(decision_obj, indent=2))
    log_file.write_text(json.dumps({'summary': summary, 'decision': decision_obj}, indent=2))
    digest_lines = [
        f"status={status}", f"decision={decision}", f"tools={','.join(tools)}",
        f"prefix_escape_check={'passed' if prefix_ok else 'failed'}",
        f"offline_bundle_hash_verified={hash_ok}",
    ]
    if failure_summary:
        digest_lines.append('failures=' + '; '.join(sorted(set(failure_summary))))
    (out / 'install-assistant-log-digest.txt').write_text('\n'.join(digest_lines) + '\n')
    print(f'[PVAS-INSTALL-ASSIST] decision={decision}; wrote {summary_path} and {decision_path}')
    return 0 if decision in {'resume', DECISION_DRY} else 2

if __name__ == '__main__':
    raise SystemExit(main())
