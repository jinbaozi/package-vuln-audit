#!/usr/bin/env python3
"""Generate controlled installation plan for missing traditional tools."""
from __future__ import annotations
import argparse, json, pathlib, sys
from tool_catalog import CATALOG, INSTALL_HINTS, CONTROLLED_INSTALL_METHOD_ORDER

POLICY = {
    'auto_install_default': False,
    'default_dry_run': True,
    'preferred_methods': CONTROLLED_INSTALL_METHOD_ORDER,
    'forbidden_by_default': ['sudo-without-auth', 'system-package-manager-auto-execution', 'write-/usr', 'write-/usr/local/bin', 'curl-pipe-shell', 'overwrite-system-tools', 'unapproved-network-fetch', 'unauthenticated-sudo'],
    'requires_per_tool_authorization': True,
    'requires_system_install_authorization': True,
    'sudo_interactive_default': True,
    'network_default': 'offline',
    'prefix_default': '~/.pvas',
}

OFFLINE_LAYOUT = [
    'offline-bundle/wheels/',
    'offline-bundle/npm-cache/',
    'offline-bundle/binaries/',
    'offline-bundle/codeql/',
    'offline-bundle/vuln-db/',
    'offline-bundle/checksums/SHA256SUMS',
    'offline-bundle/install-manifest.json',
]


def load_missing(path: pathlib.Path) -> list[dict]:
    data = json.loads(path.read_text())
    rows = []
    if 'tools' in data:
        for r in data['tools']:
            if r.get('status') in {'missing', 'not-installed'}:
                name = r.get('name')
                if name:
                    rows.append(r)
    return rows


def plan_for(row: dict) -> dict:
    name = row['name']
    hint_id = row.get('install_hint_id') or CATALOG.get(name, {}).get('install_hint_id', name)
    return {
        'tool': name,
        'impact': row.get('impact') or CATALOG.get(name, {}).get('impact', 'Capability unavailable.'),
        'authorization_required': True,
        'version_constraint': row.get('version_constraint', ''),
        'recommended_methods': INSTALL_HINTS.get(hint_id, [
            {'priority': 0, 'method': 'offline-bundle', 'commands': [f'# Install {name} from an approved offline bundle after hash verification'], 'notes': 'No automated user-local recipe is defined.'},
            {'priority': 9, 'method': 'admin-rpm-dnf-plan', 'commands': [f'# Last-resort administrator plan only: install {name} from an approved RPM/DNF source'], 'notes': 'Do not execute system package manager by default.'}
        ])
    }


def render_markdown(plan: dict) -> str:
    lines = [
        '# Tool Installation Plan', '',
        'This plan is generated because one or more traditional analysis tools are missing.', '',
        '## Controlled Installation Policy', '',
        '- Default behavior: do not auto-install tools.',
        '- Default assist behavior: dry-run only.',
        '- Each tool requires separate authorization before execution.',
        '- Preferred order: offline-bundle, Python/pipx/uv, npm/npx, GitHub release download, user-local binaries, then administrator RPM/DNF plan.',
        '- Default network mode: offline. Network fetches require explicit authorization.',
        '- Default prefix: `~/.pvas`; prefix must pass realpath escape checks and expanduser resolution.',
        '- Avoid by default: sudo without authentication, system package managers, `/usr`, `/usr/local/bin`, `curl | sh`, and overwriting system tools.',
        '- RPM/DNF commands are last-resort plans. When `--authorize-system-install` and `--interactive-sudo` are set, the assistant prompts the user for sudo password via `sudo -v` before executing `sudo dnf install`.', '',
        '## Missing Tools', ''
    ]
    if not plan['plans']:
        lines.append('No missing tools were detected.')
    for p in plan['plans']:
        lines.append(f"### {p['tool']}")
        lines.append('')
        lines.append(f"Impact: {p['impact']}")
        lines.append('')
        lines.append(f"Authorization required: `{str(p.get('authorization_required', True)).lower()}`")
        if p.get('version_constraint'):
            lines.append(f"Version constraint: `{p['version_constraint']}`")
        lines.append('')
        for m in sorted(p['recommended_methods'], key=lambda x: x['priority']):
            lines.append(f"#### P{m['priority']} — {m['method']}")
            lines.append('')
            lines.append(m['notes'])
            lines.append('')
            lines.append('```bash')
            lines.extend(m['commands'])
            lines.append('```')
            lines.append('')
    lines.extend(['## Offline Bundle Layout', '', '```text', *OFFLINE_LAYOUT, '```', ''])
    return '\n'.join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--environment-check', help='Path to environment-check.json')
    ap.add_argument('--tool-summary', help='Path to tool-summary.json')
    ap.add_argument('--out', default='audit-output/00-environment')
    args = ap.parse_args()
    src = args.environment_check or args.tool_summary
    if not src:
        ap.error('provide --environment-check or --tool-summary')
    src_path = pathlib.Path(src)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    missing_rows = load_missing(src_path)
    plan = {
        'status': 'no-missing-tools' if not missing_rows else 'install-plan-generated',
        'install_policy': POLICY,
        'plans': [plan_for(r) for r in missing_rows],
        'offline_bundle': {'supported': True, 'hash_verification_required': True, 'layout': OFFLINE_LAYOUT},
    }
    json_path = out / 'tool-install-plan.json'
    md_path = out / 'tool-install-plan.md'
    json_path.write_text(json.dumps(plan, indent=2))
    md_path.write_text(render_markdown(plan))
    if missing_rows:
        print(f"[PVAS-INSTALL-PLAN] missing tools: {', '.join(r['name'] for r in missing_rows)}", file=sys.stderr)
        print(f"[PVAS-INSTALL-PLAN] wrote {md_path}", file=sys.stderr)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
