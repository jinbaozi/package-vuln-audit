#!/usr/bin/env python3
"""Smoke the enforced driver happy path with local mock tools."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def write_mock_tool(path: pathlib.Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


def test_enforced_driver_strict_efficient_minimal_happy_path():
    with tempfile.TemporaryDirectory(prefix='pvas-driver-smoke-') as td:
        base = pathlib.Path(td)
        source = base / 'src'
        audit = base / 'audit-output'
        home = base / 'home'
        bin_dir = home / '.pvas' / 'bin'
        source.mkdir()
        bin_dir.mkdir(parents=True)

        (source / 'main.c').write_text(
            'int add(int a, int b) { return a + b; }\n'
            'int main(void) { return add(1, 2) == 3 ? 0 : 1; }\n'
        )
        intake = audit / '00-intake'
        intake.mkdir(parents=True)
        (intake / 'scope.md').write_text(
            '# Audit Scope\n\n'
            '- Authorization: local test authorization for PVAS smoke coverage\n'
            '- Source path: local temporary fixture\n'
            '- In scope: src/main.c\n'
            '- Out of scope: network and external dependencies\n'
            '- Network policy: restricted\n'
        )
        (intake / 'intake.json').write_text(json.dumps({
            'authorization': 'local test authorization for PVAS smoke coverage',
            'scope_summary': 'Temporary C fixture used to smoke the enforced driver.',
            'source_path': str(source),
            'network_policy': 'restricted',
        }))

        write_mock_tool(bin_dir / 'rg', """#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "ripgrep 13.0.0"
  exit 0
fi
exit 0
""")
        write_mock_tool(bin_dir / 'semgrep', """#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "semgrep 1.0.0"
  exit 0
fi
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    out="$2"
    shift 2
    continue
  fi
  shift
done
if [[ -n "$out" ]]; then
  mkdir -p "$(dirname "$out")"
  printf '{"results":[],"errors":[],"paths":{"scanned":[]}}\\n' > "$out"
fi
exit 0
""")

        env = os.environ.copy()
        env.update({
            'HOME': str(home),
            'PATH': f"{bin_dir}:{env.get('PATH', '')}",
            'PVAS_SANDBOX': 'disabled',
            'PVAS_TERMINAL_SUMMARY_CHARS': '500',
        })
        result = subprocess.run([
            sys.executable,
            str(ROOT / 'tools' / 'enforced_audit_driver.py'),
            '--source', str(source),
            '--out', str(audit),
            '--profile', 'minimal',
            '--workflow-preset', 'strict-efficient',
            '--cppcheck-mode', 'fast',
            '--no-startup-prompt',
        ], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        assert result.returncode == 0, result.stdout[-4000:]
        expected_steps = [
            '00-intake',
            '00-environment',
            '01-package-profile',
            '02-scope-selection',
            '03-tool-scan',
            '04-ai-hypothesis',
            '05-candidate-review',
            '06-validation',
            '07-cvss-scoring',
            '08-report',
            '09-progressive-disclosure',
            '10-final-completeness',
        ]
        for step_id in expected_steps:
            step = json.loads((audit / 'machine' / 'workflow-steps' / f'{step_id}.json').read_text())
            assert step['status'] in {'completed', 'completed-with-recovery', 'not-applicable'}, step
            assert step['decision'] == 'continue', step

        completeness = json.loads((audit / 'machine' / 'report-completeness.json').read_text())
        assert completeness['status'] == 'passed', completeness
        assert (audit / '06-report' / 'machine' / 'final-report.json').is_file()
        assert (audit / '06-report' / 'zh-CN' / 'final-summary-report.md').is_file()
        assert (audit / '06-report' / 'en-US' / 'final-summary-report.md').is_file()
        assert not (audit / 'machine' / 'user-confirmations' / 'confirmation-required.json').exists()


if __name__ == '__main__':
    test_enforced_driver_strict_efficient_minimal_happy_path()
    print('enforced driver smoke test passed')
