#!/usr/bin/env bash
set -euo pipefail
python3 -u tests/test_schemas.py
python3 -u tests/test_context_budget_per_agent.py
python3 -u tests/test_rank_candidates.py
python3 -u tests/test_tool_install_plan.py
python3 -u tests/test_strict_mode.py
python3 -u tests/test_tool_matrix.py
python3 -u tests/test_tool_execution_gates.py
python3 -u tests/test_driver_workflow_gates.py
python3 -u tests/test_install_assistant.py
python3 -u tests/test_report_completeness_enforced.py
python3 -u tests/test_final_summary_gates.py
python3 -u tests/test_report_admission.py
python3 -u tests/test_make_ai_packets.py
python3 -u tests/test_bilingual_output.py
python3 -u tests/test_poc_safety_policy.py
python3 -u tests/test_poc_testcase_generation.py
python3 -u tests/test_poc_execution_result.py
python3 -u tests/test_manual_validation_plan.py
python3 -u tests/test_public_vuln_correlation.py
if [[ "${PVAS_RUN_INTEGRATION:-0}" == "1" ]]; then
  timeout 60s python3 -u tests/test_binutils_helpers.py
  timeout 60s python3 -u tests/test_e2e_toy_project.py
  timeout 60s python3 -u tests/test_install_scripts.py
fi
for shf in tools/*.sh; do bash -n "$shf"; done
python3 -m py_compile tools/*.py
python3 - <<'PYJSON'
import json, pathlib
for pattern in ['schemas/*.json','adapters/opencode/opencode.json','skill.json','examples/binutils/*.json']:
    for f in pathlib.Path('.').glob(pattern):
        json.loads(f.read_text())
print('json validation passed')
PYJSON
python3 - <<'PYCHECK'
import pathlib, sys
required = ['adapters/claude-code/INSTALL.md', 'adapters/codex/INSTALL.md', 'adapters/opencode/INSTALL.md', 'examples/binutils/package-profile.example.json', 'examples/binutils/candidate.example.md', 'examples/binutils/hypothesis.example.json', 'examples/binutils/validation-result.example.md', 'examples/binutils/finding.example.md', 'examples/generic/internal-report.example.md', 'examples/binutils/run-binutils-audit.sh', 'examples/binutils/README.md', 'references/binutils-validation.md', 'references/context-budget-policy.md', 'references/tool-installation-policy.md', 'templates/tool-install-plan.md', 'docs/runbooks/tool-availability-advisor.md', 'docs/runbooks/binutils-real-source.md', 'docs/runbooks/install-and-migration.md', 'docs/runbooks/context-budget-guard.md', 'install/install.sh', 'install/verify-install.sh', 'RELEASE-NOTES-0.6.0-alpha6.md', 'RELEASE-NOTES-0.7.0-alpha7.md', 'RELEASE-NOTES-0.8.0-alpha8.md', 'schemas/bilingual-output.schema.json', 'schemas/public-vuln-record.schema.json', 'schemas/public-vuln-correlation.schema.json', 'schemas/poc-testcase.schema.json', 'references/bilingual-output-policy.md', 'references/public-vulnerability-correlation-policy.md', 'references/poc-reproducer-policy.md', 'docs/runbooks/bilingual-output.md', 'docs/runbooks/public-vulnerability-correlation.md', 'docs/runbooks/validated-poc-testcases.md', 'templates/zh-CN/finding.md', 'templates/en-US/finding.md', 'offline-bundle/vuln-db/manifest.example.json', 'RELEASE-NOTES-0.9.0-alpha9.md', 'CHANGELOG.md', 'LICENSE']
missing=[f for f in required if not pathlib.Path(f).is_file()]
if missing:
    print('missing required files:', missing, file=sys.stderr)
    sys.exit(1)
print('required file check passed')
PYCHECK
echo "alpha10 unit checks passed"
