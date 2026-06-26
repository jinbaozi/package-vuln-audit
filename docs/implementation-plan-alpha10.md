# alpha10 Implementation Plan: Strict Mode, Controlled Install Assist, Workflow Enforcement

## Scope

This patch adds two enforcement layers:

1. Explicit strict mode for traditional tool availability.
2. Workflow Enforcement & Report Completeness gates to prevent documented-but-not-executed behavior.

## Design Decisions

- Default mode remains degraded-but-continuing.
- Strict mode blocks when strict-required traditional tools are missing.
- Strict blocking automatically enters a controlled install-assistant flow.
- Install assistant defaults to dry-run and mock-only safe behavior.
- Installation preference order is: offline-bundle, Python/pipx/uv, npm/npx, user-local binary/distribution, administrator RPM/DNF plan.
- RPM/DNF is never executed automatically and requires separate system-install authorization.
- Parent agents read only install summary, decision, and digest files.
- Every workflow step can emit machine, zh-CN, and en-US conclusion files.
- Every Validated Finding must have a public vulnerability correlation record before final report publication.
- Final bilingual reports must contain public disclosure status and standard source summary tables.

## Modified Files

- `tools/tool_catalog.py`
- `tools/verify_environment.py`
- `tools/generate_install_plan.py`
- `tools/run_tools.sh`
- `tools/publish_bilingual_reports.py`
- `schemas/environment-check.schema.json`
- `schemas/tool-install-plan.schema.json`
- `schemas/report.schema.json`
- `SKILL.md`
- `AGENTS.md`
- `adapters/claude-code/commands/package-vuln-audit.md`
- `adapters/opencode/commands/package-vuln-audit.md`
- `run-tests.sh`

## Added Files

- `agents/tool-install-assistant.md`
- `adapters/claude-code/agents/tool-install-assistant.md`
- `adapters/opencode/agents/tool-install-assistant.md`
- `tools/install_assistant.py`
- `tools/enforce_workflow_contract.py`
- `tools/enforced_audit_driver.py`
- `tools/check_offline_db_freshness.py`
- `tools/validate_report_completeness.py`
- `schemas/install-assistant-summary.schema.json`
- `schemas/install-assistant-decision.schema.json`
- `tests/test_strict_mode.py`
- `tests/test_install_assistant.py`
- `tests/test_report_completeness_enforced.py`
- `tests/fixtures/sample-install-assistant-summary.json`
- `tests/fixtures/sample-install-assistant-decision.json`

## Verification

Run:

```bash
./run-tests.sh
python3 tools/enforce_workflow_contract.py --root . --out audit-output/machine/workflow-contract.json
```

Expected:

```text
alpha10 unit checks passed
workflow contract status: passed
```

## Strict Mode Examples

Default degraded mode:

```bash
python3 tools/verify_environment.py --profile standard --mode default --out audit-output/00-environment
```

Strict mode gate:

```bash
python3 tools/verify_environment.py --profile standard --mode strict --out audit-output/00-environment
```

Strict mode with explicit degraded execution:

```bash
python3 tools/verify_environment.py --profile standard --mode strict --allow-degraded --out audit-output/00-environment
```

Controlled install assist dry-run:

```bash
python3 tools/install_assistant.py --tools semgrep,osv-scanner --mode strict --dry-run --network-mode offline --prefix .pvas/tools --out audit-output/00-environment
```

Unified enforced driver:

```bash
python3 tools/enforced_audit_driver.py --source . --profile standard --mode strict --out audit-output
```
