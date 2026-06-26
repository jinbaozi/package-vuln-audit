# Release Notes 0.10.0-alpha10

## Added

- Explicit strict mode for traditional tool availability.
- Controlled `tool-install-assistant` subagent and helper script.
- Per-tool authorization, dry-run default, prefix escape guard, offline-bundle hash verification, network mode, system-install authorization, and mock-only tests.
- Unified `enforced_audit_driver.py`.
- Workflow contract checker for workflows, tools, schemas, templates, agents, and adapter commands.
- Post-packet Context Budget Guard enforcement in the driver.
- Offline public vulnerability database freshness checker.
- Final report completeness validator.
- Public disclosure status summary tables in zh-CN and en-US reports.

## Changed

- `verify_environment.py` now supports `--mode strict`, `--allow-degraded`, and strict required tool profiles.
- `generate_install_plan.py` now prioritizes offline-bundle/user-local paths and treats RPM/DNF as administrator-only last resort.
- `run_tools.sh` now performs an environment gate before tool execution.
- `publish_bilingual_reports.py` now emits non-skeleton internal reports with disclosure status tables.

## Verification

- `./run-tests.sh` passes.
- `python3 tools/enforce_workflow_contract.py --root .` passes with warnings only.
