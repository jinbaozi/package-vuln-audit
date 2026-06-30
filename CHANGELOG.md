# Changelog

## 0.10.0-alpha11 — Balanced simplification + CVSS 3.1 + openEuler registry

### Balanced simplification
- Unified env flags (`pvas_env`), budget helpers (`budget_common`), sha256 (`pvas_io`)
- Single strict env gate on driver path (`PVAS_SKIP_ENV_GATE`)
- Manifest `registered_schemas` single source; auditable manifest validation step
- Test harness unified in `tests/tool_runner.py`
- `pvas_io` adoption expanded to 20+ tools; `emit_gate_result` for gate artifacts
- Language isolation check merged into `validate_report_completeness`
- `stage-policies.yaml` path corrections; guides index drift CI

### CVSS 3.1
- **Changed:** Default CVSS v3.1 (was v4.0); new `tools/cvss31_calculator.py` aligned with FIRST spec / cvssjs
- Added `references/cvss31-scoring-guide.md`; cvss-scorer must run calculator `--validate`
- Driver CVSS validation step (warn-only) for Validated findings with 3.1 vectors

### openEuler CVE registry + public correlation
- **Added:** `tools/import_openeuler_vuln_registry.py` + offline bundle under `offline-bundle/vuln-db/openeuler/`
- **Added:** M3-CVE path (CVE exact match in openEuler-Registry → `publicly_disclosed`)
- **Added:** `tools/apply_correlation_to_findings.py` (writes `disclosure_status` + refs; does not escalate `disclosure_level`)
- D2 internal report: openEuler disposition column; manifest L4/L1 bindings for progressive disclosure

## 0.10.0-alpha10

- Synced all 19 root agents to Claude Code, OpenCode, and Codex adapters.
- Added `coordinator` agent to Claude Code adapter.
- Added `tool-install-assistant` to Codex AGENTS.md.
- Registered all 19 agents in `opencode.json`.
- Unified command naming: `validate-finding` renamed to `validate` across adapters.
- Added `candidate-review` command to OpenCode adapter.
- Added 6 orphan tests to `run-tests.sh`: report admission, make_ai_packets, bilingual output, PoC safety policy, PoC testcase generation, public vulnerability correlation.
- Created `sample-report.json` test fixture for `report.schema.json`.
- Expanded `enforce_workflow_contract.py` to check all 17 schemas and all tool scripts.
- Enriched 8 generic recipes with domain-specific high-risk inputs, AI hypothesis directions, and recommended tools.
- Added "Recommended evidence" section to `build-system.md`.
- Added upgrade path guidance to `unknown-conservative.md`.
- Wired `normalize_public_vuln_records.py`, `fetch_public_vuln_sources.py`, and `summarize_artifacts.py` into `enforced_audit_driver.py`.
- Fixed `poc-readme.md` placeholder mismatch (`fixed_behavior` → `expected_fixed`).

## 0.6.0-alpha6

- Added scripted install and verify flow for Claude Code, Codex, and opencode adapters.
- Added copy/symlink install modes for offline and local-development workflows.
- Added install and migration runbook.
- Added install-script tests to the validation suite.
- Updated README, skill metadata, and release notes.


## 0.3.0-alpha3 - 2026-06-25

- Completed Claude Code, Codex, and opencode adapter installation docs.
- Expanded adapter command and subagent prompts.
- Added Binutils example artifacts.
- Added generic internal report example.
- Added packaging metadata and final validation checks.

## 0.2.0-alpha2 - 2026-06-25

- Added schemas, templates, references, tool-script MVP, and tests.
- Added CVSS and validated-only PoC/test artifact rules.

## 0.1.0-alpha1 - 2026-06-25

- Added initial portable Skill skeleton, workflows, recipes, agents, and adapter skeletons.

## 0.4.0-alpha4

- Added real sample E2E fixture `examples/toy-cpkg`.
- Added demo runner and E2E test for artifact-chain validation.
- Enhanced `profile_project.sh` to emit structured package profile artifacts.
## 0.5.0-alpha5

- Added Binutils real-source audit wrapper.
- Added Binutils-specific profiling, ASan/UBSan build, and testcase validation helpers.
- Added Binutils validation reference and runbook.
- Added tests for Binutils helper scripts.


## 0.7.0-alpha7

- Added Context Budget Guard v2.1 with per-agent independent 200K context-window policy.
- Added role-specific target input budgets and artifact allow/deny policy.
- Added `schemas/context-budget.schema.json` and `tools/context_budget.py`.
- Updated project and Binutils profiling to emit traversal manifests and context-budget artifacts.
- Updated candidate packet generation with token estimation and review batching.
- Added tests for per-agent budgeting, aggregate cost telemetry, packet batching, and documentation consistency.

## 0.8.0-alpha8

- Added Tool Availability Advisor.
- Added explicit missing-tool warnings.
- Added `environment-check.json` and `tool-install-plan` schemas.
- Added `tools/verify_environment.py` and `tools/generate_install_plan.py`.
- Updated `run_tools.sh` to generate install plans when tools are missing.
- Added user-local installation policy prioritizing Python/pipx/uv, npm/npx, and user-local binaries.
- Added offline bundle layout guidance.

## 0.9.0-alpha9

- Added bilingual zh-CN/en-US output publishing.
- Added public vulnerability correlation with M0-M3 evidence levels.
- Added local-only Validated PoC/reproducer testcase generation and safety validation.
