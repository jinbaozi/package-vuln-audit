# Changelog

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
