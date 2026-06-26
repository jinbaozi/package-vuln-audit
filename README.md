# package-vuln-audit-skill

`package-vuln-audit-skill` is a portable Agent Skill for authorized software-package vulnerability discovery and analysis. It combines traditional static/dynamic tools, AI-assisted source reasoning, subagent delegation, validation evidence, CVSS scoring, and progressive disclosure.

This first implementation slice provides the core package skeleton, the portable `SKILL.md`, the cross-platform `AGENTS.md`, the workflow descriptions, and the initial recipe set including a Binutils-oriented `binary-parser` recipe.

## Supported agent platforms

- Claude Code: via `SKILL.md`, command files, and subagent prompts under `adapters/claude-code/`.
- Codex: via `AGENTS.md` and a portable Skill folder under `adapters/codex/skills/package-vuln-audit/`.
- opencode: via `opencode.json`, agents, and commands under `adapters/opencode/`.

The core behavior is intentionally platform-neutral. Platform-specific files are adapters, not the source of truth.

## Safety boundary

Use this skill only for authorized defensive source-code review. The skill does not authorize scanning third-party systems. It requires real source evidence before any finding can be reported, and it permits PoC/test artifacts only for validated local reproduction or regression testing.

## High-level workflow

1. Intake authorization, source path, version/commit, allowed tools, build/fuzz permissions, and disclosure policy.
2. Profile the package to identify language, build system, input surfaces, package type, and high-risk modules.
3. Select one or more recipes based on the package profile.
4. Delegate noisy work to subagents: tool scans, result normalization, code slicing, hypothesis generation, validation, scoring, reports, and disclosure drafts.
5. Keep the parent agent context clean: parent reads only summaries and schema-conformant artifacts.
6. Admit only validated or explicitly marked manual-review findings into formatted reports.

## Traditional tools planned for later phases

The skill is designed to integrate `rg`, `git`, `find`, Semgrep, CodeQL, Joern, Cppcheck, `gcc -fanalyzer`, clang-tidy/scan-build, OSV-Scanner, Syft/Grype/Trivy, ASan/UBSan, AFL++, libFuzzer, Coccinelle, Smatch, and Sparse. Tool scripts are intentionally deferred until after the core workflow and context-hygiene rules stabilize.

## Output artifact layout

Planned audit output is written under `audit-output/` with separate areas for intake, profile, tools, candidates, validation, findings, reports, and progressive disclosure drafts.


## Scripted installation

Install all platform adapters into a target repository:

```bash
/path/to/package-vuln-audit-skill/install/install.sh \
  --target /path/to/repo \
  --platform all \
  --mode copy \
  --force

/path/to/package-vuln-audit-skill/install/verify-install.sh \
  --target /path/to/repo \
  --platform all
```

Use `--platform claude-code`, `--platform codex`, or `--platform opencode` for a single adapter. See `docs/runbooks/install-and-migration.md` for offline and migration details.

## Adapter installation quick reference

### Claude Code

See `adapters/claude-code/INSTALL.md`. Copy adapter commands to `.claude/commands/`, subagents to `.claude/agents/`, and the skill into a project or user skill directory. Claude Code reads project/user configuration from `.claude` locations.

### Codex

See `adapters/codex/INSTALL.md`. Copy `adapters/codex/AGENTS.md` to the target repository root and copy `adapters/codex/skills/package-vuln-audit/` to the Codex skills directory used by your environment. If native subagents are unavailable, run fresh task packets as separate invocations.

### opencode

See `adapters/opencode/INSTALL.md`. Copy `opencode.json`, agents, and commands into `.opencode/`. The opencode adapter is the most direct mapping for primary-agent plus subagent orchestration.

## Current alpha status

`0.6.0-alpha6` completes the portable package structure, schemas, templates, tool-script MVP, adapter install docs, Binutils real-source runbook, and scripted installation/verification for Claude Code, Codex, and opencode. It is still a skill package, not a full scanner appliance: it delegates actual analysis to the host agent and available local tools.

## Binutils Real-Source Runbook

For GNU Binutils source trees, use:

```bash
examples/binutils/run-binutils-audit.sh /path/to/binutils /path/to/audit-output
```

For sanitizer validation after a candidate reaches `Likely`, use:

```bash
tools/build_binutils_asan.sh /path/to/binutils /path/to/binutils/build-asan
tools/validate_binutils_input.sh /path/to/binutils/build-asan testcase.elf /path/to/audit-output/04-validation/binutils
```

Only reproducible, source-grounded issues with validation evidence may move to `Validated`.


## Context Budget Guard v2.1

`package-vuln-audit-skill` uses per-agent independent context budgeting. Each Agent/Subagent invocation has a default 200K hard context window. The workflow may consume more than 200K tokens across all invocations, but each invocation must stay under its own budget.

Run:

```bash
tools/context_budget.py --profile-dir audit-output/01-profile --packet-dir audit-output/03-candidates/packets --out audit-output/01-profile/context-budget.json
```

Important constraints:

- 200K is not the target payload size.
- Coordinator remains summary-only.
- Raw tool logs and raw fuzz logs stay on disk.
- Candidate review is split into independent batches.
- Codex adapter uses fresh invocations to emulate subagents when native subagents are unavailable.

## Tool availability and install plans

Run an environment check before a formal audit:

```bash
tools/verify_environment.py --profile standard --out audit-output/00-environment
```

If tools are missing, generate an installation plan:

```bash
tools/generate_install_plan.py \
  --environment-check audit-output/00-environment/environment-check.json \
  --out audit-output/00-environment
```

`tools/run_tools.sh` also generates an install plan automatically when one of the attempted tools is missing. The plan is advisory by default and prioritizes Python/pipx/uv, npm/npx, user-local binaries, and offline bundles over system package managers.

## 0.9.0-alpha9 capabilities

- Bilingual output: `audit-output/machine/`, `audit-output/zh-CN/`, and `audit-output/en-US/`.
- Public vulnerability correlation: compare Validated findings with configured public vulnerability records and mark public status conservatively.
- Validated PoC/reproducer: generate local-only reproducer testcases only for Validated findings.
