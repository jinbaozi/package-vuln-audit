---
name: package-vuln-audit
description: Portable Agent Skill for authorized software-package vulnerability discovery, source-code analysis, traditional-tool integration, AI hypothesis generation, subagent orchestration, validation, CVSS scoring, formatted reports, and progressive disclosure.
compatibility: Claude Code, Codex, opencode, and Agent Skills compatible agents
---

# Package Vulnerability Audit Skill

## When to use

Use this skill when the user provides source code or a source package and asks for vulnerability discovery, vulnerability analysis, known-vulnerability review, source-code security review, validation evidence, patch guidance, CVSS scoring, or coordinated disclosure material.

This skill is package-generic. It must first identify the package profile and choose an appropriate recipe. Do not assume a Binutils-like binary-parser target unless profiling supports that conclusion.

## Safety boundary

This skill is for authorized defensive source-code review only.

Do not invent files, functions, call chains, line numbers, CVEs, CVSS scores, PoC artifacts, or vulnerabilities. Do not generate weaponized exploit code. Do not publish sensitive details before coordinated disclosure. PoC/test artifacts are allowed only for validated local reproduction and regression testing.

## Progressive context loading

Load context in layers:

1. Read this `SKILL.md` and the root `AGENTS.md`.
2. Run the intake workflow in `workflows/00-intake.md`.
3. Use the package profile workflow in `workflows/01-package-profile.md` to select recipes.
4. Load only the selected recipe files from `recipes/`.
5. Dispatch subagents using focused task packets.
6. Review only candidate packets and summarized evidence, not the full repository or raw tool logs.

## Parent-agent context hygiene

The parent agent coordinates. It should read only structured summaries, selected recipes, subagent result packets, final candidate summaries, validation summaries, and final findings. Noisy tasks belong to subagents: system commands, tool execution, raw log parsing, large source enumeration, code slicing, fuzz output parsing, and individual candidate review.

## Required workflow

1. Intake and scope confirmation.
2. Package profiling.
3. Recipe and scan-scope selection.
4. Traditional tool scan through subagents.
5. AI hypothesis generation for issues tools may miss.
6. Candidate normalization, ranking, and packet generation.
7. Candidate review using actual source slices only.
8. Validation using local tests, sanitizer output, fuzz reproducer, or static refutation.
9. CVSS scoring for Likely/Validated issues only.
10. Formatted Markdown/JSON reporting.
11. Progressive disclosure with internal, maintainer-private, and public-after-fix levels.

## Manifest and load tiers (phase 1)

- Registry: `core/manifest.yaml` — stage `step_id`, L0–L4 load tiers, D0–D4 disclosure mapping
- L1 index: `guides/index.json`
- Coordinator reads L1 summaries only; never read L4 raw logs (see `core/disclosure/load-tiers.md`)
- Exception summary: `audit-output/machine/exception-index.json` (L1)

## Candidate state machine

`Raw Tool Hit` and `AI Hypothesis` are not vulnerabilities.

```text
Raw Tool Hit -> T-CAND
AI Hypothesis -> A-CAND
Fuzz/Sanitizer Feedback -> F-CAND
T-CAND/A-CAND/F-CAND -> Candidate Review -> Reject | Candidate | Likely
Likely -> Validation -> Validated | Rejected | Needs Manual Review
Validated -> CVSS Scoring -> Internal Report -> Maintainer Private Disclosure -> Public Advisory After Fix
```

## Validated finding requirements

A final finding must include all of the following:

- Real source path, function name, and line range.
- Untrusted input source or attacker-controlled field.
- Sink or dangerous operation.
- Source-to-sink path or explicit reachability argument.
- Validation evidence: sanitizer/fuzz/testcase/unit test/static refutation result.
- False-positive exclusion.
- Fix recommendation and regression-test guidance.
- Disclosure level.

## CVSS policy

Use CVSS v3.1 by default. Follow `references/cvss31-scoring-guide.md`. Candidate issues do not receive final CVSS scores. Likely issues may receive provisional severity. Validated issues may receive final CVSS scoring with vector, score, severity, rationale, and uncertainty. Validate scores with `tools/cvss31_calculator.py --validate`. CVSS severity is not the same as operational risk. Do not substitute openEuler `risk_level` for CVSS.

## Report outputs

Final reports must be structured and reproducible. Required formats are Markdown and JSON. SARIF or original tool output should be indexed when available. PoC/test material belongs only under validation artifacts and only for validated local reproduction or regression testing.

By default, `audit-output/` is relative to the agent or driver process current working directory, not the skill repository and not automatically relative to `--source`. Recommended complete-audit invocation:

```bash
cd /path/to/target-project
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output
```

If auditing external source while running from the skill repository or another directory, pass an explicit `--out /path/to/output` to avoid writing artifacts into the wrong workspace.

Complete audits require explicit `audit-output/00-intake/scope.md` and `audit-output/00-intake/intake.json` before proceeding. If they are absent, the driver writes `scope.template.md` and `intake.template.json` and blocks; agents must only create real intake after explicit user authorization. The driver records absolute path resolution in `audit-output/machine/invocation.json`.

After validation, `audit-output/05-findings/finding-index.json` is the authoritative finding input for CVSS, reports, and disclosure. Candidate and Likely states stay internal; Rejected items appear only in summaries. `strict-degraded` authorizes continued evidence collection under degraded tool coverage, not complete negative conclusions.

## Context Budget Guard v2.1

This skill uses a per-agent independent context model. Each coordinator or subagent invocation has its own default 200K hard context window. The workflow uses multiple independent 200K agent windows and does not pool raw context into the coordinator.

The 200K window is a hard ceiling, not a recommended payload. Default target input is 140K tokens, warning threshold is 170K, and hard input limit is 180K to reserve room for reasoning and output.

Run `tools/context_budget.py` after profiling and after packet generation to produce `context-budget.json`. The coordinator must use this artifact to decide whether to proceed, split candidate batches, truncate packets, or block a single oversized invocation.

## Tool Availability Advisor

Before or during tool scanning, check whether traditional tools are available. Missing tools must be explicit, not silent.

Required behavior:

- Write `audit-output/00-environment/environment-check.json` when running environment checks.
- Write `audit-output/00-environment/tool-install-plan.md` when tools are missing.
- Prefer Python/pipx/uv, npm/npx, user-local binaries, and offline bundles.
- Avoid root/system package manager changes by default.
- Complete-audit workflow defaults to `strict-efficient`: strict environment profile, no degraded continuation unless explicit, context efficient mode, and strict packet budget. Use `strict-degraded` for explicit degraded evidence collection, or `compat-default` only for legacy reproduction/debugging.

cppcheck defaults to `fast` mode: default/error checks plus `warning`. `deep` mode adds `style,performance,portability` and is opt-in through `--cppcheck-mode deep` or `PVAS_CPPCHECK_MODE=deep`. Interactive complete-audit driver runs prompt for this choice when no explicit mode is set; non-interactive runs and disabled startup prompts use `fast` automatically and record the choice in `audit-output/machine/cppcheck-mode.json`. A completed fast scan is an intentional coverage profile, not degraded execution.

## osv-scanner (Known Vulnerability Scan)

osv-scanner is a strict-required tool for known-dependency-vulnerability matching against the OSV database. It runs during the traditional tool scan phase (`run_tools.sh`) as `osv-scanner scan --format json <source>`.

### Installation methods (in priority order)

1. **Offline bundle (preferred)** — Place the pre-downloaded Linux binary at `offline-bundle/binaries/osv-scanner` and add a SHA256 entry to `offline-bundle/install-manifest.json`. The install assistant copies and verifies it automatically.

2. **GitHub release download** — When `--network-mode online-approved --authorize-tool osv-scanner --execute` is passed to the install assistant, it downloads the official prebuilt Linux binary from `github.com/google/osv-scanner/releases`. Architecture is auto-detected (`x86_64` → `amd64`, `aarch64` → `arm64`). The latest release version is determined via the GitHub API, with a fallback to v2.4.0.

   ```bash
   python3 tools/install_assistant.py \
     --tool osv-scanner \
     --network-mode online-approved \
     --authorize-tool osv-scanner \
     --execute
   ```

3. **User-local binary** — Manually download and place the binary:
   ```bash
    curl -sL "https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_2.4.0_linux_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" -o ~/.pvas/bin/osv-scanner && chmod +x ~/.pvas/bin/osv-scanner
   ```

4. **Go install** — Requires Go toolchain:
   ```bash
    GOBIN=$HOME/.pvas/bin go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
   ```

### Verification

```bash
~/.pvas/bin/osv-scanner --version
```

## Bilingual correlation and PoC

Publish human reports into separated `zh-CN` and `en-US` directories from the canonical `machine` artifacts. Correlate Validated findings against configured public vulnerability records. When public records are not configured in a restricted/offline internal audit, the workflow must generate an internal degraded report with `correlation_not_configured`, mark public-disclosure negative conclusions as disallowed, and avoid claiming that a finding is unpublished. Generate verified local-only reproducer testcases for `Validated` findings; generate `draft` / `unverified` local-only testcase packages for `Needs Manual Review` findings as manual-validation inputs. Keep all PoC material private unless disclosure gates allow release.

For complete audits, `semgrep` is mandatory and must complete successfully. `Needs Manual Review` items must appear in phase and final reports with manual validation plans plus passed `draft` / `unverified` execution results. Formal verified reproducer packages remain limited to `Validated` findings, and passed draft execution must not promote an item to a verified finding state.

## Explicit Strict Mode v1.0

Complete audits default to `strict-efficient`. `compat-default` preserves the older behavior where missing traditional tools can continue in degraded mode. Strict mode blocks the audit when strict-required traditional tools are missing unless explicit degraded execution is authorized. When strict mode blocks, the workflow must enter the `tool-install-assistant` flow instead of passively waiting for the user. The assistant must default to dry-run, prefer offline-bundle/Python pipx or uv/npm or npx/user-local binaries, use RPM/DNF only as a separately authorized administrator plan, enforce per-tool authorization, prefix containment, offline-bundle hash verification, network mode, version constraints, and mock-only tests. Parent agents read only install summary and decision artifacts, not full install logs.

## Workflow Enforcement & Report Completeness v1.0

Use `tools/enforced_audit_driver.py` when running the complete audit. It enforces workflow/agent/tool/schema/template/adapter consistency, post-packet Context Budget Guard, machine/zh-CN/en-US step conclusions, public vulnerability correlation status for every Validated Finding, offline DB freshness recording when public records are configured, PoC summary completeness, and final bilingual report completeness. If public records are not configured, Validated findings receive `correlation_not_configured` and the final output is a degraded internal report; set `PVAS_REQUIRE_PUBLIC_CORRELATION_FOR_VALIDATED=1` to restore the hard gate. Reports must not use absolute unpublished wording; they must say only that no match was found in configured public sources when applicable.

For complete audits, applicable `mandatory`, `profile-required`, and `recommended` tools from `required-tools-matrix.json` must finish as `completed`, `completed-with-findings`, or `not-applicable`; `not-installed`, `incomplete`, `malformed-output`, `nonzero-exit`, and stalled execution must block as `blocked-recovery-required` or `blocked-pending-confirmation`. Non-interactive confirmation writes `audit-output/machine/user-confirmations/confirmation-required.json`; resume requires a matching approved decision in `confirmation-decisions.json` and `--resume`.
