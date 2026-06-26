# Codex Adapter AGENTS.md

Use the portable `package-vuln-audit` skill for authorized defensive source-code vulnerability analysis.

## Execution model

Codex may not always expose native subagents. When subagents are unavailable, simulate them through fresh task packets and fresh invocations:

- `coordinator` → summary-only orchestrator, reads summaries and dispatches
- `package-profiler` → `audit-output/01-profile/package-profile.json`
- `scope-selector` → `audit-output/01-profile/selected-scope.json`, `selected-recipes.md`
- `tool-runner` → `audit-output/02-tools/tool-summary.json`
- `tool-install-assistant` → `audit-output/00-environment/install-assistant-summary.json`
- `result-normalizer` → `audit-output/03-candidates/raw-candidates.json`
- `hypothesis-hunter` → `audit-output/03-candidates/A-CAND-*.md`
- `candidate-reviewer` → candidate status JSON/Markdown
- `validator` → `audit-output/04-validation/VAL-*.md/json`
- `poc-safety-reviewer` → safety verdict on PoC proposals
- `poc-testcase-generator` → `audit-output/04-validation/poc-tests/`
- `cvss-scorer` → CVSS block in finding JSON
- `patch-advisor` → fix recommendations under `audit-output/`
- `report-writer` → `audit-output/06-report/`
- `bilingual-report-publisher` → `audit-output/zh-CN/`, `audit-output/en-US/`
- `translation-reviewer` → language isolation verdict
- `public-vuln-correlator` → `audit-output/machine/correlation/public-vuln-correlation.json`
- `disclosure-coordinator` → `audit-output/07-disclosure/`
- `disclosure-status-reviewer` → disclosure status verdict

## Hard rules

- Do not read the full repository when a profile, summary, or candidate packet is sufficient.
- Do not invent vulnerabilities, line numbers, functions, call chains, or CVEs.
- Candidate and Likely items are not reportable vulnerabilities.
- PoC/test artifacts are permitted only for Validated local reproduction/regression testing.
- Parent context must contain only summaries and schema-conformant artifacts.

## Context Budget Guard v2.1

Each Agent/Subagent task should be treated as an independent invocation with a default 200K hard context window. Do not concatenate raw transcripts or raw logs across tasks. When native subagents are unavailable, use fresh task packets and consume only result packets.
