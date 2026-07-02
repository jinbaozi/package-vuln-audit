# Codex Adapter AGENTS.md

Use the portable `package-vuln-audit` skill for authorized defensive source-code vulnerability analysis.

## Execution model

For complete audits, invoke `tools/enforced_audit_driver.py`. Direct calls to lower-level scripts such as `tools/run_tools.sh`, normalizers, validators, or report generators are allowed for debugging a single stage, but they do not satisfy the complete-audit workflow gate.

Complete-audit prompts must reuse README 2.4 as the canonical prompt. The normalized entry parameters are:

```text
source_path=. output_dir=audit-output workflow_preset=strict-efficient max_candidates=20
```

`strict-efficient` is the default complete-audit preset: strict tool gates, no degraded continuation unless explicit, context efficient mode, and strict packet budget. Parent context remains summary-only; do not carry raw logs, SARIF, fuzz output, large source slices, or complete candidate sets into Codex conversation context. Candidate and Likely items are not reportable vulnerabilities; only Validated and explicitly marked Needs Manual Review items may enter human-readable reports. Validated findings require CVSS rationale and public vulnerability correlation.

The default `audit-output/` path is relative to the current Codex or driver process cwd, not automatically relative to `--source`. Start Codex from the audited repository root, or run:

```bash
cd /path/to/target-project
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output --workflow-preset strict-efficient
```

If running from the skill repository or another directory while auditing external source, pass an explicit absolute `--out /path/to/output`.

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
- `cvss-scorer` → CVSS v3.1 block in finding JSON (validate with `cvss31_calculator.py --validate`)
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
- Verified reproducer artifacts are for Validated local reproduction/regression testing. Needs Manual Review items may have draft/unverified PoC artifacts as manual-review inputs with passed local execution results.
- Parent context must contain only summaries and schema-conformant artifacts.

## Context Budget Guard v2.1

Each Agent/Subagent task should be treated as an independent invocation with a default 200K hard context window. Do not concatenate raw transcripts or raw logs across tasks. When native subagents are unavailable, use fresh task packets and consume only result packets.
