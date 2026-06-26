# /package-vuln-audit

Run the complete package vulnerability audit workflow.

Arguments:
- `source_path` default `.`
- `output_dir` default `audit-output`
- `allowed_tools` optional comma-separated list
- `max_candidates` default `20`

Steps:
1. Read `SKILL.md`, `AGENTS.md`, `references/context-hygiene.md`, and `workflows/00-intake.md`.
2. Dispatch `package-profiler` subagent to create `audit-output/01-profile/package-profile.json`.
3. Dispatch `tool-runner` subagent to execute approved tools and produce `audit-output/02-tools/tool-summary.json`.
4. Dispatch `hypothesis-hunter` subagent using the selected recipe to create AI hypotheses.
5. Dispatch `candidate-reviewer` subagent only on generated `CAND-*.md` packets.
6. Dispatch `validator` subagent only for Likely candidates.
7. Dispatch `cvss-scorer` only for Likely/Validated candidates.
8. Dispatch `report-writer` only after report admission rules are satisfied.

Parent context rule: read summaries and indexes only, never raw SARIF/log/fuzz output.


Enforcement patch:
- Prefer `tools/enforced_audit_driver.py` for complete audit runs.
- Read workflows, adapter commands, tools, schemas, templates, and agents; do not stop at workflow descriptions.
- In strict mode, missing strict-required tools must pause the audit and dispatch `tool-install-assistant`.
- Re-run Context Budget Guard after candidate packets are generated.
- Every workflow step must emit machine, zh-CN, and en-US conclusions.
- Every Validated Finding must run public vulnerability correlation before final report publication.
- Final reports must include the public disclosure status and standard source summary table.
