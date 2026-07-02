# /package-vuln-audit

Run the complete package vulnerability audit workflow.

Arguments:
- `source_path` default `.`
- `output_dir` default `audit-output`
- `allowed_tools` optional comma-separated list
- `max_candidates` default `20`

Steps:
1. Read `SKILL.md`, `AGENTS.md`, `references/context-hygiene.md`, and `workflows/00-intake.md`.
2. Run `tools/enforced_audit_driver.py --source <source_path> --out <output_dir>` for complete audits.
3. Use subagents only through the stage packets and artifacts required by the driver.
4. Treat direct calls to lower-level scripts as single-stage debugging, not complete-audit completion.

Parent context rule: read summaries and indexes only, never raw SARIF/log/fuzz output.

Enforcement: see [`adapters/_shared/enforcement-patch.md`](../../_shared/enforcement-patch.md).
