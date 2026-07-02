# /package-vuln-audit

Run the complete package vulnerability audit workflow.

Arguments:
- `source_path` default `.`
- `output_dir` default `audit-output` relative to the current command process cwd, not automatically relative to `source_path`
- `allowed_tools` optional comma-separated list
- `max_candidates` default `20`
- `workflow_preset` default `strict-efficient`; supported complete-audit presets are `strict-efficient`, `strict-degraded`, and `compat-default`
- `cppcheck_mode` default `fast`; use `deep` only when style/performance/portability cppcheck coverage is explicitly needed

Steps:
1. Read `SKILL.md`, `AGENTS.md`, `references/context-hygiene.md`, and `workflows/00-intake.md`.
2. Run `tools/enforced_audit_driver.py --source <source_path> --out <output_dir> --max-candidates <max_candidates> --workflow-preset <workflow_preset> --cppcheck-mode <cppcheck_mode>` for complete audits.
3. Use subagents only through the stage packets and artifacts required by the driver.
4. Treat direct calls to lower-level scripts as single-stage debugging, not complete-audit completion.

Subagent roles used by the driver (parent must read only the artifacts each one produces):

- `package-profiler`: produces `audit-output/01-profile/package-profile.json` and selects recipes from `recipes/`.
- `tool-runner`: produces `audit-output/02-tools/tool-summary.json` after running the traditional tool matrix.
- `hypothesis-hunter`: produces `audit-output/03-candidates/` AI hypothesis packets; respects the per-packet Context Budget.
- `candidate-reviewer`: produces `audit-output/03-candidates/candidate-summary.json` after review of Top-N candidate packets.
- `validator`: produces `audit-output/04-validation/validation-summary.json` and per-finding validation results.
- `cvss-scorer`: produces CVSS v3.1 vector, score, severity and rationale in `audit-output/05-findings/`.
- `report-writer`: produces `audit-output/06-report/` zh-CN and en-US reports from the canonical machine artifacts.
- `public-vuln-correlator`: runs `correlate_public_vulns.py` and applies correlation to every Validated Finding.
- `tool-install-assistant`: invoked only when strict-required tools are missing; parent reads only summary and decision artifacts.

Parent context rule: read summaries and indexes only, never raw SARIF/log/fuzz output. Re-run the Context Budget Guard after each candidate packet batch.

Canonical prompt rule: this slash command is only the Claude Code entry syntax. Complete audits must follow the README 2.4 canonical prompt, including `workflow_preset=strict-efficient`, `cppcheck_mode=fast`, summary-only parent context, Candidate/Likely/Validated state gates, CVSS scoring, and public vulnerability correlation. Non-interactive audits do not block for cppcheck mode selection; they use fast unless `deep` is explicit.

Recommended external driver form:

```bash
cd /path/to/target-project
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output --workflow-preset strict-efficient --cppcheck-mode fast
```

If running from the skill repository or another directory while auditing external source, pass an explicit absolute `--out /path/to/output`.

Enforcement: see [`adapters/_shared/enforcement-patch.md`](../../_shared/enforcement-patch.md).
