---
name: package-vuln-audit
description: Portable skill for authorized software-package vulnerability audit with traditional tools, AI hypotheses, validation evidence, CVSS scoring, formatted reports, and progressive disclosure.
---

# package-vuln-audit for Codex

This adapter delegates to the portable root skill. Use the root `SKILL.md`, `AGENTS.md`, `workflows/`, `recipes/`, `schemas/`, `templates/`, and `tools/` as the source of truth.

For complete audits, reuse the README 2.4 canonical prompt. The normalized entry parameters are `source_path=. output_dir=audit-output workflow_preset=strict-efficient max_candidates=20 cppcheck_mode=fast`.

## Codex-specific behavior

1. Follow repository `AGENTS.md` first.
2. Treat each subagent role as a fresh task packet if native subagents are unavailable.
3. Write all outputs under `audit-output/`, resolved relative to the current Codex/driver process cwd.
4. Use schemas for artifacts and templates for reports.
5. Do not paste raw tool logs into the parent context.
6. Do not promote Candidate/Likely issues to formal findings.
7. Keep the parent context summary-only: use stage summaries, schema-conformant packets, validation results, finding indexes, and final reports instead of raw logs or large source slices.
8. Require explicit intake (`00-intake/scope.md` and `00-intake/intake.json`) before a complete audit; missing intake templates are guidance, not authorization.

## Minimum workflow

- Run the driver from the audited project root for complete audits:
  ```bash
  cd /path/to/target-project
  python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output --workflow-preset strict-efficient --cppcheck-mode fast
  ```
- cppcheck defaults to `fast`; use `--cppcheck-mode deep` or `PVAS_CPPCHECK_MODE=deep` only when style/performance/portability checks are explicitly needed. Non-interactive audits do not block for this selection.
- If running from the skill repository or another directory while auditing external source, pass an explicit absolute `--out /path/to/output`.
- Use `audit-output/machine/invocation.json` to confirm resolved source/out paths. After validation, use `audit-output/05-findings/finding-index.json` as the only finding input for CVSS/report/disclosure.
- Let the driver enforce profiling, scope selection, tool execution, AI hypotheses, candidate review, validation, CVSS, public vulnerability correlation, report, and disclosure stages.
- Use direct lower-level script calls only for debugging or rerunning one stage; they are not a complete audit.
- Report only Validated and Needs Manual Review findings.
- Treat `strict-degraded` as authorization to continue evidence collection with limitations, not authorization to emit complete negative conclusions.
