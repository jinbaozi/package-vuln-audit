# Claude Code Adapter: package-vuln-audit

Use the root `SKILL.md` and `AGENTS.md` as the source of truth.

## Rules

- Keep the parent Claude session clean: read summaries, not raw tool logs.
- Delegate noisy work to `.claude/agents/*` subagents.
- Never claim a vulnerability without real source-code evidence and validation evidence.
- Use Candidate → Likely → Validated / Rejected / Needs Manual Review.
- Write all artifacts under `audit-output/`.
- Do not write to source files unless the user explicitly enters patch mode.
- PoC/test artifacts are allowed only for Validated local reproduction/regression testing.

## Recommended sequence

1. `/package-profile`
2. `/package-vuln-audit`
3. `/hypothesis-hunt`
4. `/candidate-review`
5. `/validate`
6. Report from `audit-output/06-report/` and `audit-output/07-disclosure/`
