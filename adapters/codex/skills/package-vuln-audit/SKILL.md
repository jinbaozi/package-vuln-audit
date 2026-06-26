---
name: package-vuln-audit
description: Portable skill for authorized software-package vulnerability audit with traditional tools, AI hypotheses, validation evidence, CVSS scoring, formatted reports, and progressive disclosure.
---

# package-vuln-audit for Codex

This adapter delegates to the portable root skill. Use the root `SKILL.md`, `AGENTS.md`, `workflows/`, `recipes/`, `schemas/`, `templates/`, and `tools/` as the source of truth.

## Codex-specific behavior

1. Follow repository `AGENTS.md` first.
2. Treat each subagent role as a fresh task packet if native subagents are unavailable.
3. Write all outputs under `audit-output/`.
4. Use schemas for artifacts and templates for reports.
5. Do not paste raw tool logs into the parent context.
6. Do not promote Candidate/Likely issues to formal findings.

## Minimum workflow

- Profile package.
- Select recipe.
- Run tools or record unavailable tools.
- Generate AI hypotheses separately from tool hits.
- Build CAND packets.
- Review each CAND packet independently.
- Validate only Likely candidates.
- Score only Likely/Validated items.
- Report only Validated and Needs Manual Review findings.
