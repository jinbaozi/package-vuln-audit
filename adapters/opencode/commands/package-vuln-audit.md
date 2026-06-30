# opencode command: package-vuln-audit

Run complete package vulnerability audit.

Delegate:
1. `@package-profiler` for package profile and recipes.
2. `@tool-runner` for approved tool execution and summary.
3. `@hypothesis-hunter` for AI hypotheses missed by tools.
4. `@candidate-reviewer` for CAND packets.
5. `@validator` for Likely candidates.
6. `@cvss-scorer` for Likely/Validated scoring.
7. `@report-writer` for admitted findings.

Coordinator reads only summaries and final indexes.

Enforcement: see [`adapters/_shared/enforcement-patch.md`](../../_shared/enforcement-patch.md).
