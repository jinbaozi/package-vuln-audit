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


Enforcement patch:
- Prefer `tools/enforced_audit_driver.py` for complete audit runs.
- Read workflows, adapter commands, tools, schemas, templates, and agents; do not stop at workflow descriptions.
- In strict mode, missing strict-required tools must pause the audit and dispatch `tool-install-assistant`.
- Re-run Context Budget Guard after candidate packets are generated.
- Every workflow step must emit machine, zh-CN, and en-US conclusions.
- Every Validated Finding must run public vulnerability correlation before final report publication.
- Final reports must include the public disclosure status and standard source summary table.
