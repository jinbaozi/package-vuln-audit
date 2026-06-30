Enforcement patch:
- Prefer `tools/enforced_audit_driver.py` for complete audit runs.
- Read workflows, adapter commands, tools, schemas, templates, and agents; do not stop at workflow descriptions.
- In strict mode, missing strict-required tools must pause the audit and dispatch `tool-install-assistant`.
- Re-run Context Budget Guard after candidate packets are generated.
- Every workflow step must emit machine, zh-CN, and en-US conclusions.
- Every Validated Finding must run public vulnerability correlation before final report publication.
- Final reports must include the public disclosure status and standard source summary table.
