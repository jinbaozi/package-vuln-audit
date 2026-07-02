# opencode command: package-vuln-audit

Run complete package vulnerability audit.

Delegate:
1. Run `tools/enforced_audit_driver.py --source <source_path> --out <output_dir>` for complete audits.
2. Use `@package-profiler`, `@tool-runner`, `@hypothesis-hunter`, `@candidate-reviewer`, `@validator`, `@cvss-scorer`, and `@report-writer` only through driver-required stage packets and artifacts.
3. Treat direct lower-level script calls as single-stage debugging, not complete-audit completion.

`output_dir` defaults to `audit-output` relative to the current command process cwd, not automatically relative to `source_path`.

Recommended external driver form:

```bash
cd /path/to/target-project
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output
```

If running from the skill repository or another directory while auditing external source, pass an explicit absolute `--out /path/to/output`.

Coordinator reads only summaries and final indexes.

Enforcement: see [`adapters/_shared/enforcement-patch.md`](../../_shared/enforcement-patch.md).
