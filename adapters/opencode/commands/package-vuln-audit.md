# opencode command: package-vuln-audit

Run complete package vulnerability audit.

Arguments:
- `source_path` default `.`
- `output_dir` default `audit-output` relative to the current command process cwd, not automatically relative to `source_path`
- `max_candidates` default `20`
- `workflow_preset` default `strict-efficient`; supported complete-audit presets are `strict-efficient`, `strict-degraded`, and `compat-default`
- `cppcheck_mode` default `fast`; use `deep` only when style/performance/portability cppcheck coverage is explicitly needed

Delegate:
1. Run `tools/enforced_audit_driver.py --source <source_path> --out <output_dir> --max-candidates <max_candidates> --workflow-preset <workflow_preset> --cppcheck-mode <cppcheck_mode>` for complete audits.
2. Use `@package-profiler`, `@tool-runner`, `@hypothesis-hunter`, `@candidate-reviewer`, `@validator`, `@cvss-scorer`, and `@report-writer` only through driver-required stage packets and artifacts.
3. Treat direct lower-level script calls as single-stage debugging, not complete-audit completion.

Canonical prompt rule: this command is only the opencode entry syntax. Complete audits must follow the README 2.4 canonical prompt, including explicit `00-intake/scope.md` and `00-intake/intake.json`, `workflow_preset=strict-efficient`, `cppcheck_mode=fast`, summary-only parent context, Candidate/Likely/Validated state gates, `05-findings/finding-index.json` as authoritative finding input, CVSS scoring, and public vulnerability correlation. Non-interactive audits do not block for cppcheck mode selection; they use fast unless `deep` is explicit. `strict-degraded` permits continued evidence collection with limitations; it does not permit complete negative conclusions.

Recommended external driver form:

```bash
cd /path/to/target-project
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output --workflow-preset strict-efficient --cppcheck-mode fast
```

If running from the skill repository or another directory while auditing external source, pass an explicit absolute `--out /path/to/output`.

Coordinator reads only summaries and final indexes.

Enforcement: see [`adapters/_shared/enforcement-patch.md`](../../_shared/enforcement-patch.md).
