# Release Notes: 0.10.0-alpha10

## Summary

This release addresses all issues found during the comprehensive project review: adapter agent synchronization gaps, test coverage shortfalls, recipe content deficiencies, and consistency problems.

## Key Changes

### Adapter Synchronization
- All 19 root agents now have corresponding definitions in Claude Code (11 new files), OpenCode (10 new files + JSON registration), and Codex (AGENTS.md expanded).
- Command naming unified: `validate-finding` → `validate`.
- OpenCode gains `candidate-review` command.

### Test Coverage
- 6 previously orphan tests added to `run-tests.sh` CI runner (13 total unit tests).
- `sample-report.json` fixture created for the last uncovered schema.
- `enforce_workflow_contract.py` now validates all 17 schemas and all tool scripts.

### Recipe Enrichment
- 8 generic recipes (crypto-auth, network-service, privileged-tool, package-manager, library-parser, cli-tool, mixed-project, unknown-conservative) enriched with domain-specific high-risk inputs, AI hypothesis directions, and recommended tool patterns.
- `build-system.md` gains missing "Recommended evidence" section.

### Pipeline Completeness
- `normalize_public_vuln_records.py`, `fetch_public_vuln_sources.py`, and `summarize_artifacts.py` wired into `enforced_audit_driver.py`.
- Template placeholder naming unified across root and bilingual templates.

## Verification

```bash
bash run-tests.sh
python3 tools/enforce_workflow_contract.py --root . --out /tmp/contract.json
```

Expected: all tests pass, contract status passed.
