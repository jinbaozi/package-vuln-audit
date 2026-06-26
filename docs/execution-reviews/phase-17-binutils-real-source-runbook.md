# Phase 17 Review: Binutils Real Source Runbook

## Spec Compliance Review

Implemented the requested fifth SDD slice: a real-source Binutils audit runbook and helper scripts that can be executed against an existing Binutils checkout without downloading source code.

Completed artifacts:

- `tools/profile_binutils.sh`
- `tools/build_binutils_asan.sh`
- `tools/validate_binutils_input.sh`
- `examples/binutils/run-binutils-audit.sh`
- `examples/binutils/README.md`
- `references/binutils-validation.md`
- `docs/runbooks/binutils-real-source.md`
- `tests/test_binutils_helpers.py`

The implementation preserves parent-agent context hygiene: the Binutils wrapper writes artifacts into `audit-output/` and instructs the parent agent to review only packet summaries and candidate files.

## Quality Review

- Shell scripts use `set -euo pipefail`.
- Optional tools tolerate absence and timeouts.
- Sanitizer validation scripts only run local binaries and local testcases.
- Binutils examples do not claim any real vulnerability.
- Added tests with a synthetic Binutils-like fixture.

## Validation

Passed:

```bash
./run-tests.sh
```

Result:

```text
schema tests passed
rank tests passed
packet tests passed
report admission tests passed
e2e toy project test passed
binutils helper tests passed
json validation passed
alpha5 checks passed
```
