# 06 Validation

## Purpose

Validate Likely candidates using safe local tests, sanitizer output, fuzz reproducer, static refutation, or regression tests.

## Inputs

- Likely candidate review
- validation plan
- build permissions

## Subagent role

`validator`

## Allowed tools

- approved bash commands
- read/write audit-output/04-validation/
- no source writes except optional patch suggestions

## Outputs

- audit-output/04-validation/VAL-*.json
- audit-output/04-validation/poc-tests/FINDING-*/

## Failure behavior

If validation cannot be performed, mark Needs Manual Review with missing prerequisites.

## Post-validation steps

After validation passes (status becomes Validated), generate PoC artifacts:

1. Run `tools/generate_poc_testcase.py --findings <finding-index.json> --generate-from-finding --language <lang>` to create local-only reproducer scripts.
2. Validate PoC artifacts: `tools/validate_poc_artifacts.py --poc-root audit-output/machine/poc-tests`
3. The PoC manifest must include `discovery_method_ref` referencing the finding's discovery_method entries.
4. The PoC directory must include `input-description.md` with SHA256 and purpose fields.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
