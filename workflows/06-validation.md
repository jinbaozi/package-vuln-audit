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

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
