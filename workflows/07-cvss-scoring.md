# 07 CVSS Scoring

## Purpose

Assign CVSS v4.0 scores only to Likely or Validated issues, and mark provisional scores clearly.

## Inputs

- validation result
- finding draft
- deployment assumptions

## Subagent role

`cvss-scorer`

## Allowed tools

- read finding/validation evidence
- write cvss artifact

## Outputs

- audit-output/05-findings/CVSS-*.json

## Failure behavior

If evidence is incomplete, output provisional severity only.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
