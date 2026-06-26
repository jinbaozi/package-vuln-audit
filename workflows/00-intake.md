# 00 Intake

## Purpose

Collect authorization, source location, package version or commit, permitted tools, build/fuzz permissions, network policy, and disclosure policy.

## Inputs

- User request
- Source package path
- Authorization statement
- Tool and execution constraints

## Subagent role

`coordinator`

## Allowed tools

- Read user-provided inputs
- Write audit-output/00-intake/

## Outputs

- audit-output/00-intake/scope.md
- audit-output/00-intake/intake.json

## Failure behavior

If authorization or target scope is unclear, stop with Needs Scope Clarification. Do not run tools.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
