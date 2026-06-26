# 03 Tool Scan

## Purpose

Run available traditional tools through a subagent and produce a summary without polluting parent context.

## Inputs

- selected-scope.json
- allowed tools policy
- source path

## Subagent role

`tool-runner`

## Allowed tools

- bash for approved commands
- write audit-output/02-tools/
- no network unless explicitly allowed

## Outputs

- audit-output/02-tools/tool-summary.json
- audit-output/02-tools/raw/

## Failure behavior

Missing tools are recorded as unavailable. The workflow must continue with available tools.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
