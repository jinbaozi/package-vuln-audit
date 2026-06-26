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

- audit-output/01-profile/required-tools-matrix.json
- audit-output/02-tools/tool-execution-attempts.json
- audit-output/02-tools/tool-summary.json
- audit-output/02-tools/raw/

## Failure behavior

`failed`、`timeout`、`not-installed`、`malformed-output` 只是中间状态，不能作为完整审计的最终降级理由。矩阵内工具最终必须是 `completed`、`blocked` 或 `not-applicable`。`semgrep` 是完整审计强制工具，缺失、超时或执行失败时必须恢复或阻断，不能静默降级。

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
