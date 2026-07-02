# 05 Candidate Review

## Purpose

Review one candidate packet at a time and decide Reject, Candidate, or Likely.

## Inputs

- CAND-*.md
- limited source slices
- relevant tool evidence and AI hypothesis context

## Subagent role

`candidate-reviewer`

## Allowed tools

- read candidate packet
- write review result
- no full repository reads

## Outputs

- audit-output/03-candidates/reviews/CAND-*.json

## Failure behavior

If source evidence is insufficient, keep the issue as Candidate or Needs Manual Review; do not validate it.

AI hypotheses are review context only. They may guide questions and discovery-method tracing, but they must not promote an item to Candidate, Likely, Validated, or Needs Manual Review without source packet evidence.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.

## Context Budget Guard

Use `context-budget.json` before loading artifacts into an agent context. The budget model is per-agent independent context: each subagent invocation has its own 200K hard window. Do not treat 200K as a workflow-wide shared limit, and do not treat it as permission to load raw repositories or raw logs.

## 多语言输出要求

每个步骤完成后，必须生成 `machine/`、`zh-CN/`、`en-US/` 三份阶段性结论：
- `machine/`：JSON 格式的结构化步骤输出摘要
- `zh-CN/`：中文自然语言步骤结论
- `en-US/`：英文自然语言步骤结论
