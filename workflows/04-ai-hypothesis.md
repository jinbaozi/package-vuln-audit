# 04 AI Hypothesis

## Purpose

Generate source-grounded hypotheses for issues traditional tools may miss.

## Inputs

- package-profile.json
- selected recipes
- limited code slices
- tool-summary.json

## Subagent role

`hypothesis-hunter`

## Allowed tools

- read selected slices
- write audit-output/03-candidates/AI-HYP-*.json
- no broad repository reads

## Outputs

- audit-output/03-candidates/ai-hypotheses.json

## Failure behavior

Hypotheses that cannot identify input, assumption, possible gap, and validation method are discarded.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.

## Context Budget Guard

Use `context-budget.json` before loading artifacts into an agent context. The budget model is per-agent independent context: each subagent invocation has its own 200K hard window. Do not treat 200K as a workflow-wide shared limit, and do not treat it as permission to load raw repositories or raw logs.
