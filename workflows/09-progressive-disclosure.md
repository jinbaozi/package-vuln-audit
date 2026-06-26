# 09 Progressive Disclosure

## Purpose

Generate internal, maintainer-private, and public-after-fix material according to disclosure level.

## Inputs

- validated findings
- disclosure policy
- fix status

## Subagent role

`disclosure-coordinator`

## Allowed tools

- read final findings
- write audit-output/07-disclosure/

## Outputs

- maintainer-private-report.md
- cve-preparation.md
- public-advisory-draft.md

## Failure behavior

Public advisory drafts must omit sensitive reproduction details unless fix/public authorization is confirmed.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
