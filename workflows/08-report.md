# 08 Report

## Purpose

Create formatted Markdown and JSON reports with finding index, validation evidence, and tool evidence index.

## Inputs

- validated findings
- CVSS artifacts
- tool summaries
- validation summaries

## Subagent role

`report-writer`

## Allowed tools

- read final artifacts
- write audit-output/06-report/

## Outputs

- audit-output/06-report/internal-security-report.md
- audit-output/06-report/internal-security-report.json

## Failure behavior

Do not include Candidate issues as confirmed vulnerabilities.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
