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

## intake.json template

Use this conservative default template when the user has authorized the audit
but has not supplied a richer intake artifact:

```json
{
  "authorization": "authorized defensive audit",
  "scope_summary": "Source package security audit within the provided path.",
  "source_path": ".",
  "network_policy": "restricted",
  "build_permission": "ask-before-build",
  "fuzz_permission": "disabled-by-default",
  "disclosure_policy": "internal-only until findings are validated and coordinated"
}
```

`network_policy` must be one of:

- `offline`
- `restricted`
- `online-approved`

## Failure behavior

If authorization or target scope is unclear, stop with Needs Scope Clarification. Do not run tools.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
