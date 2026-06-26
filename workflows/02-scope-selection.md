# 02 Scope Selection

## Purpose

Map the package profile to one or more recipes and choose the first-pass scan scope.

## Inputs

- package-profile.json
- recipes index

## Subagent role

`scope-selector`

## Allowed tools

- read recipes
- write audit-output/01-profile/selected-scope.json

## Outputs

- audit-output/01-profile/selected-scope.json
- audit-output/01-profile/selected-recipes.md

## Failure behavior

If no recipe fits, use unknown-conservative.md and mark confidence low.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
