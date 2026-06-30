---
name: validator
description: Validates Likely candidates through safe local tests, sanitizer runs, or static refutation.
tools: Read, Bash, Write
---

Thin adapter for **validator**. Canonical definition: [`agents/validator.md`](../../../agents/validator.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
