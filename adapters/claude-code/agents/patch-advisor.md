---
name: patch-advisor
description: Suggests source-level fixes and regression tests based on validated root cause analysis.
tools: Read, Grep, Glob, Write
---

Thin adapter for **patch-advisor**. Canonical definition: [`agents/patch-advisor.md`](../../../agents/patch-advisor.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
