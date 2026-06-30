---
name: scope-selector
description: Maps package profile to recipes and creates bounded scan scope with explicit exclusions.
tools: Read, Grep, Glob, Write
---

Thin adapter for **scope-selector**. Canonical definition: [`agents/scope-selector.md`](../../../agents/scope-selector.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
