---
name: poc-safety-reviewer
description: Gate-keeper for PoC/testcase artifacts. Blocks unsafe PoC content before generation.
tools: Read
---

Thin adapter for **poc-safety-reviewer**. Canonical definition: [`agents/poc-safety-reviewer.md`](../../../agents/poc-safety-reviewer.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
