# AGENTS.md

## Global role

You are working on authorized defensive vulnerability discovery for software packages. You must ground all conclusions in actual source code and validation evidence.

## Non-negotiable rules

- Do not invent files, functions, line numbers, call chains, CVEs, vulnerabilities, CVSS vectors, or PoC artifacts.
- Do not treat tool output as truth. Tool output creates candidates only.
- Do not treat AI hypotheses as vulnerabilities. Hypotheses require candidate review and validation.
- Do not read the whole repository by default.
- Do not put raw tool logs or large source dumps into the parent-agent context.
- Do not generate weaponized exploit code.
- Do not produce PoC/test artifacts unless the issue is validated and the artifact is for authorized local reproduction or regression testing.

## Parent-agent context hygiene

The parent agent coordinates and keeps context clean. It may read:

- `audit-output/00-intake/scope.md`
- `audit-output/01-profile/package-profile.json`
- `audit-output/02-tools/tool-summary.json`
- `audit-output/03-candidates/candidate-summary.json`
- `audit-output/04-validation/validation-summary.json`
- `audit-output/05-findings/finding-index.json`
- final reports and disclosure drafts

The parent agent must delegate noisy work to subagents: shell commands, traditional tool runs, raw output parsing, source enumeration, code slicing, fuzz log analysis, and individual candidate review.

## Token budget rules

- No full-repository reads unless explicitly authorized.
- Review Top-N candidates only; default Top-N is 20.
- Each candidate packet includes at most 3 functions.
- Each function slice includes ±80 lines by default.
- Rejected candidates do not re-enter the active context.
- Summaries are preferred over raw outputs.

## State machine

Allowed states:

- Raw Tool Hit
- AI Hypothesis
- T-CAND
- A-CAND
- F-CAND
- Candidate
- Likely
- Validated
- Rejected
- Needs Manual Review

Only `Validated` and explicitly marked `Needs Manual Review` items may appear in final reports. `Likely` may appear only in internal candidate lists with provisional scoring. `Candidate` must not be presented as a vulnerability.

## Evidence required for final finding

A final finding must include source path, function, line range, input source, sink, source-to-sink path, reachability, validation evidence, false-positive exclusion, fix recommendation, CVSS rationale, and disclosure level.

## Progressive disclosure

Use these levels:

- D0 Internal Candidate
- D1 Internal Likely
- D2 Internal Validated
- D3 Maintainer Private Disclosure
- D4 Public Advisory After Fix

Never generate public advisory material for unvalidated or uncoordinated issues.

## Context Budget Guard v2.1

- Each Agent or Subagent invocation has an independent default hard context window of 200,000 tokens.
- 200K is not a target payload size. Prefer 140K input, warn above 170K, and block or truncate above 180K input.
- The coordinator must remain summary-only: it must not read the full repository, full `all-files.txt`, raw tool logs, raw fuzz logs, or all candidate packets.
- Candidate review must use batches. Aggregate packet tokens may exceed 200K across the run, but each candidate-reviewer invocation must remain within its own 200K window.
- Batch merge is summary-only. Rejected candidate details must not re-enter active coordinator context.
- Codex environments without native subagents must emulate subagents with fresh task invocations and result packets.

## Tool Availability and Installation Advisory

When a required or recommended traditional tool is missing:

1. Do not silently ignore it.
2. Mark the tool as `missing` or `not-installed` in `environment-check.json` or `tool-summary.json`.
3. Print an explicit `[PVAS-TOOL-MISSING]` message during command execution when possible.
4. Explain which capability is degraded.
5. Generate `tool-install-plan.md` and `tool-install-plan.json`.
6. Prefer Python/pipx/uv, npm/npx, or user-local binaries where appropriate.
7. Prefer offline bundles in pure intranet environments.
8. Do not auto-install by default.
9. Do not use `sudo`, system package managers, `/usr/local/bin`, or `curl | sh` by default.
10. Only install into a user-controlled prefix when explicit opt-in is set, for example `PVAS_ALLOW_INSTALL=1`.

## Bilingual public correlation and PoC rules

- `machine/` artifacts are authoritative; localized reports are rendered views.
- `zh-CN/` must contain Chinese natural language and `en-US/` English natural language.
- Only M3 evidence can mark a finding as `publicly_disclosed`; M1/M2 remain `possibly_public`.
- Generate PoC/reproducer artifacts only for `Validated` findings.
- PoC artifacts must be local-only and must not be published unless the disclosure level explicitly allows public-after-fix.


## Explicit Strict Mode v1.0

Default mode tolerates missing traditional tools and continues in degraded mode. Strict mode blocks the audit when strict-required traditional tools are missing unless explicit degraded execution is authorized. When strict mode blocks, the workflow must enter the `tool-install-assistant` flow instead of passively waiting for the user. The assistant must default to dry-run, prefer offline-bundle/Python pipx or uv/npm or npx/user-local binaries, use RPM/DNF only as a separately authorized administrator plan, enforce per-tool authorization, prefix containment, offline-bundle hash verification, network mode, version constraints, and mock-only tests. Parent agents read only install summary and decision artifacts, not full install logs.

## Workflow Enforcement & Report Completeness v1.0

Use `tools/enforced_audit_driver.py` when running the complete audit. It enforces workflow/agent/tool/schema/template/adapter consistency, post-packet Context Budget Guard, machine/zh-CN/en-US step conclusions, public vulnerability correlation for every Validated Finding, offline DB freshness recording, PoC summary completeness, and final bilingual report completeness. Reports must not use absolute unpublished wording; they must say only that no match was found in configured public sources when applicable.
