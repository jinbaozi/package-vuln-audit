# Comprehensive Review & Improvement Design — v0.10.0-alpha10

**Date**: 2026-06-26
**Status**: Approved
**Scope**: Full project review and 4-batch improvement plan

---

## 1. Background

A complete, deep review of `package-vuln-audit-skill` (v0.9.0-alpha9) was conducted, covering all 10 workflows, 19 agent definitions, 27 tool scripts, 17 schemas, 23 templates, 11 recipes, 13 reference policies, 3 adapters, and 16 test files.

The review identified **3 critical issues**, **4 medium issues**, and **5 minor issues** across adapter synchronization, test coverage, recipe content, and consistency.

---

## 2. Review Findings Summary

### 2.1 What Works Well

- **Workflow completeness**: All 10 phases (00-intake → 09-progressive-disclosure) have matching `.md` workflow files, agent definitions, schemas, and templates.
- **Tool script chain**: `enforced_audit_driver.py` orchestrator invokes 17+ sub-tools; all referenced tool scripts exist with no missing files.
- **Schema-fixture coverage**: 16 of 17 schemas have corresponding test fixtures (only `sample-report.json` missing).
- **All tests pass**: 7 unit tests + static checks all pass.
- **Policy consistency**: No contradictions between 13 reference policy files, recipes, and workflows.
- **Bilingual output**: zh-CN/en-US templates are complete and symmetric (7 template pairs).
- **Context Budget Guard v2.1**: Per-agent 200K model is consistently implemented across tools, schemas, and policy docs.

### 2.2 Critical Issues

| # | Issue | Impact |
|---|-------|--------|
| C1 | **10 agents not synced to any adapter** — `scope-selector`, `result-normalizer`, `patch-advisor`, `disclosure-coordinator`, `disclosure-status-reviewer`, `poc-safety-reviewer`, `poc-testcase-generator`, `public-vuln-correlator`, `bilingual-report-publisher`, `translation-reviewer` exist in root `agents/` but not in Claude Code, OpenCode, or Codex adapters | These subagents cannot be dispatched on any platform |
| C2 | **Claude Code missing `coordinator` agent** — OpenCode has it; Claude Code does not | Core orchestrator cannot be invoked as subagent in Claude Code |
| C3 | **Codex missing `tool-install-assistant`** — Alpha10 added this to Claude Code and OpenCode but not Codex's `AGENTS.md` | Strict-mode tool recovery not available on Codex |

### 2.3 Medium Issues

| # | Issue | Impact |
|---|-------|--------|
| M1 | **6 test files not in `run-tests.sh`** — `test_bilingual_output.py`, `test_poc_safety_policy.py`, `test_poc_testcase_generation.py`, `test_public_vuln_correlation.py`, `test_report_admission.py`, `test_make_ai_packets.py` | Reduced CI coverage; regressions may go undetected |
| M2 | **Missing `sample-report.json` fixture** — `report.schema.json` has no test fixture | Top-level report format not validated in tests |
| M3 | **OpenCode missing `candidate-review` command** — Claude Code has `/candidate-review`; OpenCode does not | Inconsistent command surface |
| M4 | **`enforce_workflow_contract.py` checks only 9 of 17 schemas** | Structural validation gaps |

### 2.4 Minor Issues

| # | Issue | Impact |
|---|-------|--------|
| m1 | **8 of 11 recipes are generic boilerplate** — `cli-tool`, `crypto-auth`, `library-parser`, `mixed-project`, `network-service`, `package-manager`, `privileged-tool`, `unknown-conservative` lack domain-specific content | Reduced guidance for auditors |
| m2 | **Command naming inconsistency** — `validate-finding` (Claude Code) vs `validate` (OpenCode) | User confusion |
| m3 | **`build-system.md` missing "Recommended evidence" section** | Inconsistency with other recipes |
| m4 | **4 tool scripts not referenced by any workflow** — `fetch_public_vuln_sources.py`, `normalize_public_vuln_records.py`, `summarize_artifacts.py`, `profile_binutils.sh` | Orphan tools |
| m5 | **Root template placeholder mismatch** — `poc-readme.md` uses `{{fixed_behavior}}` vs bilingual `{{expected_fixed}}` | Rendering inconsistency |

---

## 3. Improvement Design — 4 Batches (Priority-Ordered)

### Batch 1: Adapter Agent Synchronization (Critical)

**Goal**: Ensure all 19 agents are available on all 3 platforms.

#### 3.1.1 Claude Code Adapter

Create 11 new files in `adapters/claude-code/agents/`:

| File | Source | Role |
|------|--------|------|
| `coordinator.md` | root `agents/coordinator.md` | Core orchestrator |
| `scope-selector.md` | root `agents/scope-selector.md` | Profile-to-recipe mapping |
| `result-normalizer.md` | root `agents/result-normalizer.md` | Tool output normalization |
| `patch-advisor.md` | root `agents/patch-advisor.md` | Fix recommendations |
| `disclosure-coordinator.md` | root `agents/disclosure-coordinator.md` | Progressive disclosure control |
| `disclosure-status-reviewer.md` | root `agents/disclosure-status-reviewer.md` | Disclosure status review |
| `poc-safety-reviewer.md` | root `agents/poc-safety-reviewer.md` | PoC safety gate |
| `poc-testcase-generator.md` | root `agents/poc-testcase-generator.md` | PoC testcase generation |
| `public-vuln-correlator.md` | root `agents/public-vuln-correlator.md` | Public vulnerability correlation |
| `bilingual-report-publisher.md` | root `agents/bilingual-report-publisher.md` | Bilingual report publishing |
| `translation-reviewer.md` | root `agents/translation-reviewer.md` | Translation quality review |

Each adapter file adapts the root agent definition to the Claude Code subagent prompt format (system prompt style, tool access declarations, context budget annotations).

#### 3.1.2 OpenCode Adapter

Create the same 10 new agent files in `adapters/opencode/agents/` (coordinator already exists). Update `adapters/opencode/opencode.json` to register all 19 agents with appropriate permission settings:

- `coordinator`: `bash: false` (summary-only)
- `tool-runner`: `bash: approved-tools-only`
- `validator`: `bash: approved-tools-only`
- All others: `bash: false`

Create 1 new command: `adapters/opencode/commands/candidate-review.md`

#### 3.1.3 Codex Adapter

Update `adapters/codex/AGENTS.md` to include all 19 agent descriptions (currently 7). Add `tool-install-assistant` and all 10 other missing agents. Codex uses a single `AGENTS.md` file, not individual agent files.

#### 3.1.4 Command Naming Unification

Rename `adapters/claude-code/commands/validate-finding.md` → `validate.md` to match OpenCode. Update all references in `adapters/claude-code/INSTALL.md` and any workflow files that reference the old name.

#### 3.1.5 Expected Result

| Platform | Agents | Commands |
|----------|--------|----------|
| Claude Code | 19/19 | 5 (`package-vuln-audit`, `package-profile`, `hypothesis-hunt`, `candidate-review`, `validate`) |
| OpenCode | 19/19 | 5 (same) + `opencode.json` registration |
| Codex | 19/19 in AGENTS.md | N/A (Codex uses AGENTS.md only) |

---

### Batch 2: Test Coverage & Quality Gates (Medium)

**Goal**: Achieve comprehensive test coverage and schema validation.

#### 3.2.1 Add 6 Tests to `run-tests.sh`

Insert into the always-run test section, before the existing tests:

```bash
# Report admission (pure logic, no file deps)
python3 tests/test_report_admission.py

# Bilingual output
python3 tests/test_bilingual_output.py

# PoC safety policy
python3 tests/test_poc_safety_policy.py

# PoC testcase generation
python3 tests/test_poc_testcase_generation.py

# Public vulnerability correlation
python3 tests/test_public_vuln_correlation.py

# AI packet generation (standalone)
python3 tests/test_make_ai_packets.py
```

#### 3.2.2 Create `sample-report.json`

Create `tests/fixtures/sample-report.json` conforming to `report.schema.json`:

- `package`: name, version, profile reference
- `scope`: audit scope description
- `findings`: array with at least 1 validated finding (reusing `sample-finding.json` structure)
- `public_disclosure_summary`: at least 1 entry with match_level, standard_sources, record_ids, evidence_summary, limitations, discovery_method_summary
- `generated_outputs`: machine/zh-CN/en-US path references

#### 3.2.3 Extend `enforce_workflow_contract.py`

Update `REQUIRED_SCHEMAS` from 9 entries to all 17:

```python
REQUIRED_SCHEMAS = [
    "bilingual-output.schema.json",
    "candidate.schema.json",
    "context-budget.schema.json",
    "cvss.schema.json",
    "environment-check.schema.json",
    "finding.schema.json",
    "hypothesis.schema.json",
    "install-assistant-decision.schema.json",
    "install-assistant-summary.schema.json",
    "package-profile.schema.json",
    "poc-testcase.schema.json",
    "public-vuln-correlation.schema.json",
    "public-vuln-record.schema.json",
    "report.schema.json",
    "tool-install-plan.schema.json",
    "tool-summary.schema.json",
    "validation-result.schema.json",
]
```

Also update `REQUIRED_TOOLS` to include tools added in alpha9:
- `check_offline_db_freshness.py`
- `correlate_public_vulns.py`
- `fetch_public_vuln_sources.py`
- `generate_final_report.py`
- `generate_poc_testcase.py`
- `normalize_public_vuln_records.py`
- `publish_bilingual_reports.py`
- `validate_language_outputs.py`
- `validate_poc_artifacts.py`
- `validate_report_completeness.py`

#### 3.2.4 Expected Result

- `run-tests.sh` executes 13 unit tests (7 original + 6 new)
- All 17 schemas have test fixtures
- `enforce_workflow_contract.py` validates all 17 schemas and all tool scripts

---

### Batch 3: Recipe Content Enrichment (Minor)

**Goal**: Give each recipe domain-specific high-risk inputs, AI hypothesis directions, and recommended tools.

#### 3.3.1 Enrich 8 Generic Recipes

For each recipe, add 3 sections following the `binary-parser.md` gold standard:

**`crypto-auth.md`**:
- High-risk inputs: key material, IV/nonce, certificate chains, passwords/passphrases, tokens, signed data, timestamps, permission assertions
- AI hypotheses: timing side-channels, weak PRNG, insufficient KDF, padding oracle, certificate chain validation bypass, HMAC timing attacks, CBC bit-flipping, nonce reuse
- Tool additions: `rg` patterns for `RAND_`, `srand`, `time(NULL)`, `memcmp` (password comparison)

**`network-service.md`**:
- High-risk inputs: protocol header fields, request bodies, connection metadata, TLS handshake, DNS responses, serialized messages, timeout values, concurrent connection state
- AI hypotheses: protocol state machine inconsistency, integer overflow in length fields, use-after-free on connection close, TOCTOU in request handling, deserialization vulnerabilities, DNS rebinding, HTTP request smuggling
- Tool additions: protocol-specific fuzzer modes (AFL++ protocol mode)

**`privileged-tool.md`**:
- High-risk inputs: user-supplied paths, environment variables, UID/GID, capability sets, configuration overrides, command-line arguments
- AI hypotheses: TOCTOU races, symlink attacks, capability leakage, PATH hijacking, environment variable injection, `LD_PRELOAD` attacks, uncleared environment after setuid
- Tool additions: `rg` patterns for `setuid`, `seteuid`, `setresuid`, `cap_set_proc`, `prctl`

**`package-manager.md`**:
- High-risk inputs: package name/version strings, repository URLs, signature data, dependency graphs, archive-internal paths, metadata fields
- AI hypotheses: dependency confusion, signature verification bypass, archive path traversal (zip-slip), version comparison logic errors, repository hijacking/MitM, cache poisoning
- Tool additions: `rg` patterns for `verify_signature`, `extract_to`, `resolve_version`

**`library-parser.md`**:
- High-risk inputs: external format data, serialized objects, configuration file content, user-supplied schemas
- AI hypotheses: integer overflow in size fields, deep nesting causing stack overflow, ownership semantics confusion (who frees), post-partial-parse state inconsistency, type confusion
- Tool additions: similar to `binary-parser`, focused on API boundaries

**`cli-tool.md`**:
- High-risk inputs: command-line arguments, environment variables, config file paths, stdin data, filenames
- AI hypotheses: option parsing confusion (--injection), path traversal, environment variable override, shell metacharacter injection, symlink following
- Tool additions: `getopt`/`argparse` boundary check patterns

**`mixed-project.md`**:
- High-risk inputs: cross-language boundary data, vendored dependencies, generated code, multi-build-system configs
- AI hypotheses: FFI boundary type mismatch, vendored code version staleness, generated code injection, build-system config inconsistency
- Tool additions: multi-language toolchain combination guidance

**`unknown-conservative.md`**:
- Keep minimal generic scope
- Add **upgrade path guidance**: how to transition to a more specific recipe when profiling confidence increases mid-audit

#### 3.3.2 Fix `build-system.md`

Add the missing "Recommended evidence" section: require real source path, function name, line range, source-to-sink reasoning, validation or missing-validation statement.

#### 3.3.3 Expected Result

- All 11 recipes have domain-specific high-risk inputs and AI hypothesis directions
- All 11 recipes have "Recommended evidence" sections
- `binary-parser` remains the gold standard; other recipes are no longer empty shells

---

### Batch 4: Final Polish (Minor)

**Goal**: Wire orphan tools, fix template consistency, update versioning.

#### 3.4.1 Wire Orphan Tools into Workflow

| Tool | Action |
|------|--------|
| `fetch_public_vuln_sources.py` | Add optional step in `enforced_audit_driver.py`: when `--public-records` not provided but `--allow-network` is enabled, auto-fetch public vuln sources |
| `normalize_public_vuln_records.py` | Insert before `correlate_public_vulns.py` in `enforced_audit_driver.py`: normalize raw public records before correlation |
| `summarize_artifacts.py` | Add final step in `enforced_audit_driver.py`: generate global artifact index for debugging and audit traceability |
| `profile_binutils.sh` | No workflow change needed. Document in `README.md` that it's invoked manually via `examples/binutils/run-binutils-audit.sh` |

#### 3.4.2 Unify Template Placeholders

- Update `templates/poc-readme.md`: change `{{fixed_behavior}}` → `{{expected_fixed}}` (symmetric with `{{expected_vulnerable}}`)
- Verify all other root-vs-bilingual placeholder names are consistent
- Document the intentional divergence between root `internal-report.md` (flat placeholders, simplified) and bilingual `internal-report.md` (Mustache iteration, full-featured)

#### 3.4.3 Version Update

- Update `skill.json` version to `0.10.0-alpha10`
- Update `RELEASE-NOTES-0.10.0-alpha10.md` with all improvements
- Add `0.10.0-alpha10` entry to `CHANGELOG.md`

#### 3.4.4 Expected Result

- All tool scripts have explicit roles in the workflow
- Template placeholder naming is fully consistent
- Version numbers and release docs reflect all improvements

---

## 4. Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Adapter agent files become stale after future root agent updates | Medium | Document the sync requirement in `INSTALL.md` for each adapter; add adapter sync check to `enforce_workflow_contract.py` |
| Recipe enrichment introduces incorrect domain guidance | Low | Each recipe addition is independently reviewable; content follows `binary-parser.md` patterns |
| New test additions reveal pre-existing bugs | Low | All 6 tests already pass in isolation; adding to CI just ensures they stay passing |
| `enforce_workflow_contract.py` expansion breaks on missing files | Low | Tool only checks existence, returns warnings not errors for new items initially |

---

## 5. Success Criteria

After all 4 batches are complete:

1. All 19 agents are dispatchable on all 3 adapter platforms
2. `run-tests.sh` executes 13 tests, all passing
3. `enforce_workflow_contract.py` validates 17 schemas and all tool scripts
4. All 11 recipes have domain-specific content
5. No orphan tool scripts
6. All template placeholders are consistent
7. Version bumped to `0.10.0-alpha10` with complete release notes
