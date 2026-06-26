# Implementation Plan: package-vuln-audit-skill

Date: 2026-06-25
Status: Ready for implementation
Target artifact: `package-vuln-audit-skill/`
Primary goal: Build a portable Agent Skill for software-package vulnerability discovery, analysis, validation, reporting, and progressive disclosure. It must support clean parent-agent orchestration, subagent delegation, traditional-tool integration, AI hypothesis generation, CVSS scoring, formatted reports, and validated-only PoC/test evidence. It must be portable across Claude Code, Codex, and opencode.

---

## 0. Ground Rules

This plan implements a defensive, authorized source-code security audit skill.

Hard constraints:

1. Findings must be grounded in real source code.
2. The agent must not invent functions, files, line numbers, CVEs, call chains, or vulnerabilities.
3. Traditional tool output is evidence, not truth.
4. AI hypotheses are not vulnerabilities until validated.
5. PoC artifacts are allowed only for validated local reproduction/regression testing, not weaponized exploitation.
6. The parent agent must stay clean: it reads only summaries, schemas, and final artifacts; subagents perform noisy code/tool work.
7. Progressive disclosure applies to both context loading and vulnerability disclosure.
8. CVSS scoring is allowed only for Likely/Validated findings; Candidate findings get only provisional severity.
9. The skill must be portable: core behavior lives in `SKILL.md`, `AGENTS.md`, workflows, recipes, tools, schemas, and templates; platform-specific behavior lives under `adapters/`.

---

## 1. External Standards and Design Inputs

Use these sources during implementation:

- Agent Skills specification: `SKILL.md` with YAML frontmatter; optional `scripts/`, `references/`, `assets/`; progressive disclosure; keep main SKILL concise.
- Superpowers `writing-plans`: plans should be complete, bite-sized, file-specific, testable, DRY/YAGNI/TDD-oriented, and saved under `docs/superpowers/plans/YYYY-MM-DD-feature.md`.
- opencode agents: primary agents and subagents; subagents can be specialized and invoked by primary agents; agents can be configured with permissions.
- Codex: `AGENTS.md` and Skills act as portable instructions/resources/scripts.
- Claude Code: Skills and subagents should be supported by adapter files.
- FIRST CVSS v4.0 specification: default scoring standard.
- SARIF 2.1.0: normalize static-analysis tool output where possible.
- Coordinated Vulnerability Disclosure: private validation and maintainer disclosure before public advisory.

---

## 2. Target File Structure

Create the following tree:

```text
package-vuln-audit-skill/
├── SKILL.md
├── AGENTS.md
├── README.md
├── skill.json
├── workflows/
│   ├── 00-intake.md
│   ├── 01-package-profile.md
│   ├── 02-scope-selection.md
│   ├── 03-tool-scan.md
│   ├── 04-ai-hypothesis.md
│   ├── 05-candidate-review.md
│   ├── 06-validation.md
│   ├── 07-cvss-scoring.md
│   ├── 08-report.md
│   └── 09-progressive-disclosure.md
├── recipes/
│   ├── binary-parser.md
│   ├── compiler-toolchain.md
│   ├── build-system.md
│   ├── cli-tool.md
│   ├── privileged-tool.md
│   ├── library-parser.md
│   ├── network-service.md
│   ├── crypto-auth.md
│   ├── package-manager.md
│   ├── mixed-project.md
│   └── unknown-conservative.md
├── agents/
│   ├── coordinator.md
│   ├── package-profiler.md
│   ├── scope-selector.md
│   ├── tool-runner.md
│   ├── result-normalizer.md
│   ├── hypothesis-hunter.md
│   ├── candidate-reviewer.md
│   ├── validator.md
│   ├── cvss-scorer.md
│   ├── patch-advisor.md
│   ├── report-writer.md
│   └── disclosure-coordinator.md
├── tools/
│   ├── profile_project.sh
│   ├── run_tools.sh
│   ├── normalize_results.py
│   ├── rank_candidates.py
│   ├── make_ai_packets.py
│   ├── validate_candidate.sh
│   └── summarize_artifacts.py
├── schemas/
│   ├── package-profile.schema.json
│   ├── tool-summary.schema.json
│   ├── candidate.schema.json
│   ├── hypothesis.schema.json
│   ├── validation-result.schema.json
│   ├── cvss.schema.json
│   ├── finding.schema.json
│   └── report.schema.json
├── templates/
│   ├── candidate.md
│   ├── ai-hypothesis.md
│   ├── validation-result.md
│   ├── finding.md
│   ├── internal-report.md
│   ├── maintainer-disclosure.md
│   ├── public-advisory.md
│   └── poc-readme.md
├── references/
│   ├── tools-inventory.md
│   ├── evidence-standard.md
│   ├── context-hygiene.md
│   ├── disclosure-policy.md
│   ├── severity-rating.md
│   ├── safety-boundary.md
│   └── report-admission-rules.md
├── adapters/
│   ├── claude-code/
│   │   ├── CLAUDE.md
│   │   ├── commands/
│   │   │   ├── package-vuln-audit.md
│   │   │   ├── package-profile.md
│   │   │   ├── hypothesis-hunt.md
│   │   │   ├── candidate-review.md
│   │   │   └── validate-finding.md
│   │   └── agents/
│   │       ├── package-profiler.md
│   │       ├── tool-runner.md
│   │       ├── hypothesis-hunter.md
│   │       ├── candidate-reviewer.md
│   │       ├── validator.md
│   │       ├── cvss-scorer.md
│   │       └── report-writer.md
│   ├── codex/
│   │   ├── AGENTS.md
│   │   └── skills/
│   │       └── package-vuln-audit/
│   │           └── SKILL.md
│   └── opencode/
│       ├── opencode.json
│       ├── agents/
│       │   ├── coordinator.md
│       │   ├── package-profiler.md
│       │   ├── tool-runner.md
│       │   ├── hypothesis-hunter.md
│       │   ├── candidate-reviewer.md
│       │   ├── validator.md
│       │   ├── cvss-scorer.md
│       │   └── report-writer.md
│       └── commands/
│           ├── package-vuln-audit.md
│           ├── package-profile.md
│           ├── hypothesis-hunt.md
│           └── validate.md
├── tests/
│   ├── fixtures/
│   │   ├── sample-package-profile.json
│   │   ├── sample-tool-summary.json
│   │   ├── sample-candidate.json
│   │   ├── sample-hypothesis.json
│   │   ├── sample-validation-result.json
│   │   └── sample-finding.json
│   ├── test_schemas.py
│   ├── test_rank_candidates.py
│   ├── test_make_ai_packets.py
│   └── test_report_admission.py
└── examples/
    ├── binutils/
    │   ├── package-profile.example.json
    │   ├── candidate.example.md
    │   ├── hypothesis.example.json
    │   ├── validation-result.example.md
    │   └── finding.example.md
    └── generic/
        └── internal-report.example.md
```

---

## 3. Implementation Phases

### Phase 1: Bootstrap package skeleton

- [ ] Create `package-vuln-audit-skill/` root directory.
- [ ] Create all top-level directories listed above.
- [ ] Add `README.md` explaining purpose, safety boundary, supported platforms, tool strategy, and artifact layout.
- [ ] Add `skill.json` with package metadata: name, version, compatibility, supported adapters.
- [ ] Add `.gitignore` to exclude generated `audit-output/`, caches, fuzz outputs, tool databases, and logs.
- [ ] Verification: `find package-vuln-audit-skill -maxdepth 2 -type d | sort` matches the planned directories.
- [ ] Commit: `chore: bootstrap package-vuln-audit-skill structure`

### Phase 2: Core `SKILL.md`

- [ ] Create `SKILL.md` with valid YAML frontmatter.
- [ ] Set `name: package-vuln-audit`.
- [ ] Write description with keywords: software package vulnerability audit, source code security review, CVE, CVSS, PoC test, subagent orchestration, progressive disclosure, Claude Code, Codex, opencode.
- [ ] Add compatibility note: offline-friendly, works with shell/Python tools, designed for Claude Code/Codex/opencode-style agents.
- [ ] Add body sections:
  - When to use
  - Safety boundary
  - Progressive context loading
  - Parent-agent context hygiene
  - Required workflow
  - Candidate state machine
  - Validated finding requirements
  - CVSS scoring policy
  - PoC/test artifact boundary
  - Report outputs
- [ ] Keep `SKILL.md` concise and reference deeper files in `references/`, `workflows/`, `recipes/`, and `templates/`.
- [ ] Verification: manually inspect frontmatter and ensure body references only existing files.
- [ ] Commit: `docs: add portable package vulnerability audit skill`

### Phase 3: Cross-platform `AGENTS.md`

- [ ] Create root `AGENTS.md`.
- [ ] Define global agent behavior rules:
  - must use actual source code
  - no invented functions/line numbers/vulnerabilities
  - no final finding without validation
  - parent agent reads summaries only
  - subagents do tool/corpus/code-slice work
  - no weaponized exploit generation
  - validated-only PoC/test output
- [ ] Add token-budget rules:
  - no full-repo reads by default
  - top-N candidates only
  - max 3 functions per candidate packet
  - function context ±80 lines by default
- [ ] Add state machine and report admission rules.
- [ ] Verification: compare rules against `SKILL.md` and ensure no contradictions.
- [ ] Commit: `docs: add cross-platform AGENTS instructions`

### Phase 4: Workflows

- [ ] Create `workflows/00-intake.md` for collecting package path, version/commit, authorization, allowed tools, build/fuzz permission, disclosure policy.
- [ ] Create `workflows/01-package-profile.md` for Package Profiler subagent.
- [ ] Create `workflows/02-scope-selection.md` for recipe selection.
- [ ] Create `workflows/03-tool-scan.md` for traditional tool execution and summary-only parent reporting.
- [ ] Create `workflows/04-ai-hypothesis.md` for AI-generated hypotheses not found by tools.
- [ ] Create `workflows/05-candidate-review.md` for candidate review packets.
- [ ] Create `workflows/06-validation.md` for sanitizer/fuzz/testcase verification.
- [ ] Create `workflows/07-cvss-scoring.md` for CVSS v4.0 and optional v3.1 scoring.
- [ ] Create `workflows/08-report.md` for Markdown/JSON/SARIF-indexed outputs.
- [ ] Create `workflows/09-progressive-disclosure.md` for internal/maintainer/public disclosure levels.
- [ ] Verification: each workflow has input files, output files, subagent role, allowed tools, and failure behavior.
- [ ] Commit: `docs: add package audit workflows`

### Phase 5: Recipes

- [ ] Create `recipes/binary-parser.md`.
  - Include high-risk inputs: file headers, offsets, section sizes, symbol/string tables, archive members, debug sections.
  - Include tools: Semgrep, CodeQL, Cppcheck, ASan/UBSan, fuzz.
  - Include example packages: binutils, libarchive, image/audio parsers.
- [ ] Create `recipes/compiler-toolchain.md`.
  - Include compiler inputs, plugins, options, specs, IR/optimization passes, assembler/linker outputs.
- [ ] Create `recipes/build-system.md`.
  - Include make/cmake/ninja, environment variables, path resolution, configure-time side effects.
- [ ] Create remaining recipes with concise scope and tool recommendations.
- [ ] Create `recipes/unknown-conservative.md` for low-confidence package profiles.
- [ ] Verification: Package Profiler output can map each profile to one or more recipe files.
- [ ] Commit: `docs: add vulnerability audit recipes`

### Phase 6: Agent role prompts

- [ ] Create `agents/coordinator.md`.
  - Define clean parent-agent responsibilities.
  - Explicitly forbid reading raw tool logs or whole repositories.
- [ ] Create `agents/package-profiler.md`.
  - Define package-profile schema output.
- [ ] Create `agents/scope-selector.md`.
  - Map profile to recipes and scan scope.
- [ ] Create `agents/tool-runner.md`.
  - Run tools, summarize outputs, do not perform vulnerability conclusions.
- [ ] Create `agents/result-normalizer.md`.
  - Convert tool outputs to normalized candidates.
- [ ] Create `agents/hypothesis-hunter.md`.
  - Generate AI hypotheses for issues tools may miss.
- [ ] Create `agents/candidate-reviewer.md`.
  - Review one candidate packet only.
- [ ] Create `agents/validator.md`.
  - Design and optionally run local validation.
- [ ] Create `agents/cvss-scorer.md`.
  - Score Likely/Validated issues only.
- [ ] Create `agents/patch-advisor.md`.
  - Produce patch guidance and regression tests.
- [ ] Create `agents/report-writer.md`.
  - Produce Markdown/JSON formatted reports.
- [ ] Create `agents/disclosure-coordinator.md`.
  - Enforce progressive disclosure gates.
- [ ] Verification: each agent prompt states inputs, outputs, forbidden behavior, and output schema.
- [ ] Commit: `docs: add agent and subagent role prompts`

### Phase 7: Schemas

- [ ] Create `schemas/package-profile.schema.json`.
- [ ] Create `schemas/tool-summary.schema.json`.
- [ ] Create `schemas/candidate.schema.json`.
  - Include type: `T-CAND`, `A-CAND`, `F-CAND`.
  - Include status: Raw Tool Hit, Candidate, Likely, Validated, Rejected, Needs Manual Review.
- [ ] Create `schemas/hypothesis.schema.json`.
  - Include assumption, input field, possible gap, possible sink, validation method.
- [ ] Create `schemas/validation-result.schema.json`.
  - Include command, artifact path, result, reproducibility, safety note.
- [ ] Create `schemas/cvss.schema.json`.
  - Include version, vector, score, severity, rationale, uncertainty, provisional/final.
- [ ] Create `schemas/finding.schema.json`.
  - Include source code evidence, source-to-sink, validation, CVSS, fix, disclosure level.
- [ ] Create `schemas/report.schema.json`.
- [ ] Add sample fixtures under `tests/fixtures/`.
- [ ] Verification: run `python3 -m json.tool` over each schema and fixture.
- [ ] Commit: `feat: add structured audit schemas`

### Phase 8: Templates

- [ ] Create `templates/candidate.md`.
- [ ] Create `templates/ai-hypothesis.md`.
- [ ] Create `templates/validation-result.md`.
- [ ] Create `templates/finding.md` with sections:
  - Status
  - CVSS
  - Source code evidence
  - Root cause
  - Source-to-sink path
  - Validation evidence
  - False-positive exclusion
  - Fix recommendation
  - Disclosure level
- [ ] Create `templates/internal-report.md`.
- [ ] Create `templates/maintainer-disclosure.md`.
- [ ] Create `templates/public-advisory.md`.
- [ ] Create `templates/poc-readme.md`.
  - Clearly state local authorized validation/regression testing only.
- [ ] Verification: every template maps to one schema or workflow.
- [ ] Commit: `docs: add report and evidence templates`

### Phase 9: References

- [ ] Create `references/tools-inventory.md` with tool table:
  - rg, git, find, Semgrep, CodeQL, Joern, Cppcheck, gcc -fanalyzer, clang-tidy, scan-build, OSV-Scanner, Syft, Grype, Trivy, ASan/UBSan, AFL++, libFuzzer, Coccinelle, Smatch, Sparse.
- [ ] Create `references/evidence-standard.md` with validated finding requirements.
- [ ] Create `references/context-hygiene.md` with parent/subagent context isolation rules.
- [ ] Create `references/disclosure-policy.md` with D0-D4 levels.
- [ ] Create `references/severity-rating.md` with CVSS usage and difference between severity and operational risk.
- [ ] Create `references/safety-boundary.md` with PoC/test boundaries.
- [ ] Create `references/report-admission-rules.md`.
- [ ] Verification: SKILL.md references each file once.
- [ ] Commit: `docs: add reference materials`

### Phase 10: Tool scripts MVP

- [ ] Create `tools/profile_project.sh`.
  - Output source file list, build files, dependency files, git log summary, language hints.
  - Write only to `audit-output/01-profile/`.
- [ ] Create `tools/run_tools.sh`.
  - Detect available tools.
  - Run installed tools only.
  - Never fail the whole workflow if one tool is missing.
  - Write raw outputs to `audit-output/02-tools/raw/` and summary to `tool-summary.json`.
- [ ] Create `tools/normalize_results.py`.
  - Parse minimal Semgrep JSON, CodeQL SARIF, Cppcheck text, rg output where available.
  - Output `raw-candidates.json`.
- [ ] Create `tools/rank_candidates.py`.
  - Apply profile-specific weights and output `ranked-candidates.json`.
- [ ] Create `tools/make_ai_packets.py`.
  - Create `CAND-*.md` packets with limited code slices.
- [ ] Create `tools/validate_candidate.sh`.
  - Run local validation command from a candidate validation plan.
  - Store outputs under `audit-output/04-validation/`.
- [ ] Create `tools/summarize_artifacts.py`.
  - Produce parent-readable summaries only.
- [ ] Make shell scripts executable.
- [ ] Verification: `bash -n tools/*.sh` and `python3 -m py_compile tools/*.py`.
- [ ] Commit: `feat: add audit tool scripts MVP`

### Phase 11: Tests

- [ ] Create `tests/test_schemas.py`.
  - Validate fixture JSON against schemas using `jsonschema` if installed; otherwise structural smoke checks.
- [ ] Create `tests/test_rank_candidates.py`.
  - Verify high-risk candidates sort above low-risk candidates.
- [ ] Create `tests/test_make_ai_packets.py`.
  - Verify packet generator limits context and includes source location.
- [ ] Create `tests/test_report_admission.py`.
  - Verify Candidate cannot become final finding; Validated can.
- [ ] Add `tests/fixtures/` JSON fixtures.
- [ ] Add a `Makefile` or `run-tests.sh` for test execution.
- [ ] Verification: `bash run-tests.sh` passes.
- [ ] Commit: `test: add schema and workflow guard tests`

### Phase 12: Claude Code adapter

- [ ] Create `adapters/claude-code/CLAUDE.md`.
- [ ] Create commands:
  - `package-vuln-audit.md`
  - `package-profile.md`
  - `hypothesis-hunt.md`
  - `candidate-review.md`
  - `validate-finding.md`
- [ ] Create Claude-compatible subagent markdown prompts.
- [ ] Ensure each subagent has limited tools and a clean output contract.
- [ ] Add install instructions to `README.md`.
- [ ] Verification: file paths are copyable into `.claude/commands/` and `.claude/agents/`.
- [ ] Commit: `feat: add Claude Code adapter`

### Phase 13: Codex adapter

- [ ] Create `adapters/codex/AGENTS.md`.
- [ ] Create `adapters/codex/skills/package-vuln-audit/SKILL.md` that points back to the core skill structure.
- [ ] Document subagent fallback: fresh task packet + fresh Codex invocation + artifact summary.
- [ ] Add install instructions to `README.md`.
- [ ] Verification: Codex adapter does not rely on Claude-specific subagent syntax.
- [ ] Commit: `feat: add Codex adapter`

### Phase 14: opencode adapter

- [ ] Create `adapters/opencode/opencode.json`.
- [ ] Define primary coordinator with restricted default behavior.
- [ ] Define subagents:
  - package-profiler
  - tool-runner
  - hypothesis-hunter
  - candidate-reviewer
  - validator
  - cvss-scorer
  - report-writer
- [ ] Define commands:
  - package-vuln-audit
  - package-profile
  - hypothesis-hunt
  - validate
- [ ] Ensure permissions reflect context hygiene:
  - profiler read-only
  - tool-runner bash allowed but source writes denied
  - report-writer write to audit-output only
- [ ] Add install instructions to `README.md`.
- [ ] Verification: `opencode.json` is valid JSON.
- [ ] Commit: `feat: add opencode adapter`

### Phase 15: Binutils example recipe

- [ ] Add `examples/binutils/package-profile.example.json`.
- [ ] Add `examples/binutils/candidate.example.md`.
- [ ] Add `examples/binutils/hypothesis.example.json`.
- [ ] Add `examples/binutils/validation-result.example.md`.
- [ ] Add `examples/binutils/finding.example.md`.
- [ ] Update `recipes/binary-parser.md` with Binutils-specific section:
  - readelf
  - objdump
  - BFD
  - DWARF/debug sections
  - archive members
  - opcodes/disassembler
- [ ] Add safe local validation command examples using ASan/UBSan and non-weaponized malformed-file testcases.
- [ ] Verification: examples do not claim real unverified vulnerabilities.
- [ ] Commit: `docs: add Binutils example workflow artifacts`

### Phase 16: Packaging and final validation

- [ ] Add `LICENSE` placeholder or internal license note.
- [ ] Add `CHANGELOG.md` with `0.1.0` initial release.
- [ ] Create `package-vuln-audit-skill-0.1.0.zip`.
- [ ] Create `package-vuln-audit-skill-0.1.0.tar.gz`.
- [ ] Compute SHA256 checksums.
- [ ] Run all tests.
- [ ] Run validation commands:
  - `bash -n tools/*.sh`
  - `python3 -m py_compile tools/*.py`
  - `python3 -m json.tool schemas/*.json`
  - `bash run-tests.sh`
- [ ] Commit: `chore: package package-vuln-audit-skill v0.1.0`

---

## 4. Acceptance Criteria

The implementation is complete when:

1. The skill validates as a portable `SKILL.md`-based package.
2. The package supports progressive context loading.
3. The package includes parent-agent context hygiene rules.
4. The package defines subagent task/result packet contracts.
5. Traditional tools are inventoried and invoked through scripts.
6. AI hypothesis generation is separate from tool-hit review.
7. Findings require source evidence, source-to-sink evidence, reachability, validation, and false-positive exclusion.
8. CVSS scoring exists and is limited to Likely/Validated findings.
9. Formatted Markdown and JSON reports exist.
10. PoC/test artifacts are allowed only for validated, local, authorized reproduction/regression testing.
11. Claude Code, Codex, and opencode adapter directories exist.
12. A Binutils example recipe and artifacts exist.
13. Tests and validation commands pass.

---

## 5. Execution Notes for Subagent-Driven Development

When implementing this plan:

1. Execute one phase at a time.
2. Use a fresh subagent/task context per phase when possible.
3. After each phase, run the listed verification command.
4. After each phase, perform a spec review:
   - Does the created artifact match this plan?
   - Did it preserve context hygiene?
   - Did it avoid overclaiming vulnerabilities?
5. After each phase, perform a code/docs quality review:
   - Are files focused?
   - Are schemas and templates consistent?
   - Are safety boundaries explicit?
6. Commit after each phase.

---

## 6. First Implementation Slice

Start with these phases only:

1. Phase 1: Bootstrap package skeleton
2. Phase 2: Core `SKILL.md`
3. Phase 3: Root `AGENTS.md`
4. Phase 4: Workflows
5. Phase 5: Recipes, including `binary-parser.md`

Do not implement tool scripts until the core skill behavior and context-hygiene rules are stable.
