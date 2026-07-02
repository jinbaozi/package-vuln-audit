# opencode Adapter Installation

opencode supports primary agents and subagents. This adapter maps the portable skill into opencode agents and commands.

## Project-scoped install

From the audited repository root:

```bash
mkdir -p .opencode/agents .opencode/commands .opencode/skills/package-vuln-audit
cp -a /path/to/package-vuln-audit-skill/SKILL.md \
      /path/to/package-vuln-audit-skill/AGENTS.md \
      /path/to/package-vuln-audit-skill/README.md \
      /path/to/package-vuln-audit-skill/workflows \
      /path/to/package-vuln-audit-skill/recipes \
      /path/to/package-vuln-audit-skill/agents \
      /path/to/package-vuln-audit-skill/tools \
      /path/to/package-vuln-audit-skill/schemas \
      /path/to/package-vuln-audit-skill/templates \
      /path/to/package-vuln-audit-skill/references \
      .opencode/skills/package-vuln-audit/
cp -a /path/to/package-vuln-audit-skill/adapters/opencode/opencode.json .opencode/opencode.json
cp -a /path/to/package-vuln-audit-skill/adapters/opencode/agents/*.md .opencode/agents/
cp -a /path/to/package-vuln-audit-skill/adapters/opencode/commands/*.md .opencode/commands/
cp -a /path/to/package-vuln-audit-skill/AGENTS.md ./AGENTS.md
```

## Usage

```text
/package-vuln-audit source_path=. output_dir=audit-output
/package-profile source_path=. output_dir=audit-output
/hypothesis-hunt profile=audit-output/01-profile/package-profile.json
/candidate-review candidate=audit-output/03-candidates/packets/T-CAND-0001.md
/validate candidate=audit-output/03-candidates/packets/T-CAND-0001.md
```

`output_dir=audit-output` is resolved under the current opencode command process working directory. Start opencode from the repository being audited, or use an explicit absolute output directory when auditing external source from another cwd.

Equivalent complete-audit driver form:

```bash
cd /path/to/target-project
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output
```

## Permission model

The default coordinator must not read raw logs or write source. Tool execution should be delegated to `tool-runner`; code-slice review should be delegated to `candidate-reviewer`; validation should be delegated to `validator`.

## Scripted install

From the skill package root:

```bash
install/install.sh --target /path/to/repo --platform opencode --mode copy --force
install/verify-install.sh --target /path/to/repo --platform opencode
```

## Context Budget Guard v2.1

Each Agent/Subagent task should be treated as an independent invocation with a default 200K hard context window. Do not concatenate raw transcripts or raw logs across tasks. When native subagents are unavailable, use fresh task packets and consume only result packets.
