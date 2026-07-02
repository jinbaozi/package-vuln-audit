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
/package-vuln-audit source_path=. output_dir=audit-output workflow_preset=strict-efficient
/package-profile source_path=. output_dir=audit-output
/hypothesis-hunt profile=audit-output/01-profile/package-profile.json
/candidate-review candidate=audit-output/03-candidates/packets/T-CAND-0001.md
/validate candidate=audit-output/03-candidates/packets/T-CAND-0001.md
```

`output_dir=audit-output` is resolved under the current opencode command process working directory. Start opencode from the repository being audited, or use an explicit absolute output directory when auditing external source from another cwd.

## Recommended complete-audit prompt

README 2.4 is the canonical source for this prompt. Keep platform command syntax local, but keep the audit semantics synchronized with this block:

```text
使用 package-vuln-audit-skill 对当前项目做一次授权防御性漏洞审计。

入口参数：source_path=. output_dir=audit-output workflow_preset=strict-efficient max_candidates=20
审计目标：当前仓库
输出目录：audit-output（相对当前进程 cwd）
profile：standard
候选数量上限：20

执行要求：
- 完整审计必须通过 `tools/enforced_audit_driver.py` 的完整 workflow gate；低层脚本只能用于调试或单阶段复现，不能替代 gate。
- 父上下文必须保持 summary-only：只读取阶段 summary、schema 化 JSON、candidate packet、validation result、finding index 和 final report；raw logs、SARIF、fuzz 输出、大规模源码切片和完整候选全集不得直接进入父上下文。
- 默认使用 `workflow_preset=strict-efficient`；缺少 strict-required 工具时进入 tool-install-assistant 或阻断，除非显式授权 degraded；context efficient 和 strict packet budget 默认开启。
- 传统工具缺失时不能静默跳过；必须记录 missing/not-installed、说明能力降级、生成安装计划，并按 preset 和显式覆盖项处理。
- context efficient 不减少工具矩阵、Top-N、candidate review、CVSS、公开漏洞关联和报告门禁；strict packet budget 要求超预算候选拆包或阻断。
- 每个候选必须经过 Candidate → Likely → Validated / Rejected / Needs Manual Review 状态机。
- Candidate 和 Likely 不能作为最终漏洞结论；只有 Validated 和明确标记的 Needs Manual Review 可以进入人读报告。
- 每个 Validated finding 必须包含源码证据（源码路径/函数/行范围）、输入源、sink、source-to-sink 路径、可达性、验证证据、误报排除、修复建议、CVSS 评分理由和公开漏洞关联结论。
- 最终输出 machine/ 权威机器产物、zh-CN 中文报告、en-US 英文披露材料和剩余风险说明。
```

Equivalent complete-audit driver form:

```bash
cd /path/to/target-project
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output
```

Complete audits default to `strict-efficient`. For CI or other non-interactive runs, pin the preset explicitly:

```bash
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py \
  --source . \
  --out audit-output \
  --workflow-preset strict-efficient \
  --no-startup-prompt
```

Reuse the canonical prompt in README 2.4 for full audit requirements.

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
