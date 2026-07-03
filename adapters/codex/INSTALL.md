# Codex Adapter Installation

Codex reads repository instructions from `AGENTS.md` and can use Agent Skills packaged as folders containing `SKILL.md`, resources, and optional scripts.

## Project-scoped install

From the audited repository root:

```bash
cp -a /path/to/package-vuln-audit-skill/adapters/codex/AGENTS.md ./AGENTS.md
mkdir -p .codex/skills/package-vuln-audit
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
      .codex/skills/package-vuln-audit/
cp -a /path/to/package-vuln-audit-skill/adapters/codex/skills/package-vuln-audit/* .codex/skills/package-vuln-audit/
```

If your Codex environment uses a different skills directory, copy the `skills/package-vuln-audit/` folder there.

## Subagent fallback

When native subagents are unavailable, emulate subagent delegation with:

1. A fresh task packet from `schemas/`.
2. A fresh Codex invocation for that packet.
3. A schema-conformant artifact under `audit-output/`.
4. A short artifact summary for the parent agent.

Do not carry raw tool logs into follow-up Codex turns.

## Usage

Complete audits default to `strict-efficient`: strict tool gates, no degraded continuation unless explicit, context efficient mode, and strict packet budget.

## Recommended complete-audit prompt

README 2.4 is the canonical source for this prompt. Keep platform command syntax local, but keep the audit semantics synchronized with this block:

```text
使用 package-vuln-audit-skill 对当前项目做一次授权防御性漏洞审计。

入口参数：source_path=. output_dir=audit-output workflow_preset=strict-efficient max_candidates=20 cppcheck_mode=fast
审计目标：当前仓库
输出目录：audit-output（相对当前进程 cwd）
profile：standard
候选数量上限：20
cppcheck 模式：fast（默认；deep 需显式选择）

执行要求：
- 完整审计必须通过 `tools/enforced_audit_driver.py` 的完整 workflow gate；低层脚本只能用于调试或单阶段复现，不能替代 gate。
- complete audit 必须先具备 `audit-output/00-intake/scope.md` 和 `audit-output/00-intake/intake.json`；缺失时 driver 只写模板并阻断，模板不是授权。
- 父上下文必须保持 summary-only：只读取阶段 summary、schema 化 JSON、candidate packet、validation result、finding index 和 final report；raw logs、SARIF、fuzz 输出、大规模源码切片和完整候选全集不得直接进入父上下文。
- 默认使用 `workflow_preset=strict-efficient`；缺少 strict-required 工具时进入 tool-install-assistant 或阻断，除非显式授权 degraded；`strict-degraded` 只允许继续收集证据，不允许生成完整负面结论；context efficient 和 strict packet budget 默认开启。
- cppcheck 默认使用 `fast`；`deep` 需通过 `--cppcheck-mode deep` 或 `PVAS_CPPCHECK_MODE=deep` 显式选择。非交互或禁用提示时自动使用 fast，不阻塞审计启动。
- 传统工具缺失时不能静默跳过；必须记录 missing/not-installed、说明能力降级、生成安装计划，并按 preset 和显式覆盖项处理。
- context efficient 不减少工具矩阵、Top-N、candidate review、CVSS、公开漏洞关联和报告门禁；strict packet budget 要求超预算候选拆包或阻断。
- 每个候选必须经过 Candidate → Likely → Validated / Rejected / Needs Manual Review 状态机。
- Candidate 和 Likely 不能作为最终漏洞结论；只有 Validated 和明确标记的 Needs Manual Review 可以进入人读报告。
- validation 后以 `audit-output/05-findings/finding-index.json` 作为 CVSS/report/disclosure 的唯一 finding 输入。
- 每个 Validated finding 必须包含源码证据（源码路径/函数/行范围）、输入源、sink、source-to-sink 路径、可达性、验证证据、误报排除、修复建议、CVSS 评分理由和公开漏洞关联结论。
- 最终输出 machine/ 权威机器产物、zh-CN 中文报告、en-US 英文披露材料和剩余风险说明。
```

```bash
cd /path/to/target-project
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py --source . --out audit-output
```

For CI or other non-interactive runs, pin the preset explicitly:

```bash
python3 /path/to/package-vuln-audit-skill/tools/enforced_audit_driver.py \
  --source . \
  --out audit-output \
  --workflow-preset strict-efficient \
  --cppcheck-mode fast \
  --no-startup-prompt
```

Codex prompts can include `workflow_preset=strict-efficient`. Reuse the canonical prompt in README 2.4 for full audit requirements.

## Scripted install

From the skill package root:

```bash
install/install.sh --target /path/to/repo --platform codex --mode copy --force
install/verify-install.sh --target /path/to/repo --platform codex
```

## Context Budget Guard v2.1

Each Agent/Subagent task should be treated as an independent invocation with a default 200K hard context window. Do not concatenate raw transcripts or raw logs across tasks. When native subagents are unavailable, use fresh task packets and consume only result packets.
