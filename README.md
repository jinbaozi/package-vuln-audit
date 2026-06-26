# package-vuln-audit-skill

`package-vuln-audit-skill` 是一个面向软件包源码的防御性漏洞审计 Agent Skill。它把传统安全工具、AI 辅助源码分析、子 agent 编排、验证证据、CVSS 评分、PoC/回归测试材料、中文主报告和渐进式披露流程组合成一套可复用的审计工作流。

本项目不是“自动宣称漏洞”的扫描器。它的目标是帮助审计人员在授权范围内系统化地发现、评审、验证和报告软件包漏洞，并确保每个结论都能追溯到真实源码和验证证据。

## 适用场景

- 对本地源码包、开源项目 checkout、内部组件仓库进行授权漏洞审计。
- 对依赖漏洞、解析器漏洞、命令行工具漏洞、构建系统漏洞、认证/加密逻辑缺陷等进行系统化分析。
- 将传统工具结果、AI 假设、人工评审和验证证据统一整理为结构化产物。
- 为已验证问题生成本地 PoC/回归测试包。
- 为需要人工确认的问题生成验证计划，方便后续审阅和复现。
- 生成中文优先的人读报告，同时保留机器 JSON 和英文披露材料。

## 不适用场景

- 未授权的第三方系统扫描。
- 远程目标利用、攻击链开发、持久化、规避或武器化 exploit 生成。
- 没有源码或没有合法审计权限的目标。
- 将工具告警或 AI 假设直接当作漏洞结论。
- 在未验证、未协调的情况下生成公开 advisory 或公开 PoC。

## 安全边界

本 Skill 只用于授权防御性源码审计。

必须遵守以下规则：

- 不编造文件、函数、行号、调用链、CVE、CVSS、PoC 或漏洞。
- 工具输出只是候选线索，不是漏洞事实。
- AI 假设必须经过源码证据和验证流程。
- `Candidate` 和 `Likely` 不能作为最终漏洞报告。
- 只有 `Validated` 和明确标记的 `Needs Manual Review` 可以进入正式人读报告。
- 正式可执行 PoC 包只允许用于 `Validated` finding 的本地复现和回归测试。
- `Needs Manual Review` 只生成安全的人工验证计划和测试方法，不生成正式 PoC 包。

## 支持的平台

核心规则以根目录 `SKILL.md`、`AGENTS.md`、`workflows/`、`references/`、`tools/`、`schemas/` 为准。平台适配器只是入口和提示词映射。

- Claude Code：`adapters/claude-code/`
- Codex：`adapters/codex/`
- opencode：`adapters/opencode/`

## 快速开始

在本仓库根目录中，针对某个待审计源码目录运行完整审计驱动器：

```bash
python3 tools/enforced_audit_driver.py \
  --source /path/to/source-package \
  --out audit-output \
  --profile standard
```

常用 profile：

- `minimal`：最小工具集合，适合快速探索。
- `standard`：默认审计基线。
- `full`：更完整的工具覆盖。
- `binutils`：偏 C/C++、二进制解析器、构建和 sanitizer 验证场景。

完整审计推荐使用 `tools/enforced_audit_driver.py`，因为它会执行工作流契约检查、环境检查、工具矩阵、Context Budget、候选 packet、PoC、公开漏洞关联和报告完整性门禁。

## 完整审计流程

完整流程按阶段写入 `audit-output/`：

1. `00-intake`：授权、范围、版本、工具权限、网络策略和披露策略。
2. `01-profile`：识别语言、构建系统、输入面、高风险模块、recipe 和工具矩阵。
3. `02-tools`：按工具矩阵执行传统工具扫描。
4. `03-candidates`：归一化工具结果、AI 假设、候选排序和 packet 生成。
5. `04-validation`：验证 `Likely`、生成 PoC 包或人工验证计划。
6. `05-findings`：保存 finding、CVSS 和最终证据结构。
7. `06-report`：生成机器报告、中文主报告、英文报告和最终汇总。
8. `07-disclosure`：生成维护者私下披露和修复后公开材料。

父 agent 应保持上下文干净：只读取摘要、schema 化产物、候选 packet、验证摘要和最终报告；原始工具日志、fuzz 日志、大量源码切片保留在磁盘，不应塞入父上下文。

## 传统工具策略

包画像阶段会生成：

```text
audit-output/01-profile/required-tools-matrix.json
```

工具执行阶段会生成：

```text
audit-output/02-tools/tool-summary.json
audit-output/02-tools/tool-execution-attempts.json
audit-output/02-tools/raw/
```

工具最终状态只能是：

- `completed`：成功执行并保留输出。
- `blocked`：计划内工具应执行但无法完成，完整审计被阻断。
- `not-applicable`：项目画像证明该工具不适用，并记录理由。

`failed`、`timeout`、`not-installed`、`malformed-output`、`partial-output` 只是中间状态，不能作为完整审计中的最终降级理由。

### semgrep 强制要求

完整审计中 `semgrep` 是 mandatory 工具。

如果 `semgrep` 缺失、超时、执行失败或输出不可用，流程必须进入恢复或阻断，不能静默降级。恢复方式包括安装助手、扩大超时、拆分扫描范围、切换本地规则集或要求用户补充规则集。

## 工具安装和缺失处理

先运行环境检查：

```bash
python3 tools/verify_environment.py \
  --profile standard \
  --out audit-output/00-environment
```

生成安装计划：

```bash
python3 tools/generate_install_plan.py \
  --environment-check audit-output/00-environment/environment-check.json \
  --out audit-output/00-environment
```

如果严格模式下缺少强制工具，可进入安装助手：

```bash
python3 tools/install_assistant.py \
  --tools semgrep,osv-scanner \
  --mode strict \
  --dry-run \
  --out audit-output/00-environment
```

安装策略默认保守：

- 默认不自动安装。
- 优先使用 offline bundle、Python/pipx/uv、npm/npx、用户目录二进制。
- 默认避免 `sudo`、系统包管理器、`/usr/local/bin` 和 `curl | sh`。
- 只有显式授权后才允许写入用户可控前缀，例如 `~/.pvas`。

## 候选状态机

工具结果和 AI 假设都不是漏洞。状态机如下：

```text
Raw Tool Hit -> T-CAND
AI Hypothesis -> A-CAND
Fuzz/Sanitizer Feedback -> F-CAND
T-CAND/A-CAND/F-CAND -> Candidate Review -> Rejected | Candidate | Likely | Needs Manual Review
Likely -> Validation -> Validated | Rejected | Needs Manual Review
Validated -> CVSS Scoring -> Internal Report -> Maintainer Private Disclosure -> Public Advisory After Fix
```

状态含义：

- `Raw Tool Hit`：原始工具命中。
- `AI Hypothesis`：AI 提出的源码假设。
- `Candidate`：有价值但证据仍不足。
- `Likely`：证据较强，值得进入验证。
- `Needs Manual Review`：自动验证不足，需要人工确认。
- `Validated`：已通过本地验证，满足最终 finding 准入条件。
- `Rejected`：证据不足或已排除。

## Validated finding 要求

每个 `Validated` finding 必须包含：

- 真实源码路径、函数名、行号范围。
- 不可信输入源或攻击者可控字段。
- sink 或危险操作。
- source-to-sink 路径或明确可达性论证。
- 验证证据，例如 sanitizer、fuzz、测试用例、单元测试或静态反证结果。
- PoC 执行结果。
- 误报排除说明。
- 修复建议和回归测试建议。
- CVSS v4.0 评分和理由。
- 披露级别。

## PoC 和复现材料

正式 PoC 包只为 `Validated` finding 生成，路径为：

```text
audit-output/04-validation/poc-tests/FINDING-*/
```

每个 PoC 包至少包含：

- `reproduce.sh`：本地复现脚本，必须使用 timeout。
- `input-description.md`：输入说明、SHA256、用途。
- `expected-vulnerable.txt`：脆弱版本预期行为。
- `expected-fixed.txt`：修复版本预期行为。
- `README.md`：复现步骤。
- `poc-manifest.json`：机器可校验元数据。
- `poc-run-result.json`：实际执行结果，必须为 passed。

生成 PoC：

```bash
python3 tools/generate_poc_testcase.py \
  --findings audit-output/05-findings/finding-index.json \
  --generate-from-finding \
  --out audit-output/04-validation/poc-tests
```

校验 PoC：

```bash
python3 tools/validate_poc_artifacts.py \
  --poc-root audit-output/04-validation/poc-tests
```

PoC 安全限制：

- 仅限授权本地验证和回归测试。
- 不访问第三方目标。
- 不使用网络工具。
- 不使用 `sudo`，不写系统目录。
- 不包含持久化、规避、提权或武器化逻辑。
- 未经修复后公开授权，不应在公开报告中包含 PoC 字节或可武器化细节。

## Needs Manual Review

`Needs Manual Review` 是一等报告对象，但不是已验证漏洞。

它用于记录证据有价值但自动验证不足的问题，例如：

- 依赖特殊语料。
- 构建环境缺失。
- 触发条件需要人工确认。
- 自动 PoC 不稳定。
- 需要人工判断业务逻辑或配置前提。

人工验证计划输出到：

```text
audit-output/04-validation/manual-review/MANUAL-*/manual-validation-plan.md
audit-output/04-validation/manual-review/MANUAL-*/manual-validation-plan.json
```

生成命令：

```bash
python3 tools/generate_manual_validation_plan.py \
  --findings audit-output/05-findings/finding-index.json \
  --out audit-output/04-validation/manual-review
```

人工验证计划包含：

- 源码证据。
- 复现假设。
- 阻断原因。
- 建议构建命令。
- 建议测试方法。
- 输入形态或数据要求。
- 预期可观察信号。
- 安全限制。
- 升级为 `Validated` 的条件。

## 报告输出

人读报告以简体中文为主，机器产物保持 JSON 结构。

常见输出：

```text
audit-output/06-report/machine/report.json
audit-output/06-report/machine/final-report.json
audit-output/06-report/zh-CN/final-summary-report.md
audit-output/06-report/zh-CN/04-findings/
audit-output/06-report/zh-CN/05-内部安全报告/internal-security-report.md
audit-output/06-report/en-US/
```

最终汇总报告会聚合：

- 审计范围和授权。
- 包画像和 selected recipes。
- 工具矩阵状态，特别是 `semgrep`。
- 候选漏斗。
- `Validated Findings`。
- `Needs Manual Review`。
- PoC 产物索引。
- 人工验证计划索引。
- 公开漏洞关联。
- CVSS 摘要。
- 阶段结论、阻断问题、剩余风险和人工跟进清单。

## 公开漏洞关联

对 `Validated` finding 可以和配置的公开漏洞数据源进行关联，例如 NVD、OSV 或离线漏洞库。

常用命令：

```bash
python3 tools/normalize_public_vuln_records.py \
  --input /path/to/public-records \
  --out audit-output/machine/correlation/normalized-public-records.json

python3 tools/correlate_public_vulns.py \
  --findings audit-output/05-findings/finding-index.json \
  --records audit-output/machine/correlation/normalized-public-records.json \
  --out audit-output/machine/correlation/public-vuln-correlation.json
```

报告不能使用“绝对未公开”这类结论；只能表述为“未在已配置公开数据源中发现匹配记录”。

## 安装到目标项目

可以把本 Skill 安装到待审计项目中：

```bash
/path/to/package-vuln-audit-skill/install/install.sh \
  --target /path/to/repo \
  --platform all \
  --mode copy \
  --force

/path/to/package-vuln-audit-skill/install/verify-install.sh \
  --target /path/to/repo \
  --platform all
```

单平台安装：

```bash
install/install.sh --target /path/to/repo --platform claude-code --mode copy --force
install/install.sh --target /path/to/repo --platform codex --mode copy --force
install/install.sh --target /path/to/repo --platform opencode --mode copy --force
```

更多安装细节见：

- `adapters/claude-code/INSTALL.md`
- `adapters/codex/INSTALL.md`
- `adapters/opencode/INSTALL.md`
- `docs/runbooks/install-and-migration.md`

## 平台使用方式

### Claude Code

安装后可使用命令：

```text
/package-vuln-audit source_path=. output_dir=audit-output
/package-profile source_path=. output_dir=audit-output
/hypothesis-hunt profile=audit-output/01-profile/package-profile.json
/candidate-review candidate=audit-output/03-candidates/CAND-001.md
/validate candidate=audit-output/03-candidates/CAND-001.md
```

### Codex

Codex 通过 `AGENTS.md` 和 `.codex/skills/package-vuln-audit/` 使用本 Skill。若环境没有原生 subagent，可用新任务调用模拟 subagent：每个任务读取独立 packet，产出 schema 化结果，父 agent 只读取摘要。

### opencode

opencode 通过 `.opencode/opencode.json`、`.opencode/agents/`、`.opencode/commands/` 使用本 Skill。它最接近“主 agent + subagent 编排”的原始模型。

## Binutils 示例

GNU Binutils 源码树可使用示例脚本：

```bash
examples/binutils/run-binutils-audit.sh \
  /path/to/binutils \
  /path/to/audit-output
```

sanitizer 构建和输入验证：

```bash
tools/build_binutils_asan.sh \
  /path/to/binutils \
  /path/to/binutils/build-asan

tools/validate_binutils_input.sh \
  /path/to/binutils/build-asan \
  testcase.elf \
  /path/to/audit-output/04-validation/binutils
```

## Context Budget Guard

本 Skill 使用“每个 agent / subagent 独立上下文预算”的模型。每次调用默认硬上限为 200K tokens，但这不是推荐输入大小。

生成预算报告：

```bash
python3 tools/context_budget.py \
  --profile-dir audit-output/01-profile \
  --packet-dir audit-output/03-candidates/packets \
  --out audit-output/01-profile/context-budget.json
```

约束：

- 父 agent 只读摘要。
- 不读取完整仓库、完整原始日志或完整 fuzz 输出。
- 候选评审按 packet 和批次拆分。
- 单个 subagent 输入超过预算时必须拆分或阻断。

## 常用命令速查

环境检查：

```bash
python3 tools/verify_environment.py --profile standard --out audit-output/00-environment
```

项目画像：

```bash
bash tools/profile_project.sh /path/to/source audit-output/01-profile
```

生成工具矩阵：

```bash
python3 tools/generate_tool_matrix.py \
  --package-profile audit-output/01-profile/package-profile.json \
  --profile standard \
  --out audit-output/01-profile/required-tools-matrix.json
```

执行工具矩阵：

```bash
python3 tools/run_tool_matrix.py \
  --matrix audit-output/01-profile/required-tools-matrix.json \
  --source /path/to/source \
  --out audit-output/02-tools
```

生成候选 packet：

```bash
python3 tools/make_ai_packets.py \
  --candidates audit-output/03-candidates/ranked-candidates.json \
  --source-root /path/to/source \
  --out audit-output/03-candidates/packets \
  --max-packets 20
```

生成最终报告：

```bash
python3 tools/generate_final_report.py \
  --audit-root audit-output \
  --findings audit-output/05-findings/finding-index.json \
  --out audit-output/06-report
```

运行测试：

```bash
./run-tests.sh
```

## 故障排查

### `semgrep` 缺失导致完整审计阻断

这是预期行为。完整审计要求 `semgrep` 成功执行。请检查：

```bash
python3 tools/verify_environment.py --profile standard --out audit-output/00-environment
python3 tools/generate_install_plan.py --environment-check audit-output/00-environment/environment-check.json --out audit-output/00-environment
```

如需安装，优先使用 offline bundle 或用户目录安装方案。

### 工具状态为 `not-applicable`

这表示项目画像证明该工具不适用，例如非 Node 项目跳过 `npm audit`。该状态必须有证据和理由，不能用来掩盖工具失败。

### PoC 校验失败

检查：

```text
audit-output/04-validation/poc-tests/FINDING-*/poc-manifest.json
audit-output/04-validation/poc-tests/FINDING-*/poc-run-result.json
audit-output/04-validation/poc-tests/FINDING-*/README.md
```

`poc-run-result.json` 必须显示 `status: passed` 且 `exit_code: 0`，否则不能进入 `Validated`。

### 没有最终汇总报告

确认已提供 findings，并且报告门禁通过：

```bash
python3 tools/validate_report_completeness.py \
  --findings audit-output/05-findings/finding-index.json \
  --correlation audit-output/machine/correlation/public-vuln-correlation.json \
  --report-root audit-output/06-report \
  --poc-root audit-output/04-validation/poc-tests \
  --manual-root audit-output/04-validation/manual-review
```

### 只有人工复核项，没有 Validated

这是允许的。此时最终汇总报告会展示 `Needs Manual Review`，并提供人工验证计划。它们不是已确认漏洞，也不会生成正式 PoC 包。

## 目录概览

```text
.
├── SKILL.md                         # Skill 入口和核心规则
├── AGENTS.md                        # 通用 agent 规则
├── workflows/                       # 00-09 工作流说明
├── agents/                          # 平台中立 agent 角色定义
├── adapters/                        # Claude Code / Codex / opencode 适配器
├── recipes/                         # 不同项目类型的审计 recipe
├── references/                      # 策略和证据标准
├── schemas/                         # 机器产物 schema
├── templates/                       # 报告和披露模板
├── tools/                           # 执行、归一化、验证、报告脚本
├── tests/                           # 单元和集成测试
├── examples/                        # 示例项目和 Binutils runbook
└── docs/                            # runbook、设计文档和实施计划
```

## 开发验证

提交前至少运行：

```bash
./run-tests.sh
```

该命令会执行 schema、Context Budget、工具矩阵、semgrep 门禁、PoC、Manual Review、报告完整性、公开漏洞关联、脚本语法和 Python 编译检查。

## 参考文档

- `docs/runbooks/tool-availability-advisor.md`
- `docs/runbooks/validated-poc-testcases.md`
- `docs/runbooks/public-vulnerability-correlation.md`
- `docs/runbooks/context-budget-guard.md`
- `docs/superpowers/specs/2026-06-26-audit-workflow-gates-design.md`
- `docs/superpowers/plans/2026-06-26-audit-workflow-gates.md`
