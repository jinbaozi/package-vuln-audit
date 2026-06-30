# package-vuln-audit-skill

> 面向授权软件包源码漏洞审计的防御性 Agent Skill。
>
> 它把传统安全工具、AI 辅助源码分析、subagent 编排、候选评审、验证证据、CVSS 评分、PoC/回归测试材料、中文报告与渐进式披露流程组织成一套可复用、可审查、可交付的审计工作流。

![Status](https://img.shields.io/badge/status-0.10.0--alpha10-orange)
![Type](https://img.shields.io/badge/type-Agent%20Skill-blue)
![Platforms](https://img.shields.io/badge/platform-Claude%20Code%20%7C%20Codex%20%7C%20opencode-purple)
![License](https://img.shields.io/badge/license-MIT-green)

`package-vuln-audit-skill` 不是“自动宣称漏洞”的扫描器，也不是攻击链或武器化 exploit 生成框架。它的目标是在授权范围内，帮助审计人员把源码审计、传统工具结果、AI 假设、人工评审、验证证据、报告输出和披露材料纳入同一条可追踪证据链。

---

## 目录

- [1. 项目概览](#1-项目概览)
  - [1.1 适用场景](#11-适用场景)
  - [1.2 不适用场景](#12-不适用场景)
  - [1.3 核心能力](#13-核心能力)
- [2. 在 AI 工具中使用](#2-在-ai-工具中使用)
  - [2.1 Claude Code](#21-claude-code)
  - [2.2 opencode](#22-opencode)
  - [2.3 Codex](#23-codex)
  - [2.4 推荐提示词](#24-推荐提示词)
- [3. 审计工作流](#3-审计工作流)
  - [3.1 分阶段流程](#31-分阶段流程)
  - [3.2 候选状态机](#32-候选状态机)
  - [3.3 证据准入规则](#33-证据准入规则)
- [4. 产物与报告](#4-产物与报告)
  - [4.1 输出目录](#41-输出目录)
  - [4.2 报告类型](#42-报告类型)
  - [4.3 PoC、回归测试与人工复核](#43-poc回归测试与人工复核)
- [5. 工具、规则与扩展](#5-工具规则与扩展)
  - [5.1 Profile](#51-profile)
  - [5.2 传统工具策略](#52-传统工具策略)
  - [5.3 Agents 与上下文隔离](#53-agents-与上下文隔离)
  - [5.4 Schemas 与模板](#54-schemas-与模板)
- [6. 维护与安全边界](#6-维护与安全边界)
  - [6.1 项目结构](#61-项目结构)
  - [6.2 开发验证](#62-开发验证)
  - [6.3 安全边界](#63-安全边界)
  - [6.4 License](#64-license)

---

## 1. 项目概览

`package-vuln-audit-skill` 是一个平台中立的 Agent Skill。它适合安装到 Claude Code、Codex、opencode 或其他兼容 Agent Skill / repository instruction 的 AI 编程代理环境中。

它以 `SKILL.md`、`AGENTS.md`、`workflows/`、`agents/`、`schemas/`、`templates/` 和 `references/` 为核心，将审计任务拆分为若干独立阶段，并要求每个阶段输出可审查、可复核、可机器校验的产物。

### 1.1 适用场景

适合使用本 Skill 的场景包括：

- 对本地源码包、开源项目 checkout、内部组件仓库进行授权漏洞审计。
- 对依赖漏洞、解析器漏洞、命令行工具漏洞、构建系统漏洞、认证/加密逻辑缺陷等进行系统化分析。
- 将传统工具结果、AI 假设、人工评审和验证证据统一整理为结构化产物。
- 为已验证问题生成本地 PoC / 回归测试材料。
- 为无法自动确认但证据有价值的问题生成人工验证计划。
- 生成中文优先的人读报告，同时保留机器 JSON 产物和英文披露材料。
- 将已验证 finding 与已配置的公开漏洞数据源进行关联。

### 1.2 不适用场景

本项目不适用于以下场景：

- 未授权第三方系统扫描。
- 远程目标利用、攻击链开发、持久化、规避或武器化 exploit 生成。
- 没有源码或没有合法审计权限的目标。
- 将工具告警或 AI 假设直接当作漏洞结论。
- 在未验证、未协调的情况下生成公开 advisory 或公开 PoC。
- 承诺“自动发现所有漏洞”或“自动确认 0-day”。

### 1.3 核心能力

| 能力 | 说明 |
|---|---|
| 授权范围确认 | 在 intake 阶段记录目标、版本、授权、网络策略、工具权限和披露策略。 |
| 包画像 | 识别语言、构建系统、输入面、高风险模块和适用 recipe。 |
| 工具基线 | 对传统工具结果进行执行、归一化和摘要输出。 |
| AI 假设 | 基于源码切片、recipe 和上下文预算生成候选漏洞假设。 |
| 候选评审 | 将工具命中、AI 假设和 fuzz/sanitizer 反馈纳入统一状态机。 |
| 本地验证 | 对 Likely 候选进行本地验证、静态反证、sanitizer/fuzz/testcase 验证。 |
| 报告输出 | 输出中文主报告、机器 JSON、英文披露材料和最终摘要。 |
| 渐进式披露 | 按内部报告、维护者私下披露、修复后公开 advisory 的流程组织材料。 |

---

## 2. 在 AI 工具中使用

本 README 面向 AI 工具使用者，不直接暴露底层工具脚本的逐条调用方式。底层脚本、schemas 和模板由 Agent Skill 在执行过程中调度，用户主要通过 Claude Code、opencode 或 Codex 的项目级指令和命令入口使用本 Skill。

### 2.1 Claude Code

安装适配器后，目标仓库中会出现以下关键入口：

```text
.claude/skills/package-vuln-audit/
.claude/commands/package-vuln-audit.md
.claude/agents/
CLAUDE.md
```

推荐使用方式：

```text
/package-vuln-audit source_path=. output_dir=audit-output allowed_tools=rg,semgrep,cppcheck,osv-scanner max_candidates=20
```

也可以按阶段执行：

```text
/package-profile
/package-vuln-audit
/hypothesis-hunt
/candidate-review
/validate
```

Claude Code 适配器要求：

- 根规则以 `SKILL.md` 和 `AGENTS.md` 为准。
- 父会话只读取摘要、索引、candidate packet、验证摘要和最终报告。
- 原始工具日志、fuzz 日志、大量源码切片交给 subagent 处理。
- 除非用户明确进入 patch 模式，否则不得修改目标源码。
- PoC / testcase 只允许服务于 `Validated` finding 的本地复现和回归测试。

### 2.2 opencode

安装适配器后，目标仓库中会出现以下关键入口：

```text
.opencode/opencode.json
.opencode/commands/package-vuln-audit.md
.opencode/agents/
.opencode/skills/package-vuln-audit/
```

推荐使用方式：

```text
请使用 package-vuln-audit 工作流审计当前仓库。
审计范围：当前工作区。
输出目录：audit-output。
profile：standard。
要求：保持父上下文干净，只读取摘要和 schema 化产物；不要把 raw log、SARIF、fuzz 输出直接塞入主上下文。
```

opencode 适配器提供 `coordinator` 主 agent，并将高噪声任务拆给多个 subagent，例如：

- `@package-profiler`：包画像与 recipe 选择。
- `@tool-runner`：授权工具执行与摘要。
- `@hypothesis-hunter`：AI 漏洞假设生成。
- `@candidate-reviewer`：候选证据评审。
- `@validator`：本地验证、sanitizer、fuzz replay、静态反证。
- `@cvss-scorer`：CVSS v3.1 评分（须 `cvss31_calculator --validate`）。
- `@report-writer`：从准入 finding 生成报告。
- `@public-vuln-correlator`：公开漏洞关联。
- `@tool-install-assistant`：受控工具安装辅助。

### 2.3 Codex

Codex 适配器主要依赖目标仓库根目录的 `AGENTS.md` 和 `.codex/skills/package-vuln-audit/`。

安装适配器后，目标仓库中会出现以下关键入口：

```text
AGENTS.md
.codex/skills/package-vuln-audit/
```

推荐使用方式：

```text
请按 AGENTS.md 中的 package-vuln-audit 规则，对当前仓库做一次授权防御性源码漏洞审计。

要求：
1. 不要直接读取全仓库原始日志或大规模源码内容到主上下文。
2. 如果没有原生 subagent，请用独立任务包模拟 subagent。
3. 只将摘要、候选 packet、验证结果、finding 索引和最终报告返回到主上下文。
4. Candidate 和 Likely 不能作为最终漏洞结论。
5. Validated finding 必须包含源码证据、验证证据、误报排除、CVSS 和公开漏洞关联结论。
```

Codex 如果没有原生 subagent，应通过“独立任务包 + 独立调用 + 摘要回传”的方式模拟 subagent，避免父上下文被工具日志、扫描结果和大规模源码内容污染。

### 2.4 推荐提示词

#### 完整审计

```text
使用 package-vuln-audit-skill 对当前项目做一次授权防御性漏洞审计。

审计目标：当前仓库
输出目录：audit-output
profile：standard
候选数量上限：20

要求：
- 严格读取 SKILL.md、AGENTS.md、workflows、agents、schemas、templates 和 references。
- 不要只阅读 workflow 描述后就生成报告。
- 传统工具缺失时，不要静默跳过；按 strict/default 策略阻断、降级或进入受控安装辅助。
- 每个候选必须经过 Candidate → Likely → Validated / Rejected / Needs Manual Review 状态机。
- 只有 Validated 和明确标记的 Needs Manual Review 可以进入人读报告。
- 每个 Validated finding 必须进行公开漏洞关联。
- 最终输出中文主报告、机器 JSON、英文披露材料和剩余风险说明。
```

#### 严格模式审计

```text
使用 package-vuln-audit-skill 对当前项目做严格模式审计。

要求：
- required 工具缺失时暂停审计，不得静默跳过。
- 进入工具安装辅助时，只读取安装摘要和决策结果，不读取完整安装日志。
- 默认不使用 sudo，不改系统组件，不自动执行系统包管理器。
- 如需安装工具，优先 offline bundle、用户目录安装和受控前缀。
- 所有阻断、降级和人工复核项都必须写入最终报告。
```

#### 只做报告整理

```text
读取 audit-output 中已有的审计产物，使用 package-vuln-audit-skill 生成最终报告。

要求：
- 不重新扫描源码。
- 只读取 summary、finding index、validation result、CVSS、public vulnerability correlation 和 disclosure artifacts。
- 区分 Validated Findings 与 Needs Manual Review。
- 中文主报告应可直接用于内部安全评审。
- 英文披露材料应面向维护者私下沟通，不包含未协调公开的武器化细节。
```

---

## 3. 审计工作流

### 3.1 分阶段流程

完整审计按阶段组织，核心流程如下：

```text
授权与范围确认
  ↓
包画像与 recipe 选择
  ↓
工具基线与结果摘要
  ↓
候选归一化与 AI 假设生成
  ↓
候选评审与排序
  ↓
本地验证 / 静态反证 / 人工复核计划
  ↓
CVSS 评分与 finding 固化
  ↓
中文报告 / 英文披露 / 公开漏洞关联
  ↓
渐进式披露材料
```

对应 workflow：

| 阶段 | 文件 | 作用 |
|---|---|---|
| 00 | `workflows/00-intake.md` | 授权、范围、版本、权限、网络策略、披露策略。 |
| 01 | `workflows/01-package-profile.md` | 语言、构建系统、输入面、高风险模块和 recipe 选择。 |
| 02 | `workflows/02-scope-selection.md` | 选择审计范围，避免无边界全仓库读取。 |
| 03 | `workflows/03-tool-scan.md` | 传统工具基线与工具摘要。 |
| 04 | `workflows/04-ai-hypothesis.md` | AI 辅助漏洞假设生成。 |
| 05 | `workflows/05-candidate-review.md` | 候选证据评审与状态更新。 |
| 06 | `workflows/06-validation.md` | 本地验证、反证、PoC/回归材料或人工验证计划。 |
| 07 | `workflows/07-cvss-scoring.md` | CVSS v3.1 评分和理由。 |
| 08 | `workflows/08-report.md` | 机器报告、中文主报告、英文报告。 |
| 09 | `workflows/09-progressive-disclosure.md` | 维护者私下披露与修复后公开材料。 |

### 3.2 候选状态机

工具结果和 AI 假设都不是漏洞事实。所有候选必须进入状态机：

```text
Raw Tool Hit  → T-CAND
AI Hypothesis → A-CAND
Fuzz/Sanitizer Feedback → F-CAND

T-CAND / A-CAND / F-CAND
  → Candidate Review
  → Rejected | Candidate | Likely | Needs Manual Review

Likely
  → Validation
  → Validated | Rejected | Needs Manual Review

Validated
  → CVSS Scoring
  → Internal Report
  → Maintainer Private Disclosure
  → Public Advisory After Fix
```

状态含义：

| 状态 | 含义 | 是否可作为最终漏洞 |
|---|---|---|
| `Raw Tool Hit` | 原始工具命中。 | 否 |
| `AI Hypothesis` | AI 提出的源码假设。 | 否 |
| `Candidate` | 有价值但证据不足。 | 否 |
| `Likely` | 证据较强，值得验证。 | 否 |
| `Needs Manual Review` | 自动验证不足，需要人工确认。 | 可进入报告，但必须明确标注为人工复核项 |
| `Validated` | 已通过本地验证，满足 finding 准入条件。 | 是 |
| `Rejected` | 证据不足或已排除。 | 否 |

### 3.3 证据准入规则

每个 `Validated` finding 必须包含：

- 真实源码路径、函数名和行号范围。
- 不可信输入源或攻击者可控字段。
- sink 或危险操作。
- source-to-sink 路径或明确可达性论证。
- 本地验证证据，例如 sanitizer、fuzz、测试用例、单元测试、静态反证结果。
- 误报排除说明。
- 修复建议和回归测试建议。
- CVSS v3.1 评分和理由。
- 公开漏洞关联结论。
- 披露级别与披露建议。

禁止将以下内容直接写成漏洞结论：

- 单条工具告警。
- 未验证的 AI 猜测。
- 缺少源码证据的调用链。
- 缺少触发条件的崩溃信息。
- 缺少公开来源的 CVE / CVSS / 公开披露状态。

---

## 4. 产物与报告

### 4.1 输出目录

默认审计输出目录为 `audit-output/`。推荐结构如下：

```text
audit-output/
├── 00-intake/                  # 授权、范围、策略
├── 01-profile/                 # 包画像、recipe、工具矩阵
├── 02-tools/                   # 工具摘要与原始工具输出索引
├── 03-candidates/              # 候选、排序、AI packet
├── 04-validation/              # 验证结果、PoC/回归测试、人工复核计划
├── 05-findings/                # finding 索引、CVSS、最终证据结构
├── 06-report/                  # 中文报告、英文报告、机器 JSON
├── 07-disclosure/              # 维护者披露和公开材料
└── machine/                    # 跨阶段机器产物，例如公开漏洞关联
```

父 agent 不应把这些目录中的原始大文件全部读入上下文。推荐读取顺序是：

1. 阶段 summary。
2. schema 化 JSON。
3. candidate packet。
4. validation result。
5. finding index。
6. final report。

### 4.2 报告类型

| 报告 | 用途 |
|---|---|
| 中文主报告 | 内部安全评审、研发沟通、管理层汇报。 |
| 机器 JSON | 自动化校验、二次处理、CI/归档。 |
| 英文披露材料 | 面向上游维护者的私下沟通。 |
| 公开 advisory 草案 | 修复后、协调后再进入公开阶段。 |
| 人工复核计划 | 对 `Needs Manual Review` 项提供安全验证路径。 |

最终报告必须区分：

- `Validated Findings`
- `Needs Manual Review`
- `Rejected / False Positive`
- 工具阻断与降级情况
- 剩余风险
- 公开漏洞关联状态
- 后续人工跟进清单

### 4.3 PoC、回归测试与人工复核

正式 PoC / testcase 包只允许为 `Validated` finding 生成，用途限定为授权本地复现和回归测试。

PoC 安全限制：

- 不访问第三方目标。
- 不执行远程利用。
- 不包含持久化、规避、提权或武器化逻辑。
- 不写系统目录。
- 不要求管理员权限。
- 不在未协调修复前公开可武器化细节。

`Needs Manual Review` 是一等报告对象，但不是已验证漏洞。它用于记录证据有价值但自动验证不足的问题，例如：

- 构建环境缺失。
- 触发条件需要人工确认。
- 自动 PoC 不稳定。
- 依赖特殊语料或配置。
- 业务逻辑或部署前提需要人工判断。

`Needs Manual Review` 只生成安全的人工验证计划，不生成正式 PoC 包。

---

## 5. 工具、规则与扩展

### 5.1 Profile

profile 用于控制审计深度和工具覆盖。常用 profile：

| Profile | 用途 | 说明 |
|---|---|---|
| `minimal` | 快速探索 | 最小工具集合，适合初步了解项目。 |
| `standard` | 默认审计 | 常规源码包审计基线。 |
| `full` | 深度审计 | 更完整的工具覆盖，需要显式选择。 |
| `binutils` | C/C++、解析器、二进制工具链场景 | 偏构建、sanitizer、fuzz、二进制工具链审计。 |

profile 不等于“所有工具一定运行”。工具是否运行取决于：

- 本机是否已安装。
- 当前项目画像是否适用。
- 用户授权的工具范围。
- strict/default 模式。
- 网络策略与安装策略。
- 工具输出是否可用、完整、可解析。

### 5.2 传统工具策略

传统工具结果是候选线索，不是漏洞事实。

工具最终状态只能归入：

| 状态 | 含义 |
|---|---|
| `completed` | 成功执行并保留可用输出。 |
| `blocked` | 计划内工具应执行但无法完成，完整审计被阻断。 |
| `not-applicable` | 项目画像证明该工具不适用，并记录理由。 |

以下状态只能作为中间状态，不能作为完整审计中的最终静默降级理由：

- `failed`
- `timeout`
- `not-installed`
- `malformed-output`
- `partial-output`

严格模式下，required 工具缺失时必须暂停审计或进入受控安装辅助流程。安装辅助策略默认保守：

- 默认不自动安装。
- 默认不使用管理员权限。
- 默认不改系统组件。
- 默认不直接执行系统包管理器。
- 优先 offline bundle、用户目录安装、受控前缀和可验证来源。
- 父 agent 只读取安装摘要、安装计划和决策结果，不读取完整安装日志。

### 5.3 Agents 与上下文隔离

本 Skill 通过 agent / subagent 角色拆分审计任务。父 agent 负责协调，不负责吞入所有原始材料。

| 类别 | 典型角色 |
|---|---|
| 协调与范围 | `coordinator`、`package-profiler`、`scope-selector` |
| 工具与归一化 | `tool-runner`、`result-normalizer`、`tool-install-assistant` |
| 候选与验证 | `hypothesis-hunter`、`candidate-reviewer`、`validator` |
| 评分与修复 | `cvss-scorer`、`patch-advisor` |
| PoC 与报告 | `poc-safety-reviewer`、`poc-testcase-generator`、`report-writer` |
| 披露与关联 | `public-vuln-correlator`、`disclosure-coordinator`、`disclosure-status-reviewer` |
| 双语输出 | `bilingual-report-publisher`、`translation-reviewer` |

上下文隔离原则：

- 父 agent 只读摘要、索引、packet 和最终报告。
- 高噪声任务交给 subagent。
- 原始工具日志保留在磁盘，不进入父上下文。
- 每个 candidate 尽量单独评审，避免不同候选证据互相污染。
- candidate packet 生成后必须重新执行 Context Budget Guard。

### 5.4 Schemas 与模板

本项目通过 JSON Schema 固化关键产物结构，避免报告完全依赖自然语言自由发挥。

核心 schema 类型包括：

- candidate
- finding
- validation result
- CVSS
- report
- tool summary
- environment check
- tool install plan
- public vulnerability correlation
- bilingual output
- PoC testcase
- manual validation plan

模板用于生成：

- 中文内部报告。
- 英文维护者披露材料。
- 修复后公开 advisory。
- finding 详情页。
- PoC README。
- 工具安装计划。
- 人工验证计划。

---

## 6. 维护与安全边界

### 6.1 项目结构

```text
package-vuln-audit/
├── SKILL.md                 # Skill 总入口与用途说明
├── AGENTS.md                # 全局 agent 规则、安全边界、状态机
├── skill.json               # Skill 元数据、版本、兼容平台
├── adapters/                # Claude Code / Codex / opencode 适配器
├── agents/                  # 平台中立 subagent 角色定义
├── workflows/               # 00-09 审计阶段定义
├── recipes/                 # 不同包类型和风险面的审计 recipe
├── references/              # 上下文卫生、安装策略、披露策略等参考规则
├── schemas/                 # 机器产物 JSON Schema
├── templates/               # 报告、披露、finding、PoC 模板
├── tools/                   # 底层执行、校验、归一化和报告辅助工具
├── install/                 # 适配器安装与验证辅助
├── examples/                # 示例审计目标与样例材料
├── tests/                   # 回归测试与规则校验
└── docs/                    # 运行手册、补充文档和迁移说明
```

### 6.2 开发验证

维护者修改 workflow、agent、schema、template 或 adapter 后，应执行项目测试入口，并至少检查：

- workflow、commands、tools、schemas、templates 是否一致。
- adapter 是否仍能找到核心 skill 文件。
- candidate / finding / validation / report schema 是否兼容。
- Context Budget Guard 是否仍在 candidate packet 之后执行。
- strict mode 下 required 工具缺失是否会阻断或进入安装辅助。
- 最终报告是否包含公开漏洞关联、披露状态、双语产物和人工复核项。
- PoC 生成策略是否仍只服务于 `Validated` finding。

### 6.3 安全边界

必须遵守：

- 仅用于授权防御性源码审计。
- 不编造文件、函数、行号、调用链、CVE、CVSS、PoC 或漏洞。
- 不把工具输出或 AI 假设直接作为漏洞事实。
- `Candidate` 和 `Likely` 不能作为最终漏洞报告。
- `Needs Manual Review` 必须明确标注为人工复核项。
- `Validated` finding 必须有源码证据、验证证据、误报排除和公开漏洞关联。
- 不生成远程攻击、持久化、规避、提权或武器化 exploit 内容。
- 不使用“绝对未公开”表述；只能写“未在已配置公开数据源中发现匹配记录”。

### 6.4 License

本项目使用 MIT License。详见 `LICENSE`。
