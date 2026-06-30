# Agent 加载层级（L0–L4）

本文档定义 PVAS 中 **Agent 加载层级**（Load Tier）规范。加载层级控制**哪些文档与产物可被哪些角色读取**，并与 `core/manifest.yaml` 中的 `load_tier` 字段机械绑定。

**与 Finding 披露层级（D0–D4）的关系：** 加载层级约束**知识加载**；披露层级约束**漏洞结论的可报告范围**。二者独立但可在 manifest 中联合声明。

## 层级定义

| 层级 | 内容范围 | 典型读者 | Coordinator 可见 |
|------|----------|----------|------------------|
| **L0** | 技能入口与全局规则 | 所有 agent | **是** |
| **L1** | 阶段摘要、`*-summary.json`、stage 结论 | coordinator | **是** |
| **L2** | 当前 stage 的 workflow 细节、guides detail | 对应 subagent | **否**（须委派） |
| **L3** | 角色定义、选中 recipe、schema 名 | 对应 subagent | **否** |
| **L4** | 原始 tool log、全量源码、全部 packet | tool-runner、result-normalizer 等 | **禁止** |

### L0 — 入口层

- **读者：** coordinator 与所有 subagent。
- **Coordinator 可见：** 是。
- **用途：** 审计语义、状态机、全局约束的单一入口。
- **示例：**
  - `SKILL.md`
  - `AGENTS.md`

### L1 — 协调摘要层

- **读者：** coordinator（主读者）；subagent 通常不直接加载整份 L1 树。
- **Coordinator 可见：** 是。
- **用途：** 跨 stage 编排、进度判断、异常感知（含 `exception-index.json`）。
- **示例：**
  - `guides/index.json`（阶段 2 起；阶段 1 可由 workflow 摘要替代）
  - `audit-output/*/candidate-summary.json`
  - `audit-output/machine/exception-index.json`
  - `audit-output/machine/workflow-steps/*.json` 中的 step 结论

### L2 — Stage 工作流层

- **读者：** 执行当前 stage 的 subagent。
- **Coordinator 可见：** **否** — coordinator 仅通过 L1 摘要感知 stage 结果，不得加载 L2 全文。
- **用途：** 单 stage 的操作步骤、输入输出契约、失败行为。
- **示例（阶段 1）：**
  - `workflows/*.md`（阶段 2 拆分为 `guides/*.summary.md` + `guides/*.detail.md`）
- **示例（阶段 2）：**
  - `guides/00-intake.detail.md`
  - `guides/03-tool-scan.detail.md`

### L3 — 角色与 Playbook 层

- **读者：** 被委派的 specialist subagent。
- **Coordinator 可见：** **否**。
- **用途：** 角色职责、评审标准、按项目类型选中的审计 playbook。
- **示例：**
  - `agents/*.md`（如 `hypothesis-hunter.md`、`candidate-reviewer.md`）
  - `recipes/*.md`（按需加载）
  - schema 文件名引用（不加载全量 schema 正文除非角色需要）

### L4 — 原始与全量层

- **读者：** tool-runner、result-normalizer、packet 构建器等执行型 subagent。
- **Coordinator 可见：** **禁止** — manifest 与 `context_budget.py` 须拦截 coordinator task packet 中的 L4 路径。
- **用途：** 保留完整证据链，供下游归一化与验证；不得进入 coordinator 上下文。
- **示例：**
  - 原始 tool log（`audit-output/02-tools/raw/`）
  - 全量源码树、`all-files.txt`
  - 全部 candidate packet 原文（`audit-output/03-candidates/packets/`）
  - fuzz 原始输出

## Coordinator 上下文卫生（强制）

1. Coordinator **仅**读取 L0 + L1 声明的摘要产物。
2. 噪声工作（shell、扫描、packet 评审、源码切片）**必须**委派给 subagent。
3. L4 路径出现在 coordinator 任务包中时，Context Budget Guard 与 manifest gate **必须阻断**。
4. 被拒绝（Rejected）的 candidate 细节不得重新进入 coordinator 活跃上下文。

## 与 manifest 的绑定

`core/manifest.yaml` 为每个 artifact 声明 `load_tier`（L0–L4）。阶段 1 起，新增产物注册时必须显式指定层级；未声明者不得被 coordinator 默认加载。

## 参考

- Finding 披露层级：`core/disclosure/finding-levels.md`
- 全局 agent 规则：`AGENTS.md` § Parent-agent context hygiene
- 设计 spec：`docs/superpowers/specs/2026-06-30-pvas-layered-refactor-design.md` §3.3
