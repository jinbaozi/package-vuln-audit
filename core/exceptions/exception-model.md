# 统一异常模型

本文档汇总 PVAS complete audit 的**统一异常处理**规范，继承并扩展 [`docs/superpowers/specs/2026-06-26-audit-workflow-gates-design.md`](../../docs/superpowers/specs/2026-06-26-audit-workflow-gates-design.md) §4–§9，并与分层架构下的 mechanical gate 对齐。

**目标：** 每个 driver stage 对异常的处理可预测、可审计、可汇总；coordinator **仅**通过 L1 的 `exception-index.json` 感知异常，**不**读取 L4 原始日志。

## 四类异常（canonical）

| 类型 | 含义 | 典型场景 | complete audit 最终态 |
|------|------|----------|----------------------|
| **`recoverable`** | 可重试或经用户/安装助手修复 | 工具 timeout、可安装缺失、临时非零退出 | 必须解析为 `completed` 或 `blocked`，**不得**长期停留 |
| **`blocked`** | 不可安全继续 | semgrep 未成功、Validated 无 PoC、报告完整性失败、intake 不清 | **halt pipeline** |
| **`not-applicable`** | 有画像证据的不适用 | npm 对非 Node 项目 | 记录理由，**继续** |
| **`manual-review`** | 证据有价值但无法自动验证 | Needs Manual Review finding | **一等输出**，**不得**标为 Validated |

### 中间态（仅 Execution 记录）

以下状态**只能**作为 Execution 阶段的中间执行状态，**不得**作为 complete audit 的最终降级理由：

- `failed`
- `timeout`
- `not-installed`
- `malformed-output`
- `partial-output`

Execution 结束时，中间态必须被归类为四类 canonical 异常之一，并写入 step 结论与 `exception-index.json`。

## 四段控制模型

每个 **driver `step_id`** 在 [`stage-policies.yaml`](stage-policies.yaml) 中声明 Preflight / Execution / Postflight / Report Gate 检查项；driver 按序执行，并将 step 结论写入 `audit-output/machine/workflow-steps/{step_id}.json`。

```text
Preflight   → 上游产物、schema、授权/预算、manifest 指针
Execution   → 命令执行 + tool-execution-attempts.json（如适用）
Postflight  → 语义校验、占位符检测、PoC/报告 gate
Report Gate → 最终 exception-index +（阶段 2 起）final-summary 异常章节
```

| 阶段 | 职责 | 阻断行为 |
|------|------|----------|
| **Preflight** | 授权、范围、上游 artifact/schema、context budget | 不清 → `blocked` |
| **Execution** | 运行命令，记录 attempts 与 recovery_actions | 中间态须收敛为四类异常 |
| **Postflight** | 语义与完整性校验（tool-summary、PoC、报告等） | mandatory 失败 → `blocked` |
| **Report Gate** | 汇总 `exception-index.json`，计算 `pipeline_decision` | 任一 mandatory stage `blocked` → `halt` |

### pipeline_decision 规则（摘要）

- 任一 mandatory stage 最终为 `blocked` → `pipeline_decision: halt`
- 仅 optional / recoverable 且已解决 → `continue`
- 已知跳过（如无 `--public-records`）→ 记入 `partial_stages`，**不**记为 `blocked`

## 机械绑定产物

### `stage-policies.yaml`

- **路径：** `core/exceptions/stage-policies.yaml`
- **用途：** 每个 driver `step_id` 的 preflight / execution / postflight / report_gate 清单。
- **消费者：** driver preflight/postflight（阶段 2 起由 `runtime/gates/run_postflight.py` 统一调度）；阶段 1 为声明性骨架。

### `exception-index.json`

- **路径：** `audit-output/machine/exception-index.json`
- **Load tier：** L1（coordinator 可读）
- **Schema：** `schemas/exception-index.schema.json`（阶段 2 迁至 `core/contracts/schemas/`）
- **写入：** `tools/aggregate_exceptions.py` 在各 stage 后增量合并；Report Gate 前计算最终 `pipeline_decision`
- **字段摘要：**
  - `summary`：`blocked_count`、`recoverable_count`、`not_applicable_count`、`manual_review_count`
  - `events[]`：`step_id`、`class`、`code`、`message`、`recovery_actions`、`final_decision`
  - `halted_stages[]`、`partial_stages[]`：元素均为 **driver `step_id`**（见 spec §3.4）

## Agent 侧异常（摘要）

| 场景 | 异常类 | 处理 |
|------|--------|------|
| coordinator 读取 L4 路径 | — | manifest + context_budget **block** |
| candidate packet 超 budget | `recoverable` | `split-required`；写入 exception-index |
| subagent 无 evidence 升级 Validated | `blocked` | validator / reviewer 拒绝 |
| Needs Manual Review | `manual-review` | 生成 manual-validation-plan；Report Gate 展示 |

Agent 编排步骤（如 `05-candidate-review`、`06-validation`）不由 driver 机械 `write_step`，但其结论经 L1 summary 汇入 `exception-index`（见设计 spec §11.10）。

## 阶段交付说明

| 阶段 | 异常能力 |
|------|----------|
| **阶段 1** | 异常模型文档 + `stage-policies.yaml` 骨架 + `exception-index.schema.json` + aggregate/validate 工具 |
| **阶段 2** | driver gate 统一 fail-closed、`run_postflight.py`、final-summary 异常章节 |
| **阶段 3** | Semgrep 专用恢复链（timeout / offline fallback / split-scope） |

## 参考

- Stage 策略清单：[`stage-policies.yaml`](stage-policies.yaml)
- Canonical `step_id` 对照：设计 spec §3.4
- 各 stage 传播规则：设计 spec §11.5
- 工作流门禁设计：[`2026-06-26-audit-workflow-gates-design.md`](../../docs/superpowers/specs/2026-06-26-audit-workflow-gates-design.md)
