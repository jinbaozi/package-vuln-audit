# Finding 披露层级（D0–D4）

本文档定义 PVAS **Finding 披露层级**（Disclosure Tier）规范。披露层级控制**漏洞候选与结论的可报告范围**，并与 `core/manifest.yaml` 中的 `disclosure_tier` 字段机械绑定。

**与 Agent 加载层级（L0–L4）的关系：** 披露层级描述**结论对外可见性**；加载层级描述**文档谁可读**。例如 `ranked-candidates.json` 中 `Likely` 条目为 D1（内部），但其 machine JSON 摘要可能以 L1 供 coordinator 读取。

## 层级定义

| 层级 | 含义 | 可写入最终报告 | 典型产物路径 |
|------|------|----------------|-------------|
| **D0** | Internal Candidate | 否 | `audit-output/03-candidates/` |
| **D1** | Internal Likely | 否（仅内部列表） | 见下文 D1 专节 |
| **D2** | Internal Validated | 是（内部已验证） | `audit-output/05-findings/`、`audit-output/06-report/` |
| **D3** | Maintainer Private Disclosure | 是（维护者私密） | `audit-output/07-disclosure/zh-CN/`、`audit-output/07-disclosure/en-US/` 下 `maintainer-*` |
| **D4** | Public Advisory After Fix | 是（修复后公开） | `audit-output/07-disclosure/.../public-advisory-draft.md` |

## 各层级说明

### D0 — Internal Candidate

- **状态机对应：** `Candidate`（及上游 `T-CAND` / `A-CAND` / `F-CAND`）。
- **含义：** 工具命中或 AI 假设经评审后仍为候选，**不得**表述为已确认漏洞。
- **典型路径：**
  - `audit-output/03-candidates/raw-candidates.json`
  - `audit-output/03-candidates/packets/`
  - `audit-output/03-candidates/candidate-summary.json` 中 state=`Candidate` 的条目

### D1 — Internal Likely

- **状态机对应：** `Likely`。
- **含义：** 评审后具备较强证据但仍未验证；**仅**允许出现在内部候选列表，**不得**进入对外报告或 maintainer/public 草稿。
- **权威产物路径：**

  **`audit-output/03-candidates/ranked-candidates.json`** 中 **`state` = `Likely`** 的条目（内部排序列表，非最终 finding）。

- **说明：** coordinator 可通过 L1 的 `candidate-summary.json` 感知 Likely 计数，但不得将 D1 条目升格为漏洞结论。

### D2 — Internal Validated

- **状态机对应：** `Validated`。
- **含义：** 经 validator 确认、具备完整证据链的内部已验证结论。
- **典型路径：**
  - `audit-output/05-findings/`（finding JSON、CVSS、关联结果）
  - `audit-output/06-report/`（machine / zh-CN / en-US 报告）
  - `audit-output/04-validation/poc-tests/FINDING-*/`（PoC 仅服务于 D2 Validated，本地复现）

### D3 — Maintainer Private Disclosure

- **含义：** 面向软件维护者的私密披露材料；未获授权不得公开。
- **典型路径：**
  - `audit-output/07-disclosure/zh-CN/maintainer-*.md`
  - `audit-output/07-disclosure/en-US/maintainer-*.md`

### D4 — Public Advisory After Fix

- **含义：** 修复完成并协调后的公开 advisory 草稿；**仅**在 disclosure level 明确允许时使用。
- **典型路径：**
  - `audit-output/07-disclosure/zh-CN/public-advisory-draft.md`
  - `audit-output/07-disclosure/en-US/public-advisory-draft.md`

## Needs Manual Review

- **状态机对应：** `Needs Manual Review`。
- **披露处理：** 不属于 D2 Validated；可在内部报告与 Report Gate 中作为**一等输出**展示，但**不得**标为已验证漏洞。
- **典型路径：**
  - `audit-output/04-validation/manual-review/`
  - `validation-summary.json` 中相应条目

## 报告门禁（摘要）

1. 最终报告中**仅**允许出现 **D2（Validated）** 与明确标记的 **Needs Manual Review** 条目。
2. **D0 / D1** 不得出现在 maintainer 或 public 披露草稿中。
3. **D4** 材料在未达披露协调前不得生成或发布。
4. PoC 可执行包**仅**为 D2 Validated finding 生成（见 `references/poc-reproducer-policy.md`）。

## 与 manifest 的绑定

`core/manifest.yaml` 的 `disclosure_tiers` 与 `artifacts[].disclosure_tier` 声明每个产物的披露级别。`null` 表示非 finding 产物（如 intake、tool-summary）。

## 参考

- Agent 加载层级：`core/disclosure/load-tiers.md`
- 渐进式披露策略：`references/disclosure-policy.md`、`AGENTS.md`
- 设计 spec：`docs/superpowers/specs/2026-06-30-pvas-layered-refactor-design.md` §3.3
