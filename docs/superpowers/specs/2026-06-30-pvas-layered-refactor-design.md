# PVAS 分层架构与 Semgrep 联网策略设计

**日期**：2026-06-30  
**状态**：待用户审阅  
**范围**：全栈分层重构（core / runtime / guides / adapters）、Agent 加载层级（L0–L4）与 Finding 披露层级（D0–D4）双层 manifest 映射、Semgrep Registry 联网扫描策略。

## 1. 背景

`package-vuln-audit-skill`（PVAS）已具备完整的审计流水线：10 个 workflow、`agents/` 角色定义、`tools/` 机械门禁、`schemas/` 契约、`audit-output/` 分阶段产物，以及 Context Budget Guard v2.1 与 D0–D4 渐进式披露策略。

近期已完成一轮冗余简化（`pvas_io`、`report_render`、`strict_env_gate` 等共享模块），但存在结构性问题：

| 问题 | 现状 |
|------|------|
| 目录扁平 | `workflows/`、`agents/`、`tools/` 并列，无强制分层 |
| 披露未机械绑定 | D0–D4 与 L-tier 约束写在 markdown，目录不 enforce |
| Coordinator 污染风险 | 无 manifest 索引，agent 可能误读 L4 原始日志 |
| Semgrep 策略不完整 | matrix 使用 `--config auto`，但 workflow 默认禁止联网，Registry 规则可能拉取失败 |
| 网络门禁分裂 | driver 的 `--allow-network` 仅服务公网漏洞关联，未覆盖 tool-scan |

本设计在**不重建审计语义**的前提下，引入 manifest 驱动的分层架构，并分三阶段交付。

## 2. 已确认决策

1. **架构方案**：Manifest 驱动的分层单体（方案 A），不用 stage 垂直切片或 Python 包化。
2. **重构边界**：全栈分层（core / runtime / guides / adapters），允许调整目录，保留 adapter 安装兼容。
3. **披露落地**：双层映射 — Agent 加载层级 L0–L4 + Finding 披露层级 D0–D4，`core/manifest.yaml` 显式关联。
4. **Semgrep 联网**：显式 `--allow-network` 后使用 Semgrep Registry（`--config auto` / `p/ci` 等）；默认 offline。
5. **交付节奏**：
   - **阶段 1**：manifest + 披露骨架（不迁移物理路径）
   - **阶段 2**：迁移 `tools/` → `runtime/`，`workflows/` → `guides/`
   - **阶段 3**：Semgrep 联网策略与离线规则包

## 3. 目标架构

### 3.1 分层职责

```text
core/       契约、策略、manifest（零执行副作用）
runtime/    机械执行：lib、gates、stages、driver
guides/     AI 可读 workflow（summary/detail 分离）
agents/     canonical 角色定义
recipes/    L3 按需加载的审计 playbook
adapters/   平台薄包装 + 兼容 shim
```

**依赖方向（单向）：**

```text
adapters → guides/agents → core/manifest
runtime  → core/contracts
runtime  ↛ guides（runtime 不 import markdown）
coordinator ↛ runtime/stages 源码（只读 summary JSON）
```

### 3.2 终态目录结构

```text
package-vuln-audit-skill/
├── SKILL.md                          # L0 入口（路径不变）
├── AGENTS.md                         # L0
│
├── core/
│   ├── manifest.yaml                 # L/D 双层注册表 + stage 索引
│   ├── state-machine.md              # ← 从 SKILL.md 抽取或引用
│   ├── contracts/schemas/            # ← schemas/ 迁入
│   ├── policies/                     # ← references/ 迁入
│   └── disclosure/
│       ├── load-tiers.md             # L0–L4 定义
│       └── finding-levels.md         # D0–D4 定义
│
├── runtime/
│   ├── lib/                          # pvas_io, report_render, tool_catalog…
│   ├── gates/                        # strict_env_gate, workflow_contract, validate_manifest
│   ├── stages/
│   │   ├── 00-environment/
│   │   ├── 01-profile/
│   │   ├── 02-tools/
│   │   │   └── semgrep/              # 阶段 3：strategy + offline rules
│   │   ├── 03-candidates/
│   │   ├── 04-validation/
│   │   ├── 05-findings/
│   │   ├── 06-report/
│   │   └── 07-disclosure/
│   └── driver.py                     # ← enforced_audit_driver.py
│
├── guides/
│   ├── index.json                    # L1：stage 摘要 + manifest 指针
│   ├── 00-intake.summary.md
│   ├── 00-intake.detail.md
│   └── …                             # ← workflows/ 拆分迁入
│
├── agents/                           # canonical（不变）
├── recipes/                          # L3 按需
├── templates/
├── adapters/
│   └── _compat/                      # 旧 tools/*.py 转发（过渡期）
│
├── tests/
└── audit-output/                     # 输出树契约不变
```

### 3.3 双层映射

#### Agent 加载层级（L0–L4）

| 层级 | 内容 | 读者 | Coordinator 可见 |
|------|------|------|------------------|
| L0 | `SKILL.md`、`AGENTS.md` | 所有 agent | 是 |
| L1 | `guides/index.json`、`*-summary.json`、stage 结论 | coordinator | 是 |
| L2 | `guides/*.detail.md`、当前 stage 的 workflow 细节 | 对应 subagent | 否（委派） |
| L3 | `agents/*.md`、选中 `recipes/`、schema 名 | 对应 subagent | 否 |
| L4 | 原始 tool log、全量 source、全部 packet | tool-runner 等 | **禁止** |

#### Finding 披露层级（D0–D4）

| 层级 | 含义 | 典型产物路径 |
|------|------|-------------|
| D0 | Internal Candidate | `audit-output/03-candidates/` |
| D1 | Internal Likely | 候选列表（内部） |
| D2 | Internal Validated | `06-report/`、`05-findings/` |
| D3 | Maintainer Private | `07-disclosure/zh-CN\|en-US/maintainer-*` |
| D4 | Public After Fix | `07-disclosure/.../public-advisory-draft.md` |

`core/manifest.yaml` 为每个 artifact 声明 `{ load_tier, disclosure_tier, stage, schema, path_pattern }`。

## 4. core/manifest.yaml 设计

### 4.1 顶层结构

```yaml
schema_version: "1.0"
skill_version: "0.11.0"  # 重构完成后 bump

load_tiers:
  L0: { max_tokens_hint: 8000, readers: [coordinator, all] }
  L1: { max_tokens_hint: 40000, readers: [coordinator] }
  L2: { max_tokens_hint: 80000, readers: [subagent] }
  L3: { max_tokens_hint: 120000, readers: [subagent] }
  L4: { forbidden_for: [coordinator], readers: [tool-runner, result-normalizer] }

disclosure_tiers:
  D0: { reportable: false }
  D1: { reportable: false }
  D2: { reportable: internal }
  D3: { reportable: maintainer }
  D4: { reportable: public_after_fix }

stages:
  - id: "00-intake"
    guide_summary: guides/00-intake.summary.md
    guide_detail: guides/00-intake.detail.md
    outputs:
      - path: audit-output/00-intake/scope.md
        load_tier: L1
        disclosure_tier: null

artifacts:
  - id: tool-summary
    path_pattern: audit-output/02-tools/tool-summary.json
    load_tier: L1
    schema: tool-summary.schema.json
    stage: "02-tools"
```

### 4.2 门禁集成

- `runtime/gates/validate_manifest.py`：校验 manifest 条目对应的文件/schema 存在；CI 与 driver preflight 调用。
- `enforce_workflow_contract.py` 扩展：manifest 与 `REQUIRED_SCHEMAS` 单源（消除 drift）。
- `context_budget.py` 扩展：读取 manifest 的 `load_tier`，拒绝 coordinator 任务包含 L4 artifact。

## 5. Semgrep 联网策略（阶段 3）

### 5.1 现状

- `tools/generate_tool_matrix.py`：`semgrep scan --config auto --json`
- `workflows/03-tool-scan.md`：默认 no network
- complete audit：`semgrep` applicability = `mandatory`

### 5.2 目标行为

| network_mode | semgrep config | 行为 |
|--------------|----------------|------|
| `offline`（默认） | `runtime/stages/02-tools/semgrep/rules/baseline/` | 使用 bundled 离线规则；写入 `rules_source: offline-bundle` |
| `online-approved` + `--allow-network` | `auto` 或 profile 选择 `p/ci` | Registry 拉取；写入 `rules_source: semgrep-registry` |
| strict + offline + semgrep mandatory | — | 阻断或需 `PVAS_ALLOW_DEGRADED=1` |

### 5.3 新增字段（tool-summary / matrix）

```json
{
  "name": "semgrep",
  "status": "completed",
  "rules_source": "semgrep-registry",
  "rules_config": "auto",
  "network_used": true
}
```

### 5.4 统一网络门禁

扩展 `enforced_audit_driver` / `run_tools.sh`：

- `--allow-network` 同时授权：Semgrep Registry、公网漏洞 fetch（已有）、install-assistant online-approved（已有策略）
- intake 记录 `network_policy` 与本次实际 `network_used_tools[]`

### 5.5 离线规则包

- 路径：`runtime/stages/02-tools/semgrep/rules/baseline/`
- 来源：Semgrep 官方 rules 子集（security-audit、cwe-top-25 等）定期 sync，hash 记录在 manifest
- 与 `offline-bundle/` 策略一致：hash 校验 + 版本 pin

## 6. 分阶段交付

### 阶段 1：Manifest + 披露骨架（本阶段实施入口）

**目标**：建立注册表与 L/D 定义，**不移动**现有 `tools/`、`workflows/` 物理路径。

| 交付物 | 说明 |
|--------|------|
| `core/manifest.yaml` | 注册现有 schemas、workflows、tools、audit-output 路径 |
| `core/disclosure/load-tiers.md` | L0–L4 规范 |
| `core/disclosure/finding-levels.md` | D0–D4 规范 |
| `guides/index.json` | 从 `workflows/*.md` 生成的 L1 摘要索引 |
| `runtime/gates/validate_manifest.py` | manifest 校验 gate |
| `tests/test_manifest.py` | manifest 与磁盘一致性测试 |
| `SKILL.md` 更新 | 指向 manifest 与 L-tier 加载规则 |

**完成标准：**

- `./run-tests.sh` 通过
- `validate_manifest.py` 在 driver preflight 可选启用（默认 warn，阶段 2 改 block）

### 阶段 2：物理迁移

| 自 | 至 |
|----|-----|
| `schemas/` | `core/contracts/schemas/` |
| `references/` | `core/policies/` |
| `tools/*.py` | `runtime/lib/` + `runtime/stages/*/` |
| `tools/enforced_audit_driver.py` | `runtime/driver.py` |
| `workflows/*.md` | `guides/*.summary.md` + `*.detail.md` |
| `tools/` shell | `runtime/stages/*/scripts/` |

**兼容：**

- `adapters/_compat/` 保留 `tools/<name>.py` 转发至 `runtime/`
- `run-tests.sh` 与 adapter INSTALL 文档同步更新
- 至少保留 1 个版本的 shim

### 阶段 3：Semgrep 策略

| 交付物 | 说明 |
|--------|------|
| `runtime/stages/02-tools/semgrep/strategy.py` | 按 network_mode + profile 选择 config |
| `runtime/stages/02-tools/semgrep/rules/baseline/` | 离线规则 bundle |
| `generate_tool_matrix.py` 迁移版 | 调用 strategy |
| driver `--allow-network` 扩展 | 统一 tool-scan 网络授权 |
| 测试 | offline/online/strict 三场景 |

## 7. 模块化原则

| 模块 | 内聚职责 | 对外接口 |
|------|----------|----------|
| `core/manifest` | 注册表、L/D 映射 | YAML + validate CLI |
| `core/contracts` | JSON Schema | schema 文件路径 |
| `runtime/lib` | I/O、渲染、catalog | Python 函数 |
| `runtime/gates` | 门禁 | CLI exit code + JSON |
| `runtime/stages/*` | 单 stage 工具 | CLI |
| `runtime/driver` | 编排 | CLI |
| `guides/*` | AI 指令 | markdown + index.json |
| `adapters/*` | 平台差异 | thin-ref + install |

**禁止：**

- runtime 模块 import guides markdown
- coordinator task packet 包含 L4 artifact 路径（manifest gate 拦截）
- 未授权网络下静默使用 `--config auto`

## 8. 测试策略

| 阶段 | 测试 |
|------|------|
| 1 | `test_manifest.py`：条目存在、L-tier 合法、无 orphan schema |
| 1 | `test_context_budget` 扩展：coordinator 含 L4 路径 → block |
| 2 | 全量 `run-tests.sh` + adapter install 冒烟 |
| 3 | semgrep offline bundle 扫描 toy project；online mock（或 skip if no network） |

## 9. 风险与缓解

| 风险 | 缓解 |
|------|------|
| adapter 安装路径断裂 | `_compat/` shim + INSTALL 双路径文档 |
| manifest 与代码 drift | CI gate + test_manifest |
| offline semgrep 规则过时 | manifest 记录 rules bundle version + sync 脚本 |
| 阶段 2 大范围移动 | 分 stage 子 PR，每步 run-tests |

## 10. 非目标

- 合并 `publish_bilingual_reports` 与 `generate_final_report` 为单一工具
- 引入 pytest 或第三方 Python 依赖
- Semgrep Cloud/App API（需 token 的 D 方案）
- 本阶段修改 `audit-output/` 阶段前缀或 finding state machine 语义

## 11. 下一步

用户审阅本 spec 通过后，invoke **writing-plans** 生成阶段 1 实现计划（`docs/superpowers/plans/2026-06-30-pvas-layered-refactor-phase1.md`）。
