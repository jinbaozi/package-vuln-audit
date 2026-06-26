# 软件包漏洞审计流程门禁设计

**日期**：2026-06-26
**状态**：待用户审阅
**范围**：强化完整审计流程的 agent 编排、异常处理、传统工具执行、PoC 生命周期、中文主报告和质量门禁。

## 1. 背景

本项目已经具备完整的漏洞审计 Skill 结构：`SKILL.md`、10 个 workflow 文档、agent 定义、传统工具脚本、schema、双语模板、PoC 安全策略、公开漏洞关联，以及推荐的完整审计入口 `tools/enforced_audit_driver.py`。

现有方向是合理的，但执行模型仍有缺口：

- 文档要求的步骤可能被跳过，或只部分执行。
- 传统工具可以停留在 `failed`、`timeout`、`not-installed`，但流程仍继续产出“完整审计”结果。
- `semgrep` 目前更像 recommended 工具，而不是完整审计的强制基线。
- `Validated` finding 没有被严格绑定到“已成功执行”的本地 PoC 包。
- `Needs Manual Review` 需要成为一等输出，而不是隐藏在候选阶段。
- 人工审阅报告需要简体中文主入口，并提供完整汇总，避免审阅者逐个文件翻阅。

本设计不重建整条流水线，而是在现有架构上补强执行门禁。

## 2. 已确认决策

1. 采用现有架构，先完成流程门禁设计，再进入实施计划。
2. 保留 `tools/enforced_audit_driver.py` 作为唯一推荐的完整审计入口。
3. 根据项目画像生成“应跑工具矩阵”。
4. `semgrep` 对所有完整审计强制执行。
5. 工具超时、执行报错、缺失、输出异常或部分输出，都不能静默降级。
6. 只有项目画像证明工具不适用时，才允许标记 `not-applicable`。
7. 每个 `Validated` finding 必须有本地 PoC 包，并且 PoC 已成功执行。
8. `Needs Manual Review` 必须在阶段报告和最终汇总报告中展示。
9. `Needs Manual Review` 生成“人工验证计划和测试方法”，正式可执行 PoC 包只给 `Validated` finding。
10. 人读阶段报告和最终汇总报告默认简体中文；机器 JSON、schema、工具原始输出保持结构化原文。

## 3. 整体编排

`tools/enforced_audit_driver.py` 升级为阶段门禁控制器，而不只是脚本串联器。

每个阶段必须声明：

- 必需输入。
- 必需输出。
- 完成条件。
- 阻断条件。
- 可恢复异常条件。
- 人工复核出口。
- 可报告的限制。

阶段顺序保持现有 00-09：

1. 信息收集与范围确认。
2. 包画像分析。
3. recipe 与扫描范围选择。
4. 传统工具扫描。
5. AI 假设生成。
6. 候选归一化、排序和 packet 生成。
7. 候选评审。
8. 验证与 PoC 生成。
9. CVSS 评分。
10. 报告生成与渐进式披露。

驱动器必须阻止后续阶段把缺失或低质量的上游产物当作完整输入。

## 4. 统一异常模型

所有阶段统一使用四类状态：

- `recoverable`：可以重试或修复，例如超时、缺失但可安装的工具、临时非零退出、缺少用户提供的构建命令、本地规则集缺失。
- `blocked`：阶段不能安全继续，例如授权不清、目标范围不清、强制工具失败、`semgrep` 未成功执行、`Validated` finding 缺 PoC 执行结果、最终报告完整性失败。
- `not-applicable`：该步骤或工具确实不适合当前项目，且有包画像证据支撑。
- `manual-review`：证据有价值，但自动验证不足。该项不能被展示为已验证漏洞。

`failed`、`timeout`、`not-installed`、`malformed-output`、`partial-output` 只能是中间执行状态，不能成为完整审计中的最终降级理由。

## 5. 阶段控制模型

每个阶段按四段执行和检查。

### 5.1 Preflight

Preflight 判断阶段是否允许启动。

必查项包括：

- 授权和范围明确。
- 网络策略、构建权限、fuzz 权限明确。
- 上游必需产物存在，并通过 schema 校验。
- 加载候选 packet 前，Context Budget 在限制内。
- 生成工具矩阵前，包画像已存在。
- 执行传统工具前，工具矩阵已存在。

如果授权、目标范围、网络策略或构建权限不清，必须在运行工具前阻断。

### 5.2 Execution

Execution 必须记录执行尝试和恢复动作。

工具和验证命令需要记录：

- 命令。
- 工作目录。
- 超时设置。
- 开始/结束时间或耗时。
- 退出码。
- 状态。
- 输出产物路径。
- 失败摘要。
- 恢复动作。
- 最终决策。

恢复动作可以包括：

- 重试。
- 在策略允许范围内扩大超时。
- 拆分扫描范围。
- 使用本地规则替代依赖网络的规则。
- 进入 `tool-install-assistant`。
- 请求用户补充构建或运行参数。

### 5.3 Postflight

Postflight 判断产物是否真正可用，而不只是文件存在。

必查项包括：

- schema 校验。
- 必需字段的语义校验。
- 占位内容检测。
- 源码证据完整性。
- 工具输出可解析性。
- PoC 安全性和执行结果。
- 人工验证计划完整性。
- 人读报告语言策略。

### 5.4 Report Gate

Report Gate 在最终输出前阻断缺失、误导或不完整内容。

最终汇总报告必须展示：

- 已完成阶段。
- 被阻断阶段。
- 工具恢复决策。
- `not-applicable` 工具及理由。
- `Needs Manual Review` 项和后续动作。
- `Validated` findings 和 PoC 执行状态。
- 剩余风险和人工跟进清单。

## 6. 传统工具矩阵

包画像阶段新增产物：

`audit-output/01-profile/required-tools-matrix.json`

每个工具条目包含：

- 工具名和二进制名。
- 适用性：`mandatory`、`profile-required`、`recommended`、`optional`、`not-applicable`。
- 项目画像证据。
- 命令模板。
- 超时设置。
- 重试策略。
- 允许的恢复动作。
- 是否允许降级继续。
- 最终状态。
- 最终决策理由。

工具矩阵由以下信息生成：

- 包画像。
- 已选 recipe。
- 语言和构建系统。
- 输入面。
- 用户约束。
- 工具目录。

矩阵内每个工具最终只能是：

- `completed`。
- `blocked`。
- `not-applicable`。

完整审计不能以 `failed`、`timeout`、`not-installed`、`malformed-output`、`partial-output` 作为计划内工具的最终状态。

## 7. `semgrep` 强制策略

`semgrep` 是所有完整审计的强制工具。

如果 `semgrep` 缺失：

1. 写入 `environment-check.json`。
2. 生成或更新安装计划。
3. 进入 `tool-install-assistant`。
4. 仍不可用则阻断。

如果 `semgrep` 超时：

1. 记录超时尝试。
2. 在策略限制内扩大超时，或拆分扫描范围。
3. 如果规则需要网络且网络不允许，切换本地规则或要求用户提供规则集。
4. 仍没有成功执行结果则阻断。

如果 `semgrep` 非零退出或输出格式异常：

1. 保留原始输出。
2. 判断是配置、规则、解析还是目标代码问题。
3. 安全时使用修正后的本地命令重试。
4. 仍失败则阻断。

`PVAS_SKIP_OPTIONAL` 或类似 optional 工具跳过开关不得跳过 `semgrep`。

## 8. 工具执行产物

传统工具阶段写入：

- `audit-output/02-tools/tool-summary.json`
- `audit-output/02-tools/tool-execution-attempts.json`
- `audit-output/02-tools/raw/*`

`tool-summary.json` 保存每个工具的最终简明状态。

`tool-execution-attempts.json` 保存所有尝试和恢复动作，是判断某个工具为什么完成、阻断或不适用的权威审计轨迹。

原始日志仍保留在 `raw/`，默认不进入父 agent 上下文。

## 9. 候选与人工复核处理

候选评审沿用现有状态机，但把 `Needs Manual Review` 作为一等输出。

候选评审结果包括：

- `Rejected`：证据不足以继续。
- `Candidate`：有可能但证据弱或不完整。
- `Likely`：足够强，值得进入验证。
- `Needs Manual Review`：证据有价值，但自动验证受阻或不足。

`Needs Manual Review` 必须包含：

- 源码证据摘要。
- 候选原因。
- 自动验证未完成的原因。
- 缺失前提。
- 建议测试方法。
- 预期可观察信号。
- 安全注意事项。
- 下一步人工动作。

这些项目不是最终漏洞，不能获得最终 CVSS 分数；如需严重性，只能标记为 provisional。

## 10. Validated PoC 生命周期

`Validated` 必须有成功的本地复现。

每个 `Validated` finding 都必须有 PoC 目录：

`audit-output/04-validation/poc-tests/FINDING-*/`

必需文件：

- `reproduce.sh`
- 测试输入或本地输入生成脚本。
- `input-description.md`
- `expected-vulnerable.txt`
- `expected-fixed.txt`
- `README.md`
- `poc-manifest.json`
- `poc-run-result.json`

PoC 包必须满足：

- 仅用于本地验证。
- 强制使用 timeout。
- 不攻击远程目标。
- 不使用网络工具。
- 不使用 `sudo`，不写系统目录。
- 不包含持久化、规避或武器化行为。
- 记录测试输入 hash。
- 记录 vulnerable/fixed 预期行为。
- 记录实际执行结果。

PoC 生成、安全检查或执行失败时，该项不能进入 `Validated`。

## 11. 人工验证计划

`Needs Manual Review` 生成的是人工验证计划，不是正式 PoC 包。

必需文件：

- `audit-output/04-validation/manual-review/MANUAL-*/manual-validation-plan.md`
- `audit-output/04-validation/manual-review/MANUAL-*/manual-validation-plan.json`

计划内容包括：

- 候选 ID 或类 finding ID。
- 源码证据。
- 复现假设。
- 所需环境。
- 建议构建命令。
- 建议测试命令。
- 输入形态或数据要求。
- 预期可观察信号。
- 缺失前提或阻断原因。
- 安全限制。
- 升级为 `Validated` 的条件。

如果人工后续验证成功，该项才能升级为 `Validated`，并生成正式 PoC 包。

## 12. 中文主报告

人读报告中文优先：

- workflow step Markdown 摘要默认简体中文。
- 内部报告默认简体中文。
- 中文报告树里的 finding 报告是人工审阅主入口。
- 最终汇总报告默认简体中文。

机器产物保持结构化：

- JSON 面向机器处理。
- schema 不变。
- 工具原始输出保留原文。
- 英文输出仍可用于披露或跨团队协作，但不是人工审阅主入口。

## 13. 最终汇总报告

最终汇总报告必须让审阅者无需打开每个阶段文件，也能理解审计结果。

内容包括：

- 执行摘要。
- 审计范围和授权。
- 包画像和 selected recipes。
- 环境和工具矩阵状态。
- `semgrep` 执行状态。
- 候选漏斗。
- `Validated Findings` 表。
- `Needs Manual Review` 表。
- PoC 产物索引。
- 人工验证计划索引。
- 公开漏洞关联摘要。
- 已验证 finding 的 CVSS 摘要。
- 00-09 阶段结论。
- 阻断问题。
- 剩余风险。
- 人工跟进清单。

报告不得把候选项或人工复核项呈现为已确认漏洞。

## 14. 质量门禁

质量检查同时包含 schema 校验和语义校验。

### 14.1 产物完整性

必需产物包括：

- intake 范围和元数据。
- 包画像。
- 应跑工具矩阵。
- 环境检查。
- 需要时的工具安装计划。
- 工具摘要。
- 工具执行尝试记录。
- raw output 路径索引。
- 候选摘要。
- 候选评审结果。
- 验证摘要。
- 已验证 finding 的 PoC 包。
- 人工复核项的人工验证计划。
- 已验证 finding 的 CVSS 产物。
- 已验证 finding 的公开漏洞关联。
- 中文最终汇总报告。

### 14.2 语义完整性

以下内容会导致校验失败：

- 待办标记。
- 未定事项标记。
- 占位内容标记。
- 必需字段为空。
- 必需叙述字段中出现无意义占位值，例如 `—` 或 `?`。
- 缺 source path。
- 适用时缺 function 或 line range。
- 缺 input source。
- 缺 sink。
- 缺 source-to-sink path。
- 缺 reachability argument。
- `Validated` 缺 validation evidence。
- 最终 finding 缺 false-positive exclusion。

### 14.3 证据链

每个 `Validated` finding 必须包含：

- source path。
- function。
- line range。
- input source。
- sink。
- source-to-sink path。
- reachability。
- validation evidence。
- PoC execution result。
- false-positive exclusion。
- fix recommendation。
- CVSS rationale。
- disclosure level。

### 14.4 报告准入

最终报告阶段在以下情况阻断：

- 任一计划内 mandatory 工具缺最终决策。
- `semgrep` 未完成。
- 任一 `Validated` finding 缺通过验证的 PoC 执行结果。
- 任一 `Needs Manual Review` 项缺人工验证计划。
- 已验证 finding 缺公开漏洞关联。
- 必需中文报告缺失。
- 必需报告含占位或误导内容。

## 15. 实施边界

本设计不做完整流水线重写。

预期实施范围：

- 强化 `tools/enforced_audit_driver.py`。
- 新增或扩展工具矩阵生成。
- 新增或扩展工具执行尝试记录。
- 修正 PoC 输出路径和状态判断。
- 增加 PoC 执行结果校验。
- 增加人工验证计划生成。
- 强化报告完整性校验。
- 强化最终汇总报告生成。
- 更新 workflow 和 reference 文档。
- 增加聚焦测试。

不在本次范围内：

- 替换整个 workflow engine。
- 改变渐进式披露安全模型。
- 给未验证问题生成正式 PoC 包。
- 把机器 JSON 或工具原始输出翻译成中文。

## 16. 验收标准

1. 如果 `semgrep` 缺失、超时且恢复失败、非零退出且恢复失败、或输出不可用，完整审计不能通过。
2. 包画像阶段产出应跑工具矩阵。
3. 每个计划内矩阵工具最终状态为 `completed`、`blocked` 或 `not-applicable`。
4. 工具失败会记录尝试和恢复动作。
5. `not-applicable` 决策包含项目画像证据。
6. 每个 `Validated` finding 都有 `audit-output/04-validation/poc-tests/FINDING-*/` 下的 PoC 包。
7. 每个 `Validated` finding 都有 `poc-run-result.json`，证明本地执行成功。
8. 每个 `Needs Manual Review` 项都出现在阶段报告和最终汇总报告中。
9. 每个 `Needs Manual Review` 项都有 `manual-validation-plan.md` 和 `manual-validation-plan.json`。
10. 最终报告明确区分已验证漏洞和人工复核项。
11. 最终汇总报告为简体中文，并聚合所有主要阶段结论。
12. 必需报告字段中出现占位内容会导致报告校验失败。
13. 现有测试继续通过。
14. 新增测试覆盖 `semgrep` 强制执行、工具超时阻断、工具不适用决策、PoC 执行结果、人工验证计划报告展示、最终汇总完整性。

## 17. 风险与缓解

风险：强制 `semgrep` 会在受限环境中阻断审计。

缓解：提供受控安装助手、离线 bundle、本地规则集和明确的 blocked 状态，而不是静默降级。

风险：人工复核项可能被误认为漏洞。

缓解：在报告中独立分区，明确标记，不给最终 CVSS。

风险：PoC 执行要求会让一些真实但难复现的问题无法进入 `Validated`。

缓解：保留为 `Needs Manual Review`，并提供详细人工验证计划，直到具备稳定复现。

风险：强报告门禁会影响局部探索式审计。

缓解：这些门禁只用于完整审计；局部审计必须标记为 partial，不能产出完整审计最终报告。

## 18. 下一步

用户审阅通过后，进入实施计划编写，将工作拆成小步：

1. 工具矩阵和 `semgrep` 门禁。
2. 工具执行尝试审计轨迹。
3. PoC 执行结果门禁。
4. 人工验证计划产物。
5. 中文最终汇总和报告完整性校验。
6. workflow 与 reference 文档更新。
7. 聚焦测试覆盖。
