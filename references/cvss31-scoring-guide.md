# CVSS 3.1 Scoring Guide

PVAS 默认使用 **CVSS v3.1** Base Score。向量必须以 `CVSS:3.1/` 开头，包含 8 个 Base Metric。评分与严重度映射与 [cvssjs](https://sh1yan.top/cvssjs/) 对齐；产出 vector 与 rationale 后，**禁止手算分数**，须用 `tools/cvss31_calculator.py` 计算并校验。

## Status rules

| Finding status | CVSS `status` | Notes |
|---|---|---|
| Likely | `provisional` | 可给 provisional 分数与向量；不得当作最终报告定稿分数。 |
| Validated | `final` | 须含完整 vector、base_score、severity、rationale、uncertainties（如有）。 |
| Candidate / Rejected | — | 不得分配正式 CVSS 分数。 |

## Base metrics（8 项）

| Metric | 中文 | 取值 | 说明 |
|---|---|---|---|
| **AV** | 攻击向量 | N / A / L / P | **N** 网络；**A** 相邻网络；**L** 本地；**P** 物理接触。 |
| **AC** | 攻击复杂度 | L / H | **L** 低（条件易满足）；**H** 高（需额外条件或稀有状态）。 |
| **PR** | 所需权限 | N / L / H | **N** 无；**L** 低权限；**H** 高/管理员权限。Scope Changed 时使用 PR 的 Changed 权重表。 |
| **UI** | 用户交互 | N / R | **N** 无需用户参与；**R** 需用户主动或被动配合。 |
| **S** | 影响范围 | U / C | **U** 不变（仅影响漏洞组件）；**C** 改变（可波及其他组件/信任边界）。 |
| **C** | 机密性影响 | N / L / H | **N** 无；**L** 低；**H** 高。 |
| **I** | 完整性影响 | N / L / H | **N** 无；**L** 低；**H** 高。 |
| **A** | 可用性影响 | N / L / H | **N** 无；**L** 低；**H** 高。 |

## Rationale

- `rationale` 须说明每个**非默认** metric 的取值依据（部署假设、攻击面、验证证据）。
- 记录 `uncertainties` 当部署环境、权限模型或影响范围存在未确认假设时。

## Severity mapping

| Base Score | Severity |
|---|---|
| 0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

## Calculator validation（必做）

写入 CVSS artifact 后执行：

```bash
python3 tools/cvss31_calculator.py --validate --in audit-output/05-findings/CVSS-*.json
```

校验失败则修正 vector / base_score / severity，不得进入最终 finding。

## Forbidden substitutes

- **不得**用 openEuler CVE 注册表或清单中的 `risk_level`（如「高危」「中危」「严重」）替代 CVSS 向量或 base_score。
- **不得**将运营风险、业务影响或披露级别直接映射为 CVSS severity。
- CVSS severity 不等于 operational risk；两者在报告中须分开表述。

## Example vector

```text
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L
→ base_score 3.3, severity Low
```
