# CVSS 3.1 与 openEuler CVE 注册表 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 PVAS 默认 CVSS 切换为 v3.1（stdlib 计算器 + 文档/agent 对齐），导入 openEuler CVE 离线注册表，扩展公开关联（CVE 精确 + M3-CVE）与 finding 回写闭环，并满足 §7 渐进式披露（D-tier / L-tier）约束。

**Architecture:** 六 PR 串行交付；每 PR 末尾 `./run-tests.sh` 全绿。CVSS 与 registry 可独立验证；correlate → apply → publish 形成 report gate 闭环。注册表仅工具层 L4 加载；`disclosure_status` 与 `disclosure_level` 严格分离。

**Tech Stack:** Python 3 stdlib、bash、JSON Schema、standalone test scripts（非 pytest）、`./run-tests.sh`。

**Spec reference:** [`docs/superpowers/specs/2026-06-30-cvss31-openeuler-registry-design.md`](../specs/2026-06-30-cvss31-openeuler-registry-design.md)

---

## File Structure

| PR | Create | Modify |
|----|--------|--------|
| PR-1 | `tools/cvss31_calculator.py`, `tests/test_cvss31_calculator.py` | `tests/fixtures/sample-cvss.json`, `tests/fixtures/sample-finding.json`, `tests/fixtures/sample-report.json`, `run-tests.sh`, `tools/enforce_workflow_contract.py` |
| PR-2 | `references/cvss31-scoring-guide.md` | `SKILL.md`, `agents/cvss-scorer.md`, `workflows/07-cvss-scoring.md`, `workflows/08-report.md`, `references/severity-rating.md`, adapters, `README.md`, `examples/binutils/finding.example.md`, `schemas/cvss.schema.json`, 测试中含 `CVSS:4.0` 的文件 |
| PR-3 | `schemas/openeuler-vuln-registry.schema.json`, `tools/import_openeuler_vuln_registry.py`, `tests/test_import_openeuler_vuln_registry.py`, `tests/fixtures/sample-openeuler-registry.xlsx`, `offline-bundle/vuln-db/openeuler/README.md`, `offline-bundle/vuln-db/openeuler/manifest.json`, `cve-index.json`, `records.json` | `core/manifest.yaml`, `tests/test_schemas.py` |
| PR-4 | `tools/apply_correlation_to_findings.py`, `tests/test_apply_correlation_to_findings.py` | `tools/pvas_io.py`, `tools/correlate_public_vulns.py`, `tests/test_public_vuln_correlation.py` |
| PR-5 | — | `tools/enforced_audit_driver.py`, `tools/check_offline_db_freshness.py`, `tools/publish_bilingual_reports.py`, `tools/context_budget.py`, `core/manifest.yaml`, `references/public-vulnerability-correlation-policy.md`, `AGENTS.md`, `agents/public-vuln-correlator.md`, `docs/runbooks/public-vulnerability-correlation.md` |
| PR-6 | `tests/test_cvss31_driver_gate.py`（可选轻量） | `CHANGELOG.md`, `run-tests.sh`, `skill.json`（确认版本） |

---

## PR-1: CVSS 3.1 计算器

### Task 1: Failing test with golden vectors

**Files:**
- Create: `tests/test_cvss31_calculator.py`
- Create: `tools/cvss31_calculator.py`（空壳 `main` 即可先 fail）

- [ ] **Step 1: Create test script**

```python
#!/usr/bin/env python3
import json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'cvss31_calculator.py'

GOLDEN = [
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'),
    ('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9, 'Critical'),
    ('CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H', 4.4, 'Medium'),
    ('CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', 4.2, 'Medium'),
    ('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L', 2.8, 'Low'),
    ('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0, 'None'),
]

def run_vector(vector: str) -> dict:
    p = subprocess.run(
        [sys.executable, str(TOOL), '--vector', vector],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    return json.loads(p.stdout)

def main():
    for vector, score, sev in GOLDEN:
        out = run_vector(vector)
        assert out['base_score'] == score, (vector, out)
        assert out['severity'] == sev, (vector, out)
    p = subprocess.run(
        [sys.executable, str(TOOL), '--vector', 'CVSS:3.1/AV:INVALID'],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert p.returncode != 0
    print('cvss31 calculator tests passed')

if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `python3 -u tests/test_cvss31_calculator.py`  
Expected: FAIL（工具未实现或分数不对）

---

### Task 2: Implement `tools/cvss31_calculator.py`

**Files:**
- Modify: `tools/cvss31_calculator.py`

- [ ] **Step 1: Implement parse + score + severity**

核心结构（完整实现 FIRST v3.1 公式，含 Scope Changed 分支）：

```python
#!/usr/bin/env python3
"""CVSS v3.1 Base Score calculator (stdlib only). Aligned with FIRST spec / cvssjs."""
from __future__ import annotations
import argparse, json, math, pathlib, re, sys

METRICS = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},  # unchanged scope; changed uses PR_U map
    'PR_S': {'N': 0.85, 'L': 0.68, 'H': 0.50},
    'UI': {'N': 0.85, 'R': 0.62},
    'S': {'U': False, 'C': True},
    'C': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'I': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'A': {'H': 0.56, 'L': 0.22, 'N': 0.0},
}

def parse_vector(vector: str) -> dict[str, str]:
    if not vector.startswith('CVSS:3.1/'):
        raise ValueError('expected CVSS:3.1/ prefix')
    parts = {}
    for seg in vector.split('/')[1:]:
        if ':' not in seg:
            continue
        k, v = seg.split(':', 1)
        parts[k] = v
    for k in ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'):
        if k not in parts:
            raise ValueError(f'missing metric {k}')
    return parts

def roundup(n: float) -> float:
    return math.ceil(n * 10) / 10.0

def severity(score: float) -> str:
    if score <= 0:
        return 'None'
    if score < 4.0:
        return 'Low'
    if score < 7.0:
        return 'Medium'
    if score < 9.0:
        return 'High'
    return 'Critical'

def base_score(m: dict[str, str]) -> float:
    scope_changed = METRICS['S'][m['S']]
    pr_map = METRICS['PR_S'] if scope_changed else METRICS['PR']
    iss = 1 - (1 - METRICS['C'][m['C']]) * (1 - METRICS['I'][m['I']]) * (1 - METRICS['A'][m['A']])
    if scope_changed:
        isc = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        if isc <= 0:
            return 0.0
    else:
        isc = 6.42 * iss
    exploit = 8.22 * METRICS['AV'][m['AV']] * METRICS['AC'][m['AC']] * pr_map[m['PR']] * METRICS['UI'][m['UI']]
    if scope_changed:
        score = min(1.08 * (isc + exploit), 10)
    else:
        score = min(isc + exploit, 10)
    return roundup(score)

def compute(vector: str) -> dict:
    m = parse_vector(vector)
    score = base_score(m)
    return {'version': '3.1', 'vector': vector, 'base_score': score, 'severity': severity(score)}

def validate_artifact(data: dict) -> list[str]:
    errors = []
    cvss = data.get('cvss', data)
    vector = cvss.get('vector', '')
    if not vector.startswith('CVSS:3.1/'):
        return [f'not a 3.1 vector: {vector}']
    calc = compute(vector)
    if abs(float(cvss.get('base_score', -1)) - calc['base_score']) > 0.11:
        errors.append(f'base_score mismatch: {cvss.get("base_score")} vs {calc["base_score"]}')
    if cvss.get('severity') and cvss['severity'] != calc['severity']:
        errors.append(f'severity mismatch: {cvss.get("severity")} vs {calc["severity"]}')
    return errors

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--vector')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--in', dest='inp')
    args = ap.parse_args()
    if args.validate:
        if not args.inp:
            print('error: --in required with --validate', file=sys.stderr)
            return 2
        data = json.loads(pathlib.Path(args.inp).read_text())
        errs = validate_artifact(data)
        if errs:
            print(json.dumps({'valid': False, 'errors': errs}, indent=2))
            return 1
        print(json.dumps({'valid': True}, indent=2))
        return 0
    if not args.vector:
        ap.error('--vector or --validate --in required')
    print(json.dumps(compute(args.vector), indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
```

- [ ] **Step 2: Run test**

Run: `python3 -u tests/test_cvss31_calculator.py`  
Expected: `cvss31 calculator tests passed`

- [ ] **Step 3: Register in run-tests + REQUIRED_TOOLS**

`run-tests.sh` 在 `test_public_vuln_correlation.py` 前插入：

```bash
python3 -u tests/test_cvss31_calculator.py
```

`tools/enforce_workflow_contract.py` `REQUIRED_TOOLS` 追加 `'cvss31_calculator.py'`。

---

### Task 3: Update CVSS fixtures to 3.1

**Files:**
- Modify: `tests/fixtures/sample-cvss.json`
- Modify: `tests/fixtures/sample-finding.json`（cvss 块）
- Modify: `tests/fixtures/sample-report.json`

- [ ] **Step 1: Replace sample-cvss.json**

```json
{
  "version": "3.1",
  "status": "provisional",
  "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:P/S:U/C:N/I:N/A:L",
  "base_score": 3.3,
  "severity": "Low",
  "rationale": {"AV": "local malformed input processing fixture"},
  "uncertainties": ["fixture score only"]
}
```

- [ ] **Step 2: Sync finding/report fixtures** — 同样使用 3.1 向量；`base_score`/`severity` 与 calculator 输出一致。

- [ ] **Step 3: Run**

Run: `./run-tests.sh`  
Expected: 全绿（PR-1 完成）

---

## PR-2: 文档 / Agent / Schema 切换 v3.1

### Task 4: Scoring guide + policy docs

**Files:**
- Create: `references/cvss31-scoring-guide.md`
- Modify: `references/severity-rating.md`, `SKILL.md` § CVSS policy, `agents/cvss-scorer.md`

- [ ] **Step 1: Create scoring guide** — 8 metrics 中文表（AV/AC/PR/UI/S/C/I/A），链接 cvssjs；Likely=provisional / Validated=final；禁止用欧拉 risk_level 替代 CVSS。

- [ ] **Step 2: Update SKILL.md** — `Use CVSS v3.1 by default`；引用 `references/cvss31-scoring-guide.md`。

- [ ] **Step 3: Update cvss-scorer agent** — Mission 改为 v3.1；必须调用 `cvss31_calculator.py --validate`。

- [ ] **Step 4: Grep 验收**

Run: `rg 'CVSS v4\.0|CVSS:4\.0' --glob '!CHANGELOG*' --glob '!RELEASE-NOTES*' --glob '!docs/superpowers/**'`  
Expected: 无匹配（或仅剩历史文档 intentional）

---

### Task 5: Workflows + adapters + README

**Files:**
- Modify: `workflows/07-cvss-scoring.md`, `workflows/08-report.md`
- Modify: `adapters/claude-code/agents/cvss-scorer.md`, `adapters/opencode/opencode.json`, `adapters/codex/AGENTS.md`
- Modify: `README.md`, `examples/binutils/finding.example.md`
- Modify: `tests/test_bilingual_output.py`, `tests/test_poc_testcase_generation.py` 等含 `CVSS:4.0` 的测试

- [ ] **Step 1:** 全部改为 v3.1 向量示例。

- [ ] **Step 2:** `./run-tests.sh` 全绿。

---

### Task 6: cvss.schema.json

**Files:**
- Modify: `schemas/cvss.schema.json`

- [ ] **Step 1:** 保留 `"4.0"` enum；在 `vector` 上增加 `"pattern": "^CVSS:3\\.1/"` 的 **不强制**（新产物默认 3.1，旧 fixture 迁移后可通过 schema test）。

Run: `python3 -u tests/test_schemas.py`

---

## PR-3: openEuler 注册表导入

### Task 7: Schema + synthetic fixture

**Files:**
- Create: `schemas/openeuler-vuln-registry.schema.json`
- Create: `tests/fixtures/sample-openeuler-registry.xlsx`（可用脚本生成最小 3-sheet xlsx，各 2 行数据）

- [ ] **Step 1: Schema** — 顶层 `schema_version`, `source`, `data_cutoff`, `record_count`, `records[]`, `cve_index` object。

- [ ] **Step 2: Generate mini xlsx** — 在 `tests/build_sample_openeuler_xlsx.py` 或 test 内联 zip 写入 sheet2/3/4 各 2 行，CVE 如 `CVE-2026-0001`。

---

### Task 8: `tools/import_openeuler_vuln_registry.py`

**Files:**
- Create: `tools/import_openeuler_vuln_registry.py`
- Create: `tests/test_import_openeuler_vuln_registry.py`

- [ ] **Step 1: Test**

```python
#!/usr/bin/env python3
import json, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]

def main():
    fixture = ROOT / 'tests/fixtures/sample-openeuler-registry.xlsx'
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / 'openeuler'
        subprocess.check_call([
            sys.executable, str(ROOT / 'tools/import_openeuler_vuln_registry.py'),
            '--xlsx', str(fixture), '--out', str(out),
        ])
        idx = json.loads((out / 'cve-index.json').read_text())
        assert 'CVE-2026-0001' in idx['index']
        manifest = json.loads((out / 'manifest.json').read_text())
        assert manifest['record_count'] >= 1
    print('import openeuler registry tests passed')

if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Implement importer** — zipfile+xml 解析；表头检测；`parse_branches()` 将 `['master', ...]` 字符串转 list；输出三文件。

- [ ] **Step 3: Run against real xlsx locally**

Run: `python3 tools/import_openeuler_vuln_registry.py --xlsx 漏洞数据清单.xlsx --out offline-bundle/vuln-db/openeuler`  
Expected: `record_count` > 10000；提交 `manifest.json`, `cve-index.json`, `records.json`, `README.md`。

- [ ] **Step 4:** 注册 `test_import_openeuler_vuln_registry.py`、`import_openeuler_vuln_registry.py` 到 run-tests / REQUIRED_TOOLS；`core/manifest.yaml` 增加 `openeuler-vuln-registry.schema.json`。

---

## PR-4: 公开关联 + finding 回写

### Task 9: `extract_cve_ids` in pvas_io

**Files:**
- Modify: `tools/pvas_io.py`

- [ ] **Step 1: Add function**

```python
import re
CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.I)

def extract_cve_ids(finding: dict) -> list[str]:
    ids: list[str] = []
    for r in finding.get('public_vulnerability_references') or []:
        if isinstance(r, dict) and r.get('id'):
            ids.extend(CVE_RE.findall(str(r['id'])))
    blob = ' '.join(str(finding.get(k, '')) for k in (
        'title', 'summary', 'root_cause', 'security_impact'))
    blob += ' ' + json.dumps(finding.get('validation') or {})
    ids.extend(CVE_RE.findall(blob))
    seen: set[str] = set()
    out: list[str] = []
    for c in ids:
        cu = c.upper()
        if cu not in seen:
            seen.add(cu)
            out.append(cu)
    return out
```

---

### Task 10: Extend `correlate_public_vulns.py`

**Files:**
- Modify: `tools/correlate_public_vulns.py`
- Modify: `tests/test_public_vuln_correlation.py`

- [ ] **Step 1: Load `--openeuler-index`** — 读 `cve-index.json` 的 `index` 字段；默认 `offline-bundle/vuln-db/openeuler/cve-index.json`（存在则启用）。

- [ ] **Step 2: Before NVD pool scoring** — 对每个 Validated finding：

```python
from pvas_io import extract_cve_ids
for cve_id in extract_cve_ids(f):
    hits = openeuler_index.get(cve_id, [])
    if hits:
        # status=publicly_disclosed, match_level=M3, matched_records with source openEuler-Registry
        break
```

- [ ] **Step 3: Extend test** — mini `cve-index.json` + finding summary 含 `CVE-2026-0001` → M3 + openEuler-Registry。

Run: `python3 -u tests/test_public_vuln_correlation.py`

---

### Task 11: `tools/apply_correlation_to_findings.py`

**Files:**
- Create: `tools/apply_correlation_to_findings.py`
- Create: `tests/test_apply_correlation_to_findings.py`

- [ ] **Step 1: Test disclosure_level unchanged**

```python
findings = {'findings': [{
    'id': 'F-1', 'status': 'Validated', 'disclosure_level': 'D2-internal-validated',
    'disclosure_status': 'unknown', 'title': 'x CVE-2026-0001', ...
}]}
correlation = {'correlations': [{
    'finding_id': 'F-1', 'status': 'publicly_disclosed', 'match_level': 'M3',
    'matched_records': [{'source': 'openEuler-Registry', 'id': 'CVE-2026-0001', ...}],
}]}
# after apply: disclosure_status == publicly_disclosed
# disclosure_level still D2-internal-validated
# public_vulnerability_references non-empty
```

- [ ] **Step 2: Implement** — Validated only；合并 refs；写 `apply-correlation-result.json`。

- [ ] **Step 3: Register tool + test in run-tests.sh**

---

## PR-5: Driver / Manifest L-tier / 报告 / Policy

### Task 12: Driver pipeline

**Files:**
- Modify: `tools/enforced_audit_driver.py`

- [ ] **Step 1: After correlate, before publish**

```python
run([sys.executable, 'tools/correlate_public_vulns.py',
     '--findings', args.findings, '--records', str(norm_records),
     '--openeuler-index', 'offline-bundle/vuln-db/openeuler/cve-index.json',
     '--out', str(corr)], allow_fail=False)
run([sys.executable, 'tools/apply_correlation_to_findings.py',
     '--findings', args.findings, '--correlation', str(corr),
     '--out', args.findings], allow_fail=False)
```

- [ ] **Step 2: CVSS validate（A5 必做）** — 若 findings 含 `cvss.version==3.1`，对每条 Validated 调用 `cvss31_calculator.py --validate`（allow_fail=True，warn 写入 step）。

---

### Task 13: Manifest L4 + context budget

**Files:**
- Modify: `core/manifest.yaml`
- Modify: `tools/context_budget.py`（若 L4 路径列表硬编码）

- [ ] **Step 1: l4_forbidden_patterns 增加**

```yaml
  - "offline-bundle/vuln-db/openeuler/cve-index.json"
  - "offline-bundle/vuln-db/openeuler/records.json"
```

- [ ] **Step 2: artifacts 增加**

```yaml
  - id: public-vuln-correlation
    path_pattern: audit-output/machine/correlation/public-vuln-correlation.json
    load_tier: L1
  - id: apply-correlation-result
    path_pattern: audit-output/machine/correlation/apply-correlation-result.json
    load_tier: L1
```

Run: `python3 -u tests/test_manifest.py`

---

### Task 14: D2 报告欧拉 category 列

**Files:**
- Modify: `tools/publish_bilingual_reports.py`

- [ ] **Step 1: In `disclosure_summary()`** — 从 `matched_records` 取 `openEuler-Registry` 的 `category`，映射中文：unaffected→不受影响，suspended→挂起，fixed→已修复。

- [ ] **Step 2: 内部报告表头** — zh/en 各加一列「欧拉处置状态 / openEuler disposition」。

- [ ] **Step 3:** `python3 -u tests/test_bilingual_output.py`

---

### Task 15: Policy + AGENTS M3-CVE + freshness

**Files:**
- Modify: `references/public-vulnerability-correlation-policy.md`, `AGENTS.md`
- Modify: `tools/check_offline_db_freshness.py`
- Modify: `docs/runbooks/public-vulnerability-correlation.md`, `agents/public-vuln-correlator.md`

- [ ] **Step 1:** 写入 M3-CVE 段落 + §7.1 硬规则（不升格 disclosure_level）。

- [ ] **Step 2: freshness** — 支持重复 `--extra-manifest` 或固定读取 `offline-bundle/vuln-db/openeuler/manifest.json`。

---

## PR-6: CHANGELOG + 全量验收

### Task 16: CHANGELOG + run-tests required files

**Files:**
- Modify: `CHANGELOG.md`, `run-tests.sh`

- [ ] **Step 1: CHANGELOG alpha11 节**

```markdown
## 0.10.0-alpha11
- **Changed:** Default CVSS v3.1; cvss31_calculator required for score validation.
- **Added:** openEuler CVE registry import; M3-CVE correlation; apply_correlation_to_findings.
- **Added:** Progressive disclosure guards (disclosure_status vs disclosure_level).
```

- [ ] **Step 2: run-tests required files** — 增加 `offline-bundle/vuln-db/openeuler/manifest.json`。

---

### Task 17: Final acceptance

- [ ] **Step 1: Full suite**

Run: `./run-tests.sh`  
Expected: `alpha10 unit checks passed`（或更新 echo 文案）

- [ ] **Step 2: Integration（可选）**

Run: `PVAS_RUN_INTEGRATION=1 ./run-tests.sh`

- [ ] **Step 3: Grep v4.0 + progressive disclosure checklist（spec §7.4）**

Run: `rg 'CVSS:4\.0' tests/ tools/ SKILL.md agents/`  
Run: 确认无自动 `07-disclosure/public-advisory-draft` 由 correlate 触发

---

## Spec Coverage Self-Review

| Spec § | Task |
|--------|------|
| §4 CVSS 3.1 | PR-1, PR-2, Task 12 Step 2 |
| §5 openEuler registry | PR-3 |
| §6 correlate + apply | PR-4, PR-5 Task 12 |
| §7 progressive disclosure | PR-4 Task 11, PR-5 Task 13–15 |
| §8 tests | 各 PR run-tests |
| §9 CHANGELOG | PR-6 |

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-30-cvss31-openeuler-registry.md`.

**Two execution options:**

1. **Subagent-Driven（推荐）** — 按 PR-1→PR-6 派发 subagent，每 PR 后 `./run-tests.sh` 审查。
2. **Inline Execution** — 本会话按 Task 顺序实施，每 PR 结束 checkpoint。

请选择执行方式；若选 Inline，将使用 executing-plans 从 PR-1 Task 1 开始。
