#!/usr/bin/env python3
"""Generate manual validation plans for Needs Manual Review items."""
from __future__ import annotations

import argparse
import json
import pathlib

from pvas_io import load_findings, write_json


def field(finding: dict, key: str, fallback: str) -> str:
    value = finding.get(key)
    return str(value).strip() if value else fallback


def build_plan(finding: dict) -> dict:
    mr = finding.get("manual_review") if isinstance(finding.get("manual_review"), dict) else {}
    evidence = finding.get("source_code_evidence") or []
    return {
        "id": finding.get("id", "MANUAL-UNKNOWN"),
        "status": "Needs Manual Review",
        "title": field(finding, "title", "需要人工确认的问题"),
        "source_evidence": evidence,
        "source_to_sink_path": field(finding, "source_to_sink_path", "需要人工补充 source-to-sink 路径"),
        "blocked_reason": mr.get("blocked_reason") or field(finding, "manual_review_reason", "自动验证条件不足"),
        "suggested_build_command": mr.get("suggested_build_command") or "按照项目构建文档构建受影响目标",
        "suggested_test_method": mr.get("suggested_test_method") or "构造触发输入并在本地受控环境运行受影响目标",
        "expected_observable_signal": mr.get("expected_observable_signal") or "观察崩溃、sanitizer 报告、错误输出或安全边界绕过信号",
        "input_requirements": mr.get("input_requirements") or "根据 source-to-sink 路径准备最小触发输入",
        "safety_restrictions": [
            "仅在授权本地环境验证",
            "不访问第三方目标",
            "不使用 sudo 或写系统目录",
            "验证成功前不得作为 Validated 漏洞发布",
        ],
        "upgrade_criteria": [
            "人工验证得到稳定可复现信号",
            "补齐本地 PoC 包",
            "PoC 安全校验通过",
            "PoC 执行结果为 passed",
        ],
    }


def write_plan(plan: dict, outdir: pathlib.Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "manual-validation-plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False))
    lines = [
        f"# 人工验证计划：{plan['id']}",
        "",
        f"- 状态：{plan['status']}",
        f"- 标题：{plan['title']}",
        f"- 阻断原因：{plan['blocked_reason']}",
        f"- 建议构建命令：{plan['suggested_build_command']}",
        f"- 建议测试方法：{plan['suggested_test_method']}",
        f"- 输入要求：{plan['input_requirements']}",
        f"- 预期可观察信号：{plan['expected_observable_signal']}",
        "",
        "## 源码证据",
        "",
        "```json",
        json.dumps(plan["source_evidence"], indent=2, ensure_ascii=False),
        "```",
        "",
        "## 安全限制",
        "",
    ]
    lines.extend(f"- {item}" for item in plan["safety_restrictions"])
    lines.extend(["", "## 升级为 Validated 的条件", ""])
    lines.extend(f"- {item}" for item in plan["upgrade_criteria"])
    (outdir / "manual-validation-plan.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out", default="audit-output/04-validation/manual-review")
    args = ap.parse_args()

    findings = load_findings(pathlib.Path(args.findings))
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    count = 0
    for finding in findings:
        if finding.get("status") != "Needs Manual Review":
            continue
        plan = build_plan(finding)
        write_plan(plan, out / plan["id"])
        count += 1
    (out / "manual-validation-plan-summary.json").write_text(json.dumps({"generated": count}, indent=2))
    print(f"[PVAS-MANUAL] generated {count} manual validation plan(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
