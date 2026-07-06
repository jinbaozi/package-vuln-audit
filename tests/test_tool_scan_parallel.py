#!/usr/bin/env python3
"""Behavior tests for sandboxed parallel tool matrix execution."""
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import pvas_container  # noqa: E402
import run_tool_matrix  # noqa: E402


def _tool(name, *, command=None, applicability="recommended"):
    return {
        "name": name,
        "binary": name,
        "applicability": applicability,
        "evidence": f"{name} coverage",
        "command": command or [name, "--version"],
        "timeout": "5s",
        "network_policy": "restricted",
        "network_required": False,
        "allowed_cidrs": [],
        "mem_limit_mb": 256,
        "sandbox_runtime": "pvas-container",
        "retry_policy": {"max_attempts": 1},
        "degraded_continuation_allowed": False,
    }


def test_build_container_spec_uses_catalog_runtime_fields():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        raw = td / "raw"
        raw.mkdir()
        source = td / "src"
        source.mkdir()
        tool = _tool("rg", command=["rg", "needle", "<source>"])
        tool["mem_limit_mb"] = 512
        tool["allowed_cidrs"] = ["10.0.0.0/8"]
        spec = run_tool_matrix.build_container_spec(tool, source, raw)
        assert spec.mem_limit_mb == 512
        assert spec.network_policy == "bridge-deny"
        assert spec.allowed_cidrs == ["10.0.0.0/8"]
        assert spec.labels["pvas-tool"] == "rg"
        assert str(source.resolve()) in spec.command


def test_semgrep_runs_before_parallel_batch_and_summary_preserves_blocked():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        source = td / "src"
        source.mkdir()
        raw = td / "raw"
        raw.mkdir()
        tools = [
            _tool("semgrep", command=["semgrep", "scan", "--config", "p/c", "--json", "--output", "<raw>/semgrep.json", "<source>"], applicability="mandatory"),
            _tool("rg", command=["rg", "needle", "<source>"]),
            _tool("npm", command=["npm", "audit", "--json"]),
        ]
        calls = []
        old_run = run_tool_matrix.pvas_container.run
        old_parallel = run_tool_matrix.pvas_container.run_parallel

        def fake_run(spec, backend=None):
            calls.append(("run", spec.labels["pvas-tool"]))
            if spec.labels["pvas-tool"] == "semgrep":
                (raw / "semgrep.json").write_text(json.dumps({"results": []}))
            return pvas_container.ContainerResult(
                exit_code=0,
                stdout="",
                stderr="",
                duration_seconds=0.01,
                container_id="semgrep123456",
                oom_killed=False,
                timed_out=False,
                netpolicy_id="np-semgrep",
            )

        def fake_parallel(specs):
            calls.append(("parallel", [s.labels["pvas-tool"] for s in specs]))
            results = []
            for spec in specs:
                exit_code = 1 if spec.labels["pvas-tool"] == "npm" else 0
                results.append(pvas_container.ContainerResult(
                    exit_code=exit_code,
                    stdout="{}",
                    stderr="",
                    duration_seconds=0.01,
                    container_id=f"{spec.labels['pvas-tool']}123456",
                    oom_killed=False,
                    timed_out=False,
                    netpolicy_id=f"np-{spec.labels['pvas-tool']}",
                ))
            return results

        run_tool_matrix.pvas_container.run = fake_run
        run_tool_matrix.pvas_container.run_parallel = fake_parallel
        try:
            rows, attempts = run_tool_matrix.run_matrix_tools(tools, source, raw)
        finally:
            run_tool_matrix.pvas_container.run = old_run
            run_tool_matrix.pvas_container.run_parallel = old_parallel

        assert calls[0] == ("run", "semgrep")
        assert calls[1] == ("parallel", ["rg", "npm"])
        by_name = {row["name"]: row for row in rows}
        assert by_name["semgrep"]["status"] == "completed"
        assert by_name["rg"]["status"] == "completed"
        assert by_name["npm"]["status"] == "blocked-recovery-required"
        assert by_name["npm"]["container"]["netpolicy_id"] == "np-npm"
        summary = run_tool_matrix.collect_summary(rows, attempts)
        assert summary["strict_decision"] == "block"
        assert "npm" in summary["blocked_tools"]


if __name__ == "__main__":
    test_build_container_spec_uses_catalog_runtime_fields()
    test_semgrep_runs_before_parallel_batch_and_summary_preserves_blocked()
    print("tool scan parallel tests passed")
