#!/usr/bin/env python3
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def write_executable(path: pathlib.Path, content: str):
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def base_matrix(td: pathlib.Path, semgrep_binary="semgrep"):
    matrix = {
        "schema_version": "1.0",
        "environment_profile": "standard",
        "package": "fixture",
        "tools": [
            {
                "name": "semgrep",
                "binary": semgrep_binary,
                "applicability": "mandatory",
                "evidence": "complete-audit baseline",
                "command": [semgrep_binary, "scan", "--json", "--output", "<raw>/semgrep.json", "<source>"],
                "timeout": "5s",
                "retry_policy": {"max_attempts": 1},
                "allowed_recovery_actions": ["retry"],
                "degraded_continuation_allowed": False,
                "final_status": "planned",
                "final_decision_rationale": "",
            },
            {
                "name": "npm",
                "binary": "npm",
                "applicability": "not-applicable",
                "evidence": "no Node.js package metadata",
                "command": ["npm", "audit", "--json"],
                "timeout": "5s",
                "retry_policy": {"max_attempts": 1},
                "allowed_recovery_actions": [],
                "degraded_continuation_allowed": True,
                "final_status": "planned",
                "final_decision_rationale": "",
            },
        ],
    }
    path = td / "matrix.json"
    path.write_text(json.dumps(matrix))
    return path


def test_semgrep_missing_blocks_complete_audit():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        matrix = base_matrix(td, semgrep_binary="missing-semgrep")
        out = td / "tools"
        p = subprocess.run([
            sys.executable,
            str(ROOT / "tools" / "run_tool_matrix.py"),
            "--matrix",
            str(matrix),
            "--source",
            str(td),
            "--out",
            str(out),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 2
        summary = json.loads((out / "tool-summary.json").read_text())
        semgrep = next(t for t in summary["tools"] if t["name"] == "semgrep")
        assert semgrep["status"] == "blocked"
        assert semgrep["reason"] == "not-installed"


def test_semgrep_success_completes_and_not_applicable_is_preserved():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake_semgrep = bindir / "semgrep"
        write_executable(fake_semgrep, "#!/usr/bin/env bash\nwhile [[ $# -gt 0 ]]; do if [[ \"$1\" == \"--output\" ]]; then shift; echo '{\"results\":[]}' > \"$1\"; fi; shift || true; done\n")
        matrix = base_matrix(td, semgrep_binary="semgrep")
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = subprocess.run([
            sys.executable,
            str(ROOT / "tools" / "run_tool_matrix.py"),
            "--matrix",
            str(matrix),
            "--source",
            str(td),
            "--out",
            str(out),
        ], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 0
        summary = json.loads((out / "tool-summary.json").read_text())
        semgrep = next(t for t in summary["tools"] if t["name"] == "semgrep")
        npm = next(t for t in summary["tools"] if t["name"] == "npm")
        assert semgrep["status"] == "completed"
        assert npm["status"] == "not-applicable"
        attempts = json.loads((out / "tool-execution-attempts.json").read_text())
        assert attempts["attempts"][0]["tool"] == "semgrep"


if __name__ == "__main__":
    test_semgrep_missing_blocks_complete_audit()
    test_semgrep_success_completes_and_not_applicable_is_preserved()
    print("tool execution gate tests passed")
