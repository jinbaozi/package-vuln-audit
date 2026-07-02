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
                "command": [semgrep_binary, "scan", "--config", "local-rules", "--json", "--output", "<raw>/semgrep.json", "<source>"],
                "timeout": "5s",
                "watchdog": {"strategy": "adaptive", "idle_timeout": "1s"},
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


def run_tool_matrix(matrix: pathlib.Path, source: pathlib.Path, out: pathlib.Path, env=None):
    return subprocess.run([
        sys.executable,
        str(ROOT / "tools" / "run_tool_matrix.py"),
        "--matrix",
        str(matrix),
        "--source",
        str(source),
        "--out",
        str(out),
    ], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_semgrep_missing_is_recorded_and_blocks():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        matrix = base_matrix(td, semgrep_binary="missing-semgrep")
        out = td / "tools"
        p = run_tool_matrix(matrix, td, out)
        assert p.returncode == 2
        assert "[PVAS-TOOL-MISSING] semgrep not installed" in p.stderr
        summary = json.loads((out / "tool-summary.json").read_text())
        semgrep = next(t for t in summary["tools"] if t["name"] == "semgrep")
        assert semgrep["status"] == "not-installed"
        assert semgrep["reason"] == "not-installed"
        assert semgrep["strict_decision"] == "block"


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
        p = run_tool_matrix(matrix, td, out, env=env)
        assert p.returncode == 0
        summary = json.loads((out / "tool-summary.json").read_text())
        semgrep = next(t for t in summary["tools"] if t["name"] == "semgrep")
        npm = next(t for t in summary["tools"] if t["name"] == "npm")
        assert semgrep["status"] == "completed"
        assert npm["status"] == "not-applicable"
        attempts = json.loads((out / "tool-execution-attempts.json").read_text())
        assert attempts["attempts"][0]["tool"] == "semgrep"
        assert "watchdog_events" in attempts["attempts"][0]


def test_no_local_semgrep_rules_is_incomplete_not_blocking():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake_semgrep = bindir / "semgrep"
        write_executable(fake_semgrep, "#!/usr/bin/env bash\nexit 99\n")
        matrix_data = json.loads(base_matrix(td, semgrep_binary="semgrep").read_text())
        matrix_data["tools"][0]["command"] = ["semgrep", "scan", "--json", "--output", "<raw>/semgrep.json", "<source>"]
        matrix = td / "matrix.json"
        matrix.write_text(json.dumps(matrix_data))
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        out = td / "tools"
        p = run_tool_matrix(matrix, td, out, env=env)
        assert p.returncode == 0
        summary = json.loads((out / "tool-summary.json").read_text())
        semgrep = next(t for t in summary["tools"] if t["name"] == "semgrep")
        assert semgrep["status"] == "incomplete"
        assert semgrep["reason"] == "no-local-rules"


def test_watchdog_allows_progress_past_soft_timeout():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "progress-tool"
        write_executable(fake, "#!/usr/bin/env bash\nfor i in 1 2 3 4 5; do echo tick-$i; sleep 0.2; done\n")
        matrix = {
            "tools": [{
                "name": "progress-tool",
                "binary": "progress-tool",
                "applicability": "mandatory",
                "evidence": "progress test",
                "command": ["progress-tool"],
                "timeout": "0.3s",
                "watchdog": {"strategy": "adaptive", "idle_timeout": "0.4s"},
                "retry_policy": {"max_attempts": 1},
            }]
        }
        matrix_path = td / "matrix.json"
        matrix_path.write_text(json.dumps(matrix))
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        out = td / "tools"
        p = run_tool_matrix(matrix_path, td, out, env=env)
        assert p.returncode == 0
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "completed"


def test_watchdog_marks_idle_hang_abnormal():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "hang-tool"
        write_executable(fake, "#!/usr/bin/env bash\nsleep 5\n")
        matrix = {
            "tools": [{
                "name": "hang-tool",
                "binary": "hang-tool",
                "applicability": "mandatory",
                "evidence": "hang test",
                "command": ["hang-tool"],
                "timeout": "0.2s",
                "watchdog": {"strategy": "adaptive", "idle_timeout": "0.2s"},
                "retry_policy": {"max_attempts": 1},
            }]
        }
        matrix_path = td / "matrix.json"
        matrix_path.write_text(json.dumps(matrix))
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        out = td / "tools"
        p = run_tool_matrix(matrix_path, td, out, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "abnormal"
        assert row["reason"] == "abnormal-timeout"


def test_osv_no_package_sources_is_not_applicable():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "osv-scanner"
        write_executable(fake, "#!/usr/bin/env bash\necho 'No package sources found'; exit 1\n")
        matrix = {
            "tools": [{
                "name": "osv-scanner",
                "binary": "osv-scanner",
                "applicability": "mandatory",
                "evidence": "known vulnerability scan",
                "command": ["osv-scanner", "scan", "--format", "json", "<source>"],
                "timeout": "2s",
                "retry_policy": {"max_attempts": 1},
            }]
        }
        # Add package manifest so preflight passes and osv-scanner actually runs
        (td / "package.json").write_text('{"name":"test"}')
        matrix_path = td / "matrix.json"
        matrix_path.write_text(json.dumps(matrix))
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        out = td / "tools"
        p = run_tool_matrix(matrix_path, td, out, env=env)
        assert p.returncode == 0, f"exit {p.returncode}: {p.stderr[:500]}"
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "not-applicable"
        assert row["reason"] == "no-package-sources"


if __name__ == "__main__":
    test_semgrep_missing_is_recorded_and_blocks()
    test_semgrep_success_completes_and_not_applicable_is_preserved()
    test_no_local_semgrep_rules_is_incomplete_not_blocking()
    test_watchdog_allows_progress_past_soft_timeout()
    test_watchdog_marks_idle_hang_abnormal()
    test_osv_no_package_sources_is_not_applicable()
    print("tool execution gate tests passed")
