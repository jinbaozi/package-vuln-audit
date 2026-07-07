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
    (td / "local-rules").mkdir(exist_ok=True)
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
                "command": [semgrep_binary, "scan", "--config", str(td / "local-rules"), "--json", "--output", "<raw>/semgrep.json", "<source>"],
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


def cppcheck_matrix(
    td: pathlib.Path,
    *,
    shard_size=2,
    timeout="1s",
    enable="warning,style,performance,portability",
    mode="deep",
    mode_source="test-fixture",
):
    matrix = {
        "schema_version": "1.0",
        "environment_profile": "standard",
        "package": "fixture",
        "tools": [{
            "name": "cppcheck",
            "binary": "cppcheck",
            "applicability": "mandatory",
            "evidence": "cppcheck C/C++ static analysis coverage",
            "command": ["cppcheck", f"--enable={enable}", "--template=gcc", "<source>"],
            "timeout": timeout,
            "watchdog": {"strategy": "adaptive", "idle_timeout": timeout},
            "retry_policy": {"max_attempts": 1},
            "execution_mode": "sharded",
            "shard_size": shard_size,
            "output_validator": "cppcheck-gcc-template",
            "expected_output": "<raw>/cppcheck.out",
            "cppcheck_mode": mode,
            "cppcheck_mode_source": mode_source,
            "mode_limitations": "fixture cppcheck mode metadata",
        }],
    }
    path = td / "matrix.json"
    path.write_text(json.dumps(matrix))
    return path


def write_source_files(td: pathlib.Path, names: list[str]) -> pathlib.Path:
    source = td / "src"
    source.mkdir()
    paths = []
    for name in names:
        path = source / name
        path.write_text("int main(void) { return 0; }\n")
        paths.append(path)
    file_list = td / "source-files.txt"
    file_list.write_text("\n".join(str(p) for p in paths))
    return file_list


def run_cppcheck_matrix(matrix: pathlib.Path, source: pathlib.Path, out: pathlib.Path, file_list: pathlib.Path, env=None):
    return subprocess.run([
        sys.executable,
        str(ROOT / "tools" / "run_tool_matrix.py"),
        "--matrix",
        str(matrix),
        "--source",
        str(source),
        "--out",
        str(out),
        "--file-list",
        str(file_list),
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
        assert semgrep["status"] == "blocked-recovery-required"
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


def test_tool_output_is_raw_only_and_terminal_gets_bounded_summary():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "noisy-tool"
        write_executable(fake, "#!/usr/bin/env bash\npython3 - <<'PY'\nprint('RAWLOG-' + 'x' * 5000)\nPY\n")
        matrix = {
            "tools": [{
                "name": "noisy-tool",
                "binary": "noisy-tool",
                "applicability": "mandatory",
                "evidence": "large output capture",
                "command": ["noisy-tool"],
                "timeout": "5s",
                "retry_policy": {"max_attempts": 1},
            }]
        }
        matrix_path = td / "matrix.json"
        matrix_path.write_text(json.dumps(matrix))
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        env["PVAS_TERMINAL_SUMMARY_CHARS"] = "120"
        p = run_tool_matrix(matrix_path, td, out, env=env)
        assert p.returncode == 0
        assert "RAWLOG-" not in p.stdout
        assert len(p.stdout) < 600
        raw_text = (out / "raw" / "noisy-tool.out").read_text()
        assert "RAWLOG-" in raw_text
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["output_bytes"] == len(raw_text)
        assert row["raw_output_ref"].endswith("raw/noisy-tool.out")
        assert isinstance(row["terminal_summary_truncated"], bool)
        if row["terminal_summary_truncated"]:
            assert "[truncated]" in p.stdout


def test_no_local_semgrep_rules_blocks_mandatory_tool():
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
        assert p.returncode == 2
        summary = json.loads((out / "tool-summary.json").read_text())
        semgrep = next(t for t in summary["tools"] if t["name"] == "semgrep")
        assert semgrep["status"] == "blocked-recovery-required"
        assert semgrep["reason"] == "no-local-rules"
        assert semgrep["strict_decision"] == "block"


def test_semgrep_preflight_blocks_unwritable_settings_path():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake_semgrep = bindir / "semgrep"
        write_executable(fake_semgrep, "#!/usr/bin/env bash\nexit 99\n")
        matrix_data = json.loads(base_matrix(td, semgrep_binary="semgrep").read_text())
        blocking_parent = td / "not-a-dir"
        blocking_parent.write_text("file blocks mkdir\n")
        matrix_data["tools"][0]["env"] = {
            "SEMGREP_SETTINGS_FILE": str(blocking_parent / "semgrep-settings.yml"),
        }
        matrix = td / "matrix.json"
        matrix.write_text(json.dumps(matrix_data))
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        out = td / "tools"
        p = run_tool_matrix(matrix, td, out, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "semgrep_settings_file-not-writable"
        assert row["strict_decision"] == "block"


def test_mandatory_nonzero_exit_blocks_recovery():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "semgrep"
        write_executable(fake, "#!/usr/bin/env bash\nexit 7\n")
        matrix = base_matrix(td, semgrep_binary="semgrep")
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_tool_matrix(matrix, td, out, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "nonzero-exit"
        assert row["strict_decision"] == "block"


def test_mandatory_malformed_semgrep_output_blocks_recovery():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "semgrep"
        write_executable(fake, "#!/usr/bin/env bash\nwhile [[ $# -gt 0 ]]; do if [[ \"$1\" == \"--output\" ]]; then shift; echo 'not-json' > \"$1\"; fi; shift || true; done\n")
        matrix = base_matrix(td, semgrep_binary="semgrep")
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_tool_matrix(matrix, td, out, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "malformed-output"
        assert row["strict_decision"] == "block"


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


def test_watchdog_records_stalled_mandatory_tool_and_blocks_after_exit():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "hang-tool"
        write_executable(fake, "#!/usr/bin/env bash\nsleep 0.7\n")
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
        assert row["status"] == "blocked-pending-confirmation"
        assert row["reason"] == "stalled"
        assert any(e["event"] == "stalled-diagnostic" for e in row["watchdog_events"])


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


def test_cppcheck_stderr_diagnostics_are_captured_and_mark_findings():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, """#!/usr/bin/env bash
for arg in "$@"; do
  if [[ "$arg" == --file-list=* ]]; then
    while IFS= read -r path; do
      [[ "$path" == *.c ]] && echo "$path:3:1: warning: unsafe copy [bufferAccessOutOfBounds]" >&2
    done < "${arg#--file-list=}"
  fi
done
""")
        file_list = write_source_files(td, ["one.c"])
        matrix = cppcheck_matrix(td, shard_size=4)
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 0
        merged = (out / "raw" / "cppcheck.out").read_text()
        assert "bufferAccessOutOfBounds" in merged
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "completed-with-findings"
        assert row["result_count"] == 1
        assert row["shards_total"] == 1
        assert row["shards_completed"] == 1


def test_cppcheck_fast_mode_command_executes_and_metadata_is_recorded():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        args_log = td / "cppcheck-args.txt"
        fake = bindir / "cppcheck"
        write_executable(fake, f"#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > {args_log}\nexit 0\n")
        file_list = write_source_files(td, ["one.c"])
        matrix = cppcheck_matrix(
            td,
            shard_size=4,
            enable="warning",
            mode="fast",
            mode_source="default-noninteractive",
        )
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 0
        args_text = args_log.read_text()
        assert "--enable=warning" in args_text
        assert "style,performance,portability" not in args_text
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "completed"
        assert row["cppcheck_mode"] == "fast"
        assert row["cppcheck_mode_source"] == "default-noninteractive"
        assert row["mode_limitations"] == "fixture cppcheck mode metadata"


def test_cppcheck_runner_creates_configured_build_dir_before_shard_execution():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, """#!/usr/bin/env python3
import pathlib
import sys
for arg in sys.argv[1:]:
    if arg.startswith("--cppcheck-build-dir="):
        build_dir = pathlib.Path(arg.split("=", 1)[1])
        if not build_dir.is_dir():
            print(f"missing build dir: {build_dir}", file=sys.stderr)
            sys.exit(13)
""")
        file_list = write_source_files(td, ["one.c"])
        matrix_data = json.loads(cppcheck_matrix(td, shard_size=1).read_text())
        matrix_data["tools"][0]["command"].insert(2, "--cppcheck-build-dir=<raw>/cppcheck-build-dir")
        matrix = td / "matrix.json"
        matrix.write_text(json.dumps(matrix_data))
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 0, p.stderr
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "completed"
        assert (out / "raw" / "cppcheck-build-dir").is_dir()


def test_cppcheck_shards_all_complete_before_merging():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, """#!/usr/bin/env bash
for arg in "$@"; do
  if [[ "$arg" == --file-list=* ]]; then
    while IFS= read -r path; do
      [[ "$path" == *.c ]] && echo "$path:5:1: warning: shard hit [memleak]" >&2
    done < "${arg#--file-list=}"
  fi
done
""")
        file_list = write_source_files(td, ["one.c", "two.c", "three.c", "four.c", "five.c"])
        matrix = cppcheck_matrix(td, shard_size=2)
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 0
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "completed-with-findings"
        assert row["shards_total"] == 3
        assert row["shards_completed"] == 3
        merged = (out / "raw" / "cppcheck.out").read_text()
        assert "one.c" in merged
        assert "five.c" in merged
        attempts = json.loads((out / "tool-execution-attempts.json").read_text())["attempts"]
        cpp_attempts = [a for a in attempts if a["tool"] == "cppcheck"]
        assert len(cpp_attempts) == 3
        assert {a["shard_index"] for a in cpp_attempts} == {1, 2, 3}


def test_cppcheck_nonzero_shard_blocks_and_preserves_attempt():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, """#!/usr/bin/env bash
for arg in "$@"; do
  if [[ "$arg" == --file-list=* ]]; then
    if grep -q 'fail.c$' "${arg#--file-list=}"; then
      echo "fail.c:7:1: error: failed [internalError]" >&2
      exit 7
    fi
  fi
done
exit 0
""")
        file_list = write_source_files(td, ["ok.c", "fail.c", "later.c"])
        matrix = cppcheck_matrix(td, shard_size=1)
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "nonzero-exit"
        assert row["shards_completed"] == 1
        attempts = json.loads((out / "tool-execution-attempts.json").read_text())["attempts"]
        failed = [a for a in attempts if a["exit_code"] == 7]
        assert failed
        assert failed[0]["recovery_action"] == "manual-review"


def test_cppcheck_stalled_shard_splits_and_then_completes():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, """#!/usr/bin/env python3
import pathlib, sys, time
files = []
for arg in sys.argv[1:]:
    if arg.startswith('--file-list='):
        files.extend(pathlib.Path(arg.split('=', 1)[1]).read_text().splitlines())
if len(files) > 1:
    time.sleep(0.5)
    sys.exit(0)
for path in files:
    print(f"{path}:9:1: warning: split hit [uninitvar]", file=sys.stderr)
""")
        file_list = write_source_files(td, ["one.c", "two.c"])
        matrix = cppcheck_matrix(td, shard_size=2, timeout="0.1s")
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 0
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "completed-with-findings"
        assert row["shards_total"] == 2
        assert row["shards_completed"] == 2
        attempts = json.loads((out / "tool-execution-attempts.json").read_text())["attempts"]
        assert any(a["status"] == "blocked-pending-confirmation" and a["recovery_action"] == "split-scope" for a in attempts)


def test_cppcheck_single_file_stall_blocks_for_confirmation():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, "#!/usr/bin/env bash\nsleep 0.5\n")
        file_list = write_source_files(td, ["one.c"])
        matrix = cppcheck_matrix(td, shard_size=1, timeout="0.1s")
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-pending-confirmation"
        assert row["reason"] == "stalled"


def test_cppcheck_sharded_command_uses_file_list_not_expanded_source_paths():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        args_log = td / "cppcheck-args.jsonl"
        fake = bindir / "cppcheck"
        write_executable(fake, f"""#!/usr/bin/env python3
import json, pathlib, sys
args = sys.argv[1:]
pathlib.Path({str(args_log)!r}).write_text(json.dumps(args) + "\\n")
for arg in args:
    if arg.startswith('--file-list='):
        for source in pathlib.Path(arg.split('=', 1)[1]).read_text().splitlines():
            print(f"{{source}}:5:1: warning: shard hit [memleak]", file=sys.stderr)
""")
        file_list = write_source_files(td, [f"file{i}.c" for i in range(3005)])
        matrix = cppcheck_matrix(td, shard_size=4000)
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 0
        args = json.loads(args_log.read_text())
        file_list_args = [arg for arg in args if arg.startswith("--file-list=")]
        assert len(file_list_args) == 1
        assert not any(arg.endswith(".c") for arg in args)
        shard_file_list = pathlib.Path(file_list_args[0].split("=", 1)[1])
        assert shard_file_list.name == "cppcheck.part0001.files.txt"
        assert len(shard_file_list.read_text().splitlines()) == 3005
        attempts = json.loads((out / "tool-execution-attempts.json").read_text())["attempts"]
        assert attempts[0]["file_list"] == str(shard_file_list)
        assert not any(str(td / "src" / "file0.c") == arg for arg in attempts[0]["command"])


def test_cppcheck_directory_scan_is_blocked_in_preflight():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, "#!/usr/bin/env bash\necho should-not-run >&2\nexit 99\n")
        (td / "src").mkdir()
        (td / "src" / "one.c").write_text("int main(void) { return 0; }\n")
        matrix_data = json.loads(cppcheck_matrix(td, shard_size=4).read_text())
        matrix_data["tools"][0].pop("cppcheck_scope_file", None)
        matrix_data["tools"][0]["command"] = ["cppcheck", "--enable=warning", "--template=gcc", "<source>"]
        matrix = td / "matrix.json"
        matrix.write_text(json.dumps(matrix_data))
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_tool_matrix(matrix, td / "src", out, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "cppcheck-directory-scan-disabled"
        attempts = json.loads((out / "tool-execution-attempts.json").read_text())["attempts"]
        assert attempts == []


def test_cppcheck_scope_over_budget_blocks_before_execution():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, "#!/usr/bin/env bash\necho should-not-run >&2\nexit 99\n")
        file_list = write_source_files(td, ["one.c", "two.c"])
        matrix_data = json.loads(cppcheck_matrix(td, shard_size=2).read_text())
        matrix_data["tools"][0]["max_scope_files"] = 1
        matrix = td / "matrix.json"
        matrix.write_text(json.dumps(matrix_data))
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "blocked-preflight-resource-risk"
        assert row["cppcheck_preflight"]["file_count"] == 2
        assert row["cppcheck_preflight"]["max_scope_files"] == 1
        attempts = json.loads((out / "tool-execution-attempts.json").read_text())["attempts"]
        assert attempts == []


def test_cppcheck_hard_limit_is_incomplete_timeout_not_completed():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, "#!/usr/bin/env bash\nsleep 0.5\n")
        file_list = write_source_files(td, ["one.c"])
        matrix = cppcheck_matrix(td, shard_size=1, timeout="5s")
        matrix_data = json.loads(matrix.read_text())
        matrix_data["tools"][0]["watchdog"] = {"idle_timeout": "5s", "hard_timeout": "0.1s"}
        matrix.write_text(json.dumps(matrix_data))
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "incomplete-timeout"
        assert row["coverage_profile"] == "unavailable"


def test_container_timeout_and_oom_are_normalized_for_cppcheck():
    sys.path.insert(0, str(ROOT / "tools"))
    import pvas_container
    import run_tool_matrix

    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        raw = td / "raw"
        raw.mkdir()
        tool = {
            "name": "cppcheck",
            "binary": "cppcheck",
            "applicability": "mandatory",
            "evidence": "cppcheck coverage",
            "command": ["cppcheck", "--template=gcc", "<source>"],
        }
        timeout_result = pvas_container.ContainerResult(
            exit_code=-1,
            stdout="",
            stderr="timed out",
            duration_seconds=1.0,
            container_id="",
            oom_killed=False,
            timed_out=True,
        )
        row, _ = run_tool_matrix._container_result_to_row(tool, timeout_result, raw)
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "incomplete-timeout"

        oom_result = pvas_container.ContainerResult(
            exit_code=137,
            stdout="",
            stderr="Out of memory",
            duration_seconds=1.0,
            container_id="",
            oom_killed=True,
            timed_out=False,
        )
        row, _ = run_tool_matrix._container_result_to_row(tool, oom_result, raw)
        assert row["status"] == "blocked-recovery-required"
        assert row["reason"] == "incomplete-resource-failure"


def test_cppcheck_partial_timeout_preserves_completed_output_and_degraded_can_continue():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, """#!/usr/bin/env python3
import pathlib, sys, time
files = []
for arg in sys.argv[1:]:
    if arg.startswith('--file-list='):
        files.extend(pathlib.Path(arg.split('=', 1)[1]).read_text().splitlines())
if any(path.endswith('hang.c') for path in files):
    time.sleep(0.5)
    sys.exit(0)
for path in files:
    print(f"{path}:11:1: warning: completed shard [memleak]", file=sys.stderr)
""")
        file_list = write_source_files(td, ["ok.c", "hang.c"])
        matrix_data = json.loads(cppcheck_matrix(td, shard_size=1, timeout="0.1s").read_text())
        matrix_data["tools"][0]["degraded_continuation_allowed"] = True
        matrix = td / "matrix.json"
        matrix.write_text(json.dumps(matrix_data))
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 0
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "incomplete"
        assert row["strict_decision"] == "continue-needs-manual-review"
        assert row["reason"] == "partial-timeout"
        assert row["shards_completed"] == 1
        assert row["result_count"] == 1
        assert row["coverage_impact"]["limitation"] == "partial cppcheck coverage"
        assert pathlib.Path(row["raw_output_ref"]).name == "cppcheck.out"
        assert "completed shard" in pathlib.Path(row["raw_output_ref"]).read_text()


def test_cppcheck_partial_timeout_blocks_without_degraded_confirmation():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bindir = td / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        write_executable(fake, """#!/usr/bin/env python3
import pathlib, sys, time
files = []
for arg in sys.argv[1:]:
    if arg.startswith('--file-list='):
        files.extend(pathlib.Path(arg.split('=', 1)[1]).read_text().splitlines())
if any(path.endswith('hang.c') for path in files):
    time.sleep(0.5)
    sys.exit(0)
for path in files:
    print(f"{path}:12:1: warning: completed shard [memleak]", file=sys.stderr)
""")
        file_list = write_source_files(td, ["ok.c", "hang.c"])
        matrix = cppcheck_matrix(td, shard_size=1, timeout="0.1s")
        out = td / "tools"
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = run_cppcheck_matrix(matrix, td / "src", out, file_list, env=env)
        assert p.returncode == 2
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "blocked-recovery-required"
        assert row["strict_decision"] == "block"
        assert row["reason"] == "partial-timeout"
        assert row["shards_completed"] == 1
        assert row["coverage_impact"]["limitation"] == "partial cppcheck coverage"


if __name__ == "__main__":
    test_semgrep_missing_is_recorded_and_blocks()
    test_semgrep_success_completes_and_not_applicable_is_preserved()
    test_tool_output_is_raw_only_and_terminal_gets_bounded_summary()
    test_no_local_semgrep_rules_blocks_mandatory_tool()
    test_mandatory_nonzero_exit_blocks_recovery()
    test_mandatory_malformed_semgrep_output_blocks_recovery()
    test_watchdog_allows_progress_past_soft_timeout()
    test_watchdog_records_stalled_mandatory_tool_and_blocks_after_exit()
    test_osv_no_package_sources_is_not_applicable()
    test_cppcheck_stderr_diagnostics_are_captured_and_mark_findings()
    test_cppcheck_fast_mode_command_executes_and_metadata_is_recorded()
    test_cppcheck_runner_creates_configured_build_dir_before_shard_execution()
    test_cppcheck_shards_all_complete_before_merging()
    test_cppcheck_nonzero_shard_blocks_and_preserves_attempt()
    test_cppcheck_stalled_shard_splits_and_then_completes()
    test_cppcheck_single_file_stall_blocks_for_confirmation()
    test_cppcheck_sharded_command_uses_file_list_not_expanded_source_paths()
    test_cppcheck_partial_timeout_preserves_completed_output_and_degraded_can_continue()
    test_cppcheck_partial_timeout_blocks_without_degraded_confirmation()
    print("tool execution gate tests passed")
