#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_profile(src: pathlib.Path, out: pathlib.Path) -> None:
    subprocess.check_call(["bash", str(ROOT / "tools/profile_project.sh"), str(src), str(out)])


def test_generic_c_cpp_profile_writes_conservative_cppcheck_scope():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        src = td / "src"
        (src / "src").mkdir(parents=True)
        (src / "tests").mkdir()
        (src / "examples").mkdir()
        (src / "docs").mkdir()
        (src / "vendor").mkdir()
        (src / "src" / "main.c").write_text("int main(void) { return 0; }\n")
        (src / "src" / "lib.cpp").write_text("int lib(void) { return 0; }\n")
        (src / "src" / "lib.h").write_text("int lib(void);\n")
        (src / "tests" / "test.c").write_text("int test(void) { return 0; }\n")
        (src / "examples" / "demo.c").write_text("int demo(void) { return 0; }\n")
        (src / "docs" / "sample.c").write_text("int sample(void) { return 0; }\n")
        (src / "vendor" / "dep.c").write_text("int dep(void) { return 0; }\n")

        out = td / "audit-output" / "01-profile"
        run_profile(src, out)

        scope = json.loads((out / "cppcheck-scope.json").read_text())
        files = (out / "cppcheck.files.txt").read_text().splitlines()
        rel_files = {pathlib.Path(p).relative_to(src).as_posix() for p in files}
        assert scope["scope_mode"] == "file-list"
        assert "generic-c-cpp" in scope["profile_ids"]
        assert scope["direct_header_policy"] == "exclude-direct-headers"
        assert scope["compile_database"] is None
        assert rel_files == {"src/main.c", "src/lib.cpp"}
        assert any("tests" in pattern for pattern in scope["excluded_patterns"])


def test_compile_database_profile_prefers_project_scope():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        src = td / "src"
        src.mkdir()
        (src / "main.c").write_text("int main(void) { return 0; }\n")
        (src / "compile_commands.json").write_text(json.dumps([{
            "directory": str(src),
            "command": "cc -Iinclude -DDEMO main.c",
            "file": "main.c",
        }]))

        out = td / "audit-output" / "01-profile"
        run_profile(src, out)

        scope = json.loads((out / "cppcheck-scope.json").read_text())
        assert scope["scope_mode"] == "compile-database"
        assert scope["compile_database"] == str(src / "compile_commands.json")
        assert "compile-database" in scope["profile_ids"]
        assert "compile_commands.json available; cppcheck should use --project" in scope["limitations"]


def test_binutils_profile_is_registry_plugin_not_hardcoded_scope():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        src = td / "binutils-src"
        (src / "binutils").mkdir(parents=True)
        (src / "bfd").mkdir()
        (src / "opcodes").mkdir()
        (src / "configure").write_text("#!/bin/sh\n")
        (src / "binutils" / "readelf.c").write_text("int display(void) { return 0; }\n")
        (src / "bfd" / "elf.c").write_text("int elf(void) { return 0; }\n")
        (src / "opcodes" / "op.h").write_text("int op(void);\n")

        out = td / "audit-output" / "01-profile"
        run_profile(src, out)

        scope = json.loads((out / "cppcheck-scope.json").read_text())
        files = (out / "cppcheck.files.txt").read_text().splitlines()
        rel_files = {pathlib.Path(p).relative_to(src).as_posix() for p in files}
        assert "binutils" in scope["profile_ids"]
        assert "binutils/readelf.c" in rel_files
        assert "bfd/elf.c" in rel_files
        assert any("binutils high-risk module focus applied" in item for item in scope["limitations"])


def test_cppcheck_matrix_records_scope_contract_metadata():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        profile = td / "package-profile.json"
        scope = td / "cppcheck-scope.json"
        out = td / "required-tools-matrix.json"
        profile.write_text(json.dumps({
            "package_name": "demo",
            "source_root": str(td),
            "primary_language": ["C/C++"],
            "profiles": ["binary-parser"],
            "build_system": ["cmake"],
        }))
        scope.write_text(json.dumps({
            "scope_mode": "compile-database",
            "profile_ids": ["generic-c-cpp", "compile-database"],
            "compile_database": str(td / "compile_commands.json"),
            "limitations": ["fixture limitation"],
        }))
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "generate_tool_matrix.py"),
            "--package-profile",
            str(profile),
            "--profile",
            "standard",
            "--cppcheck-scope",
            str(scope),
            "--out",
            str(out),
        ])
        matrix = json.loads(out.read_text())
        cppcheck = next(t for t in matrix["tools"] if t["name"] == "cppcheck")
        assert cppcheck["cppcheck_scope_mode"] == "compile-database"
        assert cppcheck["cppcheck_scope_file"] == str(scope)
        assert cppcheck["cppcheck_compile_database"] == str(td / "compile_commands.json")
        assert cppcheck["execution_mode"] == "project"
        assert "--project=" + str(td / "compile_commands.json") in cppcheck["command"]
        assert cppcheck["cppcheck_profile_ids"] == ["generic-c-cpp", "compile-database"]
        assert "fixture limitation" in cppcheck["scope_limitations"]


def test_cppcheck_runner_uses_project_scope_and_records_fallback_limitation():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        src = td / "src"
        src.mkdir()
        compile_db = src / "compile_commands.json"
        compile_db.write_text("[]\n")
        (src / "main.c").write_text("int main(void) { return 0; }\n")
        bindir = td / "bin"
        bindir.mkdir()
        args_log = td / "cppcheck-args.txt"
        fake = bindir / "cppcheck"
        fake.write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > {args_log}\n")
        fake.chmod(0o755)
        out = td / "tools"
        matrix = td / "matrix.json"
        missing_scope = td / "missing-cppcheck-scope.json"
        matrix.write_text(json.dumps({
            "schema_version": "1.0",
            "environment_profile": "standard",
            "package": "fixture",
            "tools": [{
                "name": "cppcheck",
                "binary": "cppcheck",
                "applicability": "mandatory",
                "evidence": "cppcheck coverage",
                "command": ["cppcheck", "--enable=warning", "--template=gcc", "<source>"],
                "timeout": "1s",
                "watchdog": {"strategy": "adaptive", "idle_timeout": "1s"},
                "retry_policy": {"max_attempts": 1},
                "execution_mode": "sharded",
                "shard_size": 50,
                "cppcheck_scope_file": str(missing_scope),
            }],
        }))
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH','')}"
        p = subprocess.run([
            sys.executable,
            str(ROOT / "tools" / "run_tool_matrix.py"),
            "--matrix",
            str(matrix),
            "--source",
            str(src),
            "--out",
            str(out),
        ], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 0, p.stderr
        row = json.loads((out / "tool-summary.json").read_text())["tools"][0]
        assert row["status"] == "completed"
        assert row["cppcheck_scope_mode"] == "fallback-file-list"
        assert row["scope_limitations"] == ["cppcheck scope artifact missing; used conservative fallback file discovery"]


if __name__ == "__main__":
    test_generic_c_cpp_profile_writes_conservative_cppcheck_scope()
    test_compile_database_profile_prefers_project_scope()
    test_binutils_profile_is_registry_plugin_not_hardcoded_scope()
    test_cppcheck_matrix_records_scope_contract_metadata()
    test_cppcheck_runner_uses_project_scope_and_records_fallback_limitation()
    print("cppcheck scope profile tests passed")
