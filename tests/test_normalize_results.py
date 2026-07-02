#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_normalizer(tools_dir: pathlib.Path, out: pathlib.Path):
    return subprocess.run([
        sys.executable,
        str(ROOT / "tools" / "normalize_results.py"),
        "--tools-dir",
        str(tools_dir),
        "--out",
        str(out),
    ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_cppcheck_full_output_is_parsed_but_low_value_style_is_summarized():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        raw = td / "raw"
        raw.mkdir()
        lines = [
            f"src/style{i}.c:1:1: style: variable scope can be reduced [variableScope]"
            for i in range(205)
        ]
        lines.append("src/parser.c:222:4: warning: array index out of bounds [arrayIndexOutOfBounds]")
        (raw / "cppcheck.out").write_text("\n".join(lines))
        out = td / "raw-candidates.json"
        p = run_normalizer(raw, out)
        assert p.returncode == 0
        data = json.loads(out.read_text())
        cppcheck_candidates = [c for c in data["candidates"] if c["component"] == "cppcheck"]
        assert len(cppcheck_candidates) == 1
        candidate = cppcheck_candidates[0]
        assert candidate["source_locations"][0]["file"] == "src/parser.c"
        assert candidate["source_locations"][0]["start_line"] == 222
        assert candidate["evidence"]["cppcheck_id"] == "arrayIndexOutOfBounds"
        assert data["tool_summaries"]["cppcheck"]["low_value_suppressed_count"] == 205


def test_cppcheck_configuration_noise_is_summarized_as_coverage_limitation():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        raw = td / "raw"
        raw.mkdir()
        (raw / "cppcheck.out").write_text("\n".join([
            "src/a.c:1:1: information: Too many #ifdef configurations [toomanyconfigs]",
            "src/b.c:2:1: error: syntax error [syntaxError]",
            "src/c.c:3:1: information: Limiting analysis branches [normalCheckLevelMaxBranches]",
            "src/d.c:4:1: error: Unknown macro [unknownMacro]",
            "src/parser.c:22:4: warning: array index out of bounds [arrayIndexOutOfBounds]",
        ]))
        out = td / "raw-candidates.json"
        p = run_normalizer(raw, out)
        assert p.returncode == 0
        data = json.loads(out.read_text())
        cppcheck_candidates = [c for c in data["candidates"] if c["component"] == "cppcheck"]
        assert len(cppcheck_candidates) == 1
        summary = data["tool_summaries"]["cppcheck"]
        assert summary["coverage_limitation_count"] == 4
        assert summary["coverage_limitations"]["toomanyconfigs"] == 1
        assert summary["coverage_limitations"]["syntaxError"] == 1
        assert summary["coverage_limitations"]["normalCheckLevelMaxBranches"] == 1
        assert summary["coverage_limitations"]["unknownMacro"] == 1


if __name__ == "__main__":
    test_cppcheck_full_output_is_parsed_but_low_value_style_is_summarized()
    test_cppcheck_configuration_noise_is_summarized_as_coverage_limitation()
    print("normalize results tests passed")
