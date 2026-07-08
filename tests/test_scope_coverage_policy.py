from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import profile_registry


def touch(path: pathlib.Path, text: str = "") -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def make_scope_fixture(tmp_path: pathlib.Path):
    src = tmp_path / "src"
    files = [
        touch(src / "src" / "main.c", "int main(void) { return 0; }"),
        touch(src / "tests" / "harness.c", "int harness(void) { return 0; }"),
        touch(src / "examples" / "example.c", "int example(void) { return 0; }"),
        touch(src / "docs" / "format.md", "# format"),
        touch(src / "fuzz" / "corpus" / "seed.bin", "seed"),
        touch(src / "build" / "generated.c", "int generated(void) { return 0; }"),
    ]
    out = tmp_path / "out"
    out.mkdir()
    (out / "all-files.txt").write_text("\n".join(str(path) for path in files) + "\n")
    return src, out, files


def test_scope_coverage_records_evidence_only_paths_by_default(tmp_path, monkeypatch):
    for name in (
        "PVAS_SCOPE_INCLUDE_TESTS",
        "PVAS_SCOPE_INCLUDE_EXAMPLES",
        "PVAS_SCOPE_INCLUDE_DOCS",
        "PVAS_SCOPE_INCLUDE_FUZZ_CORPUS",
    ):
        monkeypatch.delenv(name, raising=False)
    src, out, _files = make_scope_fixture(tmp_path)

    scope = profile_registry.write_cppcheck_scope(
        src,
        out,
        max_files=100,
        exclude_dirs=profile_registry.HARD_SCOPE_EXCLUDE_DIRS,
    )
    coverage = json.loads((out / "scope-coverage.json").read_text())
    evidence_text = "\n".join(scope["evidence_only_files"])
    direct_text = "\n".join(scope["included_files"])

    assert "src/main.c" in direct_text
    assert "tests/harness.c" not in direct_text
    assert "examples/example.c" not in direct_text
    assert "build/generated.c" not in direct_text
    assert "tests/harness.c" in evidence_text
    assert "examples/example.c" in evidence_text
    assert "docs/format.md" in evidence_text
    assert "fuzz/corpus/seed.bin" in evidence_text
    assert coverage["counts"]["direct_scan_files"] == 1
    assert coverage["evidence_only_categories"]["tests"] == 1
    assert coverage["evidence_only_categories"]["examples"] == 1
    assert coverage["evidence_only_categories"]["docs"] == 1
    assert coverage["evidence_only_categories"]["fuzz-corpus"] == 1
    assert (out / "evidence-only.files.txt").is_file()


def test_scope_coverage_allows_tests_opt_in_to_direct_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("PVAS_SCOPE_INCLUDE_TESTS", "1")
    monkeypatch.delenv("PVAS_SCOPE_INCLUDE_EXAMPLES", raising=False)
    src, out, _files = make_scope_fixture(tmp_path)

    scope = profile_registry.write_cppcheck_scope(
        src,
        out,
        max_files=100,
        exclude_dirs=profile_registry.HARD_SCOPE_EXCLUDE_DIRS,
    )
    coverage = json.loads((out / "scope-coverage.json").read_text())
    evidence_text = "\n".join(scope["evidence_only_files"])
    direct_text = "\n".join(scope["included_files"])

    assert "src/main.c" in direct_text
    assert "tests/harness.c" in direct_text
    assert "examples/example.c" not in direct_text
    assert "tests/harness.c" not in evidence_text
    assert "examples/example.c" in evidence_text
    assert coverage["counts"]["direct_scan_files"] == 2
    assert "tests" not in coverage["evidence_only_categories"]


def test_main_exclude_dirs_downgrades_legacy_test_excludes_to_evidence_only(tmp_path, monkeypatch):
    monkeypatch.delenv("PVAS_SCOPE_INCLUDE_TESTS", raising=False)
    src, out, _files = make_scope_fixture(tmp_path)
    configured_excludes = {"tests", "examples", "docs", "build"}
    exclude_dirs = (profile_registry.HARD_SCOPE_EXCLUDE_DIRS | configured_excludes) - profile_registry.EVIDENCE_ONLY_DIRS

    scope = profile_registry.write_cppcheck_scope(src, out, max_files=100, exclude_dirs=exclude_dirs)
    direct_text = "\n".join(scope["included_files"])
    evidence_text = "\n".join(scope["evidence_only_files"])
    hard_text = "\n".join(json.loads((out / "scope-coverage.json").read_text())["hard_excluded_file_samples"])

    assert "tests/harness.c" not in direct_text
    assert "tests/harness.c" in evidence_text
    assert "examples/example.c" in evidence_text
    assert "docs/format.md" in evidence_text
    assert "build/generated.c" in hard_text
