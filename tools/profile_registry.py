#!/usr/bin/env python3
"""Profile registry and cppcheck scope builder.

Scope selection is deliberately split into three layers:

1. hard-excluded paths: generated/vendor/runtime directories never scanned;
2. evidence-only paths: tests/examples/docs/fuzz/corpus are indexed as audit
   evidence and input-surface hints, but are not part of the default cppcheck
   direct scan;
3. direct-scan paths: implementation files included in cppcheck scope.

This avoids silently losing harnesses and corpus inputs while keeping baseline
static analysis focused and deterministic.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
from dataclasses import dataclass
from typing import Callable


IMPL_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".c++"}
HEADER_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx", ".inc"}
HARD_SCOPE_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    "out",
    "target",
    "node_modules",
    "vendor",
    "third_party",
    "external",
    "deps",
    "audit-output",
}
TEST_EVIDENCE_DIRS = {"test", "tests", "__tests__"}
EXAMPLE_EVIDENCE_DIRS = {"example", "examples"}
DOC_EVIDENCE_DIRS = {"doc", "docs"}
FUZZ_EVIDENCE_DIRS = {"fuzz", "fuzzing", "oss-fuzz", "corpus", "corpora", "testdata", "regression"}
EVIDENCE_ONLY_DIRS = TEST_EVIDENCE_DIRS | EXAMPLE_EVIDENCE_DIRS | DOC_EVIDENCE_DIRS | FUZZ_EVIDENCE_DIRS
DEFAULT_SCOPE_EXCLUDE_DIRS = HARD_SCOPE_EXCLUDE_DIRS
BINUTILS_DIRS = {"binutils", "bfd", "opcodes", "gas", "ld", "gold", "gprof", "libctf", "libsframe"}
BINUTILS_CPPCHECK_FOCUS_ROOTS = {"bfd", "binutils", "opcodes"}
BINUTILS_INCLUDE_CANDIDATES = ["include", "bfd", "binutils", "opcodes", "libiberty", "intl", "zlib"]
BINUTILS_FOCUS = [
    "binutils/readelf.c",
    "binutils/objdump.c",
    "binutils/nm.c",
    "binutils/objcopy.c",
    "bfd/elf.c",
    "bfd/archive.c",
    "bfd/compress.c",
    "binutils/dwarf.c",
]


@dataclass(frozen=True)
class ProfileRule:
    profile_id: str
    priority: int
    detector: Callable[[pathlib.Path, list[pathlib.Path]], bool]


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_path(path: pathlib.Path) -> pathlib.Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def read_all_files(src: pathlib.Path, out: pathlib.Path, max_files: int) -> list[pathlib.Path]:
    path = out / "all-files.txt"
    files: list[pathlib.Path] = []
    if path.exists():
        for line in path.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            candidate = pathlib.Path(line.strip())
            files.append(candidate if candidate.is_absolute() else src / candidate)
        return files[:max_files]

    for candidate in src.rglob("*"):
        if candidate.is_file():
            files.append(candidate)
            if len(files) >= max_files:
                break
    return files


def relative_parts(src: pathlib.Path, path: pathlib.Path) -> tuple[str, ...]:
    try:
        return path.relative_to(src).parts
    except ValueError:
        return path.parts


def lower_parts(src: pathlib.Path, path: pathlib.Path) -> tuple[str, ...]:
    return tuple(part.lower() for part in relative_parts(src, path))


def part_hits(parts: tuple[str, ...], names: set[str]) -> bool:
    return any(part in names for part in parts)


def is_excluded(src: pathlib.Path, path: pathlib.Path, exclude_dirs: set[str]) -> bool:
    return part_hits(lower_parts(src, path), exclude_dirs)


def evidence_category(src: pathlib.Path, path: pathlib.Path) -> str:
    parts = lower_parts(src, path)
    if part_hits(parts, TEST_EVIDENCE_DIRS):
        return "tests"
    if part_hits(parts, EXAMPLE_EVIDENCE_DIRS):
        return "examples"
    if part_hits(parts, DOC_EVIDENCE_DIRS):
        return "docs"
    if part_hits(parts, FUZZ_EVIDENCE_DIRS):
        return "fuzz-corpus"
    return ""


def direct_scan_allowed_for_evidence(category: str) -> bool:
    if not category:
        return True
    return {
        "tests": env_flag("PVAS_SCOPE_INCLUDE_TESTS", False),
        "examples": env_flag("PVAS_SCOPE_INCLUDE_EXAMPLES", False),
        "docs": env_flag("PVAS_SCOPE_INCLUDE_DOCS", False),
        "fuzz-corpus": env_flag("PVAS_SCOPE_INCLUDE_FUZZ_CORPUS", False),
    }.get(category, False)


def is_evidence_only(src: pathlib.Path, path: pathlib.Path) -> bool:
    category = evidence_category(src, path)
    return bool(category) and not direct_scan_allowed_for_evidence(category)


def is_impl_file(path: pathlib.Path) -> bool:
    return path.suffix.lower() in IMPL_EXTENSIONS


def is_c_cpp_file(path: pathlib.Path) -> bool:
    return path.suffix.lower() in IMPL_EXTENSIONS | HEADER_EXTENSIONS


def detect_generic_c_cpp(src: pathlib.Path, files: list[pathlib.Path]) -> bool:
    return any(is_c_cpp_file(path) and not is_excluded(src, path, HARD_SCOPE_EXCLUDE_DIRS) for path in files)


def detect_binutils(src: pathlib.Path, files: list[pathlib.Path]) -> bool:
    return (src / "bfd").is_dir() and (src / "binutils").is_dir()


def find_compile_database(src: pathlib.Path, files: list[pathlib.Path], exclude_dirs: set[str]) -> pathlib.Path | None:
    candidates = [src / "compile_commands.json"]
    for path in files:
        if path.name == "compile_commands.json" and not is_excluded(src, path, exclude_dirs):
            candidates.append(path)
    for path in candidates:
        if path.exists() and path.is_file():
            return normalize_path(path)
    return None


def compile_database_files(src: pathlib.Path, compile_db: pathlib.Path, exclude_dirs: set[str]) -> list[pathlib.Path]:
    try:
        entries = json.loads(compile_db.read_text(errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(entries, list):
        return []

    files: list[pathlib.Path] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("file"):
            continue
        directory = pathlib.Path(str(entry.get("directory") or src))
        candidate = pathlib.Path(str(entry["file"]))
        if not candidate.is_absolute():
            candidate = directory / candidate
        candidate = normalize_path(candidate)
        if candidate.exists() and is_impl_file(candidate) and not is_excluded(src, candidate, exclude_dirs):
            if not is_evidence_only(src, candidate):
                files.append(candidate)
    return unique_paths(files)


def unique_paths(paths: list[pathlib.Path]) -> list[pathlib.Path]:
    seen: set[str] = set()
    unique: list[pathlib.Path] = []
    for path in paths:
        key = str(normalize_path(path))
        if key not in seen:
            seen.add(key)
            unique.append(normalize_path(path))
    return unique


def included_implementation_files(src: pathlib.Path, files: list[pathlib.Path], exclude_dirs: set[str]) -> list[pathlib.Path]:
    selected = [
        normalize_path(path)
        for path in files
        if path.exists()
        and is_impl_file(path)
        and not is_excluded(src, path, exclude_dirs)
        and not is_evidence_only(src, path)
    ]
    return unique_paths(sorted(selected))


def evidence_only_files(src: pathlib.Path, files: list[pathlib.Path], exclude_dirs: set[str], *, max_files: int) -> list[pathlib.Path]:
    selected = [
        normalize_path(path)
        for path in files
        if path.exists()
        and not is_excluded(src, path, exclude_dirs)
        and is_evidence_only(src, path)
    ]
    return unique_paths(sorted(selected))[:max_files]


def hard_excluded_files(src: pathlib.Path, files: list[pathlib.Path], exclude_dirs: set[str], *, max_files: int) -> list[pathlib.Path]:
    selected = [normalize_path(path) for path in files if path.exists() and is_excluded(src, path, exclude_dirs)]
    return unique_paths(sorted(selected))[:max_files]


def binutils_focus_files(src: pathlib.Path) -> list[pathlib.Path]:
    selected: list[pathlib.Path] = []
    for rel in BINUTILS_FOCUS:
        path = src / rel
        if path.exists() and path.is_file() and is_impl_file(path):
            selected.append(path)
    return unique_paths(selected)


def binutils_scope_files(src: pathlib.Path, files: list[pathlib.Path], exclude_dirs: set[str]) -> list[pathlib.Path]:
    focused = binutils_focus_files(src)
    for path in files:
        if not path.exists() or not is_impl_file(path) or is_excluded(src, path, exclude_dirs) or is_evidence_only(src, path):
            continue
        parts = relative_parts(src, path)
        if parts and parts[0] in BINUTILS_CPPCHECK_FOCUS_ROOTS:
            focused.append(path)
    return unique_paths(sorted(focused))


def generic_include_paths(src: pathlib.Path, files: list[pathlib.Path], selected: list[pathlib.Path], exclude_dirs: set[str]) -> list[pathlib.Path]:
    selected_roots = {path.parent for path in selected}
    header_dirs = {
        normalize_path(path.parent)
        for path in files
        if path.exists()
        and path.suffix.lower() in HEADER_EXTENSIONS
        and not is_excluded(src, path, exclude_dirs)
        and not is_evidence_only(src, path)
    }
    include_dirs: list[pathlib.Path] = []
    for directory in sorted(header_dirs | selected_roots):
        if directory.exists() and directory.is_dir() and not is_excluded(src, directory, exclude_dirs) and not is_evidence_only(src, directory):
            include_dirs.append(directory)
    return unique_paths(include_dirs)


def binutils_include_paths(src: pathlib.Path) -> list[pathlib.Path]:
    paths = [src / rel for rel in BINUTILS_INCLUDE_CANDIDATES if (src / rel).is_dir()]
    return unique_paths(paths)


def detect_profiles(src: pathlib.Path, files: list[pathlib.Path]) -> list[ProfileRule]:
    rules = [
        ProfileRule("binutils", 80, detect_binutils),
        ProfileRule("generic-c-cpp", 10, detect_generic_c_cpp),
    ]
    return sorted([rule for rule in rules if rule.detector(src, files)], key=lambda r: r.priority, reverse=True)


def coverage_summary(src: pathlib.Path, files: list[pathlib.Path], direct: list[pathlib.Path], evidence: list[pathlib.Path], hard: list[pathlib.Path], exclude_dirs: set[str]) -> dict:
    categories: dict[str, int] = {}
    for path in evidence:
        category = evidence_category(src, path) or "unknown"
        categories[category] = categories.get(category, 0) + 1
    return {
        "schema_version": "1.0",
        "source_root": str(src),
        "policy": {
            "hard_excluded_dirs": sorted(exclude_dirs),
            "evidence_only_dirs": sorted(EVIDENCE_ONLY_DIRS),
            "direct_scan_opt_in_env": {
                "tests": "PVAS_SCOPE_INCLUDE_TESTS=1",
                "examples": "PVAS_SCOPE_INCLUDE_EXAMPLES=1",
                "docs": "PVAS_SCOPE_INCLUDE_DOCS=1",
                "fuzz-corpus": "PVAS_SCOPE_INCLUDE_FUZZ_CORPUS=1",
            },
            "default_semantics": "tests/examples/docs/fuzz/corpus are evidence-only unless explicitly opted into direct scan",
        },
        "counts": {
            "all_files_considered": len(files),
            "direct_scan_files": len(direct),
            "evidence_only_files": len(evidence),
            "hard_excluded_files_sampled": len(hard),
        },
        "evidence_only_categories": categories,
        "direct_scan_files": [str(path) for path in direct],
        "evidence_only_files": [str(path) for path in evidence],
        "hard_excluded_file_samples": [str(path) for path in hard],
    }


def write_cppcheck_scope(src: pathlib.Path, out: pathlib.Path, *, max_files: int, exclude_dirs: set[str]) -> dict:
    files = read_all_files(src, out, max_files)
    matched = detect_profiles(src, files)
    profile_ids = [rule.profile_id for rule in matched]
    limitations: list[str] = []
    compile_db = find_compile_database(src, files, exclude_dirs)

    selected = included_implementation_files(src, files, exclude_dirs)
    evidence = evidence_only_files(src, files, exclude_dirs, max_files=max_files)
    hard = hard_excluded_files(src, files, exclude_dirs, max_files=200)
    if evidence:
        limitations.append("tests/examples/docs/fuzz/corpus indexed as evidence-only; not part of default direct cppcheck scope")
    if "binutils" in profile_ids:
        selected = binutils_scope_files(src, files, exclude_dirs)
        limitations.append("binutils high-risk module focus applied")
    if compile_db:
        profile_ids = [*profile_ids, "compile-database"]
        compile_selected = compile_database_files(src, compile_db, exclude_dirs)
        if compile_selected:
            selected = compile_selected
        limitations.append("compile_commands.json available; cppcheck should use --project")

    if not selected:
        limitations.append("no C/C++ implementation files selected for direct cppcheck file-list scope")

    include_paths = generic_include_paths(src, files, selected, exclude_dirs)
    if "binutils" in profile_ids:
        include_paths = unique_paths(binutils_include_paths(src) + include_paths)

    scope = {
        "schema_version": "1.0",
        "scope_mode": "compile-database" if compile_db else "file-list",
        "profile_ids": profile_ids,
        "source_root": str(src),
        "included_files": [str(path) for path in selected[:max_files]],
        "include_paths": [str(path) for path in include_paths],
        "excluded_patterns": sorted(f"**/{name}/**" for name in exclude_dirs),
        "evidence_only_patterns": sorted(f"**/{name}/**" for name in EVIDENCE_ONLY_DIRS),
        "evidence_only_files": [str(path) for path in evidence],
        "direct_header_policy": "exclude-direct-headers",
        "compile_database": str(compile_db) if compile_db else None,
        "limitations": limitations,
    }
    coverage = coverage_summary(src, files, selected[:max_files], evidence, hard, exclude_dirs)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cppcheck-scope.json").write_text(json.dumps(scope, indent=2))
    (out / "scope-coverage.json").write_text(json.dumps(coverage, indent=2))
    (out / "cppcheck.files.txt").write_text(
        "\n".join(scope["included_files"]) + ("\n" if scope["included_files"] else "")
    )
    (out / "cppcheck.includes.txt").write_text(
        "\n".join(scope["include_paths"]) + ("\n" if scope["include_paths"] else "")
    )
    (out / "evidence-only.files.txt").write_text(
        "\n".join(scope["evidence_only_files"]) + ("\n" if scope["evidence_only_files"] else "")
    )
    return scope


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--max-files", type=int, default=50000)
    ap.add_argument("--exclude-dirs", default="")
    args = ap.parse_args()

    src = normalize_path(pathlib.Path(args.src))
    out = pathlib.Path(args.out)
    configured_excludes = {part.strip().lower() for part in args.exclude_dirs.split() if part.strip()}
    # Keep existing --exclude-dirs behavior, but tests/examples/docs/fuzz/corpus are
    # downgraded to evidence-only unless the caller explicitly adds them again and
    # also opts into direct scanning with the PVAS_SCOPE_INCLUDE_* variables.
    exclude_dirs = (HARD_SCOPE_EXCLUDE_DIRS | configured_excludes) - EVIDENCE_ONLY_DIRS
    write_cppcheck_scope(src, out, max_files=args.max_files, exclude_dirs=exclude_dirs)
    print(f"[PVAS-PROFILE] wrote {out / 'cppcheck-scope.json'}")
    print(f"[PVAS-PROFILE] wrote {out / 'scope-coverage.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
