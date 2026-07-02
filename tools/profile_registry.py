#!/usr/bin/env python3
"""Profile registry and cppcheck scope builder."""
from __future__ import annotations

import argparse
import json
import pathlib
from dataclasses import dataclass
from typing import Callable


IMPL_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".c++"}
HEADER_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx", ".inc"}
DEFAULT_SCOPE_EXCLUDE_DIRS = {
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
    "test",
    "tests",
    "__tests__",
    "example",
    "examples",
    "doc",
    "docs",
}
BINUTILS_DIRS = {"binutils", "bfd", "opcodes", "gas", "ld", "gold", "gprof", "libctf", "libsframe"}
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


def is_excluded(src: pathlib.Path, path: pathlib.Path, exclude_dirs: set[str]) -> bool:
    return any(part.lower() in exclude_dirs for part in relative_parts(src, path))


def is_impl_file(path: pathlib.Path) -> bool:
    return path.suffix.lower() in IMPL_EXTENSIONS


def is_c_cpp_file(path: pathlib.Path) -> bool:
    return path.suffix.lower() in IMPL_EXTENSIONS | HEADER_EXTENSIONS


def detect_generic_c_cpp(src: pathlib.Path, files: list[pathlib.Path]) -> bool:
    return any(is_c_cpp_file(path) for path in files)


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
        if path.exists() and is_impl_file(path) and not is_excluded(src, path, exclude_dirs)
    ]
    return unique_paths(sorted(selected))


def binutils_focus_files(src: pathlib.Path) -> list[pathlib.Path]:
    selected: list[pathlib.Path] = []
    for rel in BINUTILS_FOCUS:
        path = src / rel
        if path.exists() and path.is_file() and is_impl_file(path):
            selected.append(path)
    return unique_paths(selected)


def detect_profiles(src: pathlib.Path, files: list[pathlib.Path]) -> list[ProfileRule]:
    rules = [
        ProfileRule("binutils", 80, detect_binutils),
        ProfileRule("generic-c-cpp", 10, detect_generic_c_cpp),
    ]
    return sorted([rule for rule in rules if rule.detector(src, files)], key=lambda r: r.priority, reverse=True)


def write_cppcheck_scope(src: pathlib.Path, out: pathlib.Path, *, max_files: int, exclude_dirs: set[str]) -> dict:
    files = read_all_files(src, out, max_files)
    matched = detect_profiles(src, files)
    profile_ids = [rule.profile_id for rule in matched]
    limitations: list[str] = []
    compile_db = find_compile_database(src, files, exclude_dirs)

    selected = included_implementation_files(src, files, exclude_dirs)
    if "binutils" in profile_ids:
        selected = unique_paths(binutils_focus_files(src) + selected)
        limitations.append("binutils high-risk module focus applied")
    if compile_db:
        profile_ids = [*profile_ids, "compile-database"]
        compile_selected = compile_database_files(src, compile_db, exclude_dirs)
        if compile_selected:
            selected = compile_selected
        limitations.append("compile_commands.json available; cppcheck should use --project")

    if not selected:
        limitations.append("no C/C++ implementation files selected for direct cppcheck file-list scope")

    scope = {
        "schema_version": "1.0",
        "scope_mode": "compile-database" if compile_db else "file-list",
        "profile_ids": profile_ids,
        "source_root": str(src),
        "included_files": [str(path) for path in selected[:max_files]],
        "excluded_patterns": sorted(f"**/{name}/**" for name in exclude_dirs),
        "direct_header_policy": "exclude-direct-headers",
        "compile_database": str(compile_db) if compile_db else None,
        "limitations": limitations,
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "cppcheck-scope.json").write_text(json.dumps(scope, indent=2))
    (out / "cppcheck.files.txt").write_text(
        "\n".join(scope["included_files"]) + ("\n" if scope["included_files"] else "")
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
    exclude_dirs = DEFAULT_SCOPE_EXCLUDE_DIRS | configured_excludes
    write_cppcheck_scope(src, out, max_files=args.max_files, exclude_dirs=exclude_dirs)
    print(f"[PVAS-PROFILE] wrote {out / 'cppcheck-scope.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
