#!/usr/bin/env python3
"""Pre-build dependency audit for PVAS sandbox runtime image.

Validates that everything the Dockerfile needs is staged on the host:
  - offline-bundle/binaries/<tool> exists and is executable for each tool
  - offline-bundle/python/wheels/ has required distributions
  - imported base image exists locally

Returns:
  exit 0 if all checks pass (or fail but --strict not set)
  exit 1 if any check fails AND --strict is set

Usage:
    python3 audit-image-prereqs.py [--strict] [--manifest PATH]

Exit code semantics designed for use in build pipelines:
  - Pre-flight gate before docker build
  - Build pipeline should call with --strict so build fails early
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
from collections import defaultdict


def wheel_name(filename: str) -> str:
    """PEP 503 distribution name from wheel filename. Same as dedupe-wheels.py."""
    base = pathlib.Path(filename).name
    if not base.endswith(".whl"):
        return ""
    parts = base[:-4].split("-")
    for i, p in enumerate(parts):
        if p and p[0].isdigit():
            return "-".join(parts[:i]).lower().replace("_", "-")
    return "-".join(parts).lower().replace("_", "-")


def check_binaries(offline_bundle: pathlib.Path, manifest: dict) -> list[str]:
    """Check that each required binary is staged and executable."""
    errs = []
    for entry in manifest.get("binary_stage", []):
        name = pathlib.Path(entry["src"]).name
        p = offline_bundle / "binaries" / name
        if not p.exists():
            errs.append(f"missing {p}")
            continue
        if not p.is_file():
            errs.append(f"{p} not a regular file")
            continue
        if not p.stat().st_mode & 0o111:
            errs.append(f"{p} not executable")
    return errs


def check_wheels(offline_bundle: pathlib.Path, required: list[str]) -> list[str]:
    """Check that required wheel distributions are present."""
    errs = []
    wheels_dir = offline_bundle / "python" / "wheels"
    if not wheels_dir.is_dir():
        return [f"missing wheels dir {wheels_dir}"]
    present: dict[str, list[pathlib.Path]] = defaultdict(list)
    for w in wheels_dir.glob("*.whl"):
        n = wheel_name(str(w))
        if n:
            present[n].append(w)
    for req in required:
        # Extract base distribution name (strip PEP 440 version specifier)
        base = req.split("<")[0].split(">")[0].split("=")[0].strip().lower()
        # Normalize underscore <-> hyphen for matching (PEP 503)
        base_normalized = base.replace("_", "-")
        # Match by normalized name comparison
        if not any(base_normalized == n for n in present):
            errs.append(f"missing wheel distribution: {req}")
    return errs


def check_docker_imported(image_tag: str) -> list[str]:
    """Check that imported base image exists locally."""
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return ["docker CLI not available"]
    if result.returncode != 0:
        return [f"docker images failed: {result.stderr.strip()}"]
    if image_tag not in result.stdout.splitlines():
        return [f"{image_tag} missing — run pvas-import-image.sh first"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Pre-build dependency audit")
    skill_root = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument(
        "--manifest",
        default=str(skill_root / "sandbox" / "manifest" / "deps.json"),
        help="Path to deps.json manifest",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 1 on any check failure (use in build pipelines)",
    )
    args = parser.parse_args()

    manifest_path = pathlib.Path(args.manifest)
    if not manifest_path.is_file():
        print(f"[FAIL] manifest not found: {manifest_path}")
        return 1 if args.strict else 0
    manifest = json.loads(manifest_path.read_text())

    offline_bundle = skill_root / "offline-bundle"
    # The imported BASE image is what we need to check; the runtime image
    # is built FROM the imported base in build-runtime.sh.
    imported_tag = os.environ.get(
        "PVAS_IMPORTED_IMAGE",
        manifest.get("imported_image", "pvas-sandbox:v11-2503-imported")
    )
    runtime_tag = manifest.get("image", "pvas-sandbox:v11-2503-runtime")

    print(f"[preflight] manifest: {manifest_path}")
    print(f"[preflight] offline_bundle: {offline_bundle}")
    print(f"[preflight] imported_image: {imported_tag}")
    print(f"[preflight] runtime_image:   {runtime_tag}")
    print()

    checks = [
        ("binary-stage", check_binaries(offline_bundle, manifest)),
        ("python-wheels", check_wheels(offline_bundle, manifest.get("python_wheels_required", []))),
        ("docker-imported-base", check_docker_imported(imported_tag)),
    ]

    fail = 0
    for label, errs in checks:
        if not errs:
            print(f"[PASS] {label}")
        else:
            print(f"[FAIL] {label}:")
            for e in errs:
                print(f"  - {e}")
            fail += 1

    print()
    if fail == 0:
        print(f"[preflight] all checks passed ({len(checks)})")
        return 0
    print(f"[preflight] {fail} check(s) failed")
    return 1 if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())